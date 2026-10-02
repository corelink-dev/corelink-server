//! `corelink bazel-init` — wire a Bazel repo to the CoreLink remote cache.
//!
//! Appends a managed remote-cache block to `.bazelrc` and writes a
//! `.corelink/credentials` file (mode `0600`) carrying the PAT scoped to
//! the repo root. Idempotent: a marker line guards re-runs (exit `0`
//! without rewriting); `--force` removes and rewrites the managed block.
//!
//! # Which config we actually write (important)
//!
//! The container serves TWO live Bazel cache surfaces, both plain HTTPS —
//! there is no gRPC endpoint on this topology, so any `grpcs://` CoreLink
//! address is wrong by construction (see `crates/corelink-container/src/
//! routes/bazel_v2.rs`, where both are registered):
//!
//! 1. **REAPI v2 ByteStream** at `<endpoint>/bazel/v2/<tenant>` — the
//!    tenant is the `:instance` path segment.
//! 2. **The stock-Bazel HTTP alias** at `<endpoint>/bazel/cache` — the
//!    `/cas/<hash>` and `/ac/<hash>` paths vanilla
//!    `--remote_cache=https://…` emits. It is BUILT (it does not 404); the
//!    tenant comes from the PAT rather than the URL, so it takes NO
//!    `--remote_instance_name`.
//!
//! We emit the REAPI v2 config, because this command has already resolved
//! the tenant and can pin it explicitly via `--remote_instance_name=<tenant>`,
//! so Bazel's built-in REAPI client hits `<endpoint>/bazel/v2/<tenant>/…`:
//!
//! ```text
//! build --remote_cache=<endpoint>/bazel/v2
//! build --remote_instance_name=<tenant>
//! build --remote_header=Authorization=Bearer ${CORELINK_PAT}
//! build --remote_timeout=30s
//! build --remote_upload_local_results=true
//! ```
//!
//! `<endpoint>` and `<tenant>` are derived from `config.rs`
//! (`defaults.endpoint` / `DEFAULT_ENDPOINT`, `defaults.tenant_id`) — never
//! hardcoded — and the PAT comes from the resolved credential chain.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::config::{self, DEFAULT_ENDPOINT};
use crate::error::CliError;
use crate::output::{Formatter, OutputFormat};

/// Opening marker of the managed `.bazelrc` block.
const MARKER_START: &str = "# >>> corelink bazel-init (managed block — do not edit) >>>";
/// Closing marker of the managed `.bazelrc` block.
const MARKER_END: &str = "# <<< corelink bazel-init (managed block) <<<";

/// Structured outcome of a `bazel-init` run.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct BazelInitOutcome {
    /// Remote-cache URL written to `.bazelrc`.
    pub remote_cache: String,
    /// REAPI instance name (== tenant id).
    pub instance_name: String,
    /// Path to the `.bazelrc` that was written.
    pub bazelrc_path: String,
    /// Path to the credentials file that was written.
    pub credentials_path: String,
    /// `true` when a pre-existing managed block short-circuited the run.
    pub already_initialized: bool,
    /// `true` when `--force` rewrote an existing managed block.
    pub forced_rewrite: bool,
}

impl fmt::Display for BazelInitOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.already_initialized {
            return write!(
                f,
                "corelink bazel-init: {} already has a managed block; nothing to do (use --force to rewrite)",
                self.bazelrc_path
            );
        }
        writeln!(f, "corelink bazel-init: appended to {}:", self.bazelrc_path)?;
        writeln!(f, "  build --remote_cache={}", self.remote_cache)?;
        writeln!(f, "  build --remote_instance_name={}", self.instance_name)?;
        writeln!(
            f,
            "  build --remote_header=Authorization=Bearer ${{CORELINK_PAT}}"
        )?;
        writeln!(f, "  build --remote_timeout=30s")?;
        writeln!(f, "  build --remote_upload_local_results=true")?;
        write!(
            f,
            "corelink bazel-init: wrote {} (mode 0600)",
            self.credentials_path
        )
    }
}

/// Normalise the endpoint (strip a single trailing slash).
fn normalise_endpoint(endpoint: &str) -> &str {
    endpoint.strip_suffix('/').unwrap_or(endpoint)
}

/// Render the managed `.bazelrc` block (marker-delimited).
fn render_managed_block(remote_cache: &str, tenant: &str) -> String {
    format!(
        "{MARKER_START}\n\
         build --remote_cache={remote_cache}\n\
         build --remote_instance_name={tenant}\n\
         build --remote_header=Authorization=Bearer ${{CORELINK_PAT}}\n\
         build --remote_timeout=30s\n\
         build --remote_upload_local_results=true\n\
         {MARKER_END}\n"
    )
}

/// Render the `.corelink/credentials` env-style file body.
fn render_credentials(pat: &str, tenant: &str, endpoint: &str) -> String {
    format!(
        "# CoreLink credentials — DO NOT COMMIT (add .corelink/ to .gitignore).\n\
         # Source these before `bazel build`:  export $(grep -v '^#' .corelink/credentials | xargs)\n\
         CORELINK_PAT={pat}\n\
         CORELINK_TENANT={tenant}\n\
         CORELINK_ENDPOINT={endpoint}\n"
    )
}

/// Strip a previously-written managed block (between and including the
/// markers) from an existing `.bazelrc` body. Returns the remaining
/// content plus whether a block was found.
fn strip_managed_block(existing: &str) -> (String, bool) {
    if !existing.contains(MARKER_START) {
        return (existing.to_owned(), false);
    }
    let mut out: Vec<&str> = Vec::new();
    let mut in_block = false;
    for line in existing.lines() {
        if line.trim() == MARKER_START {
            in_block = true;
            continue;
        }
        if line.trim() == MARKER_END {
            in_block = false;
            continue;
        }
        if !in_block {
            out.push(line);
        }
    }
    // Re-join; trim trailing blank lines so we don't accrete whitespace.
    let mut joined = out.join("\n");
    while joined.ends_with('\n') || joined.ends_with(char::is_whitespace) {
        joined.pop();
    }
    (joined, true)
}

/// Core, filesystem-scoped implementation (testable against a tempdir).
///
/// `base_dir` is the repo root (cwd in production).
fn run_in_dir(
    base_dir: &Path,
    pat: &str,
    endpoint: &str,
    tenant: &str,
    force: bool,
) -> Result<BazelInitOutcome, CliError> {
    let endpoint = normalise_endpoint(endpoint);
    let remote_cache = format!("{endpoint}/bazel/v2");
    let bazelrc = base_dir.join(".bazelrc");
    let cred_dir = base_dir.join(".corelink");
    let cred_path = cred_dir.join("credentials");

    let existing = if bazelrc.exists() {
        std::fs::read_to_string(&bazelrc).map_err(CliError::Io)?
    } else {
        String::new()
    };
    let has_block = existing.contains(MARKER_START);

    if has_block && !force {
        return Ok(BazelInitOutcome {
            remote_cache,
            instance_name: tenant.to_owned(),
            bazelrc_path: bazelrc.display().to_string(),
            credentials_path: cred_path.display().to_string(),
            already_initialized: true,
            forced_rewrite: false,
        });
    }

    // Build the new .bazelrc body: existing content (managed block
    // stripped if --force) + a separating blank line + the fresh block.
    let (base_body, stripped) = strip_managed_block(&existing);
    let block = render_managed_block(&remote_cache, tenant);
    let new_body = if base_body.trim().is_empty() {
        block
    } else {
        format!("{base_body}\n\n{block}")
    };
    std::fs::write(&bazelrc, new_body).map_err(CliError::Io)?;

    // Write credentials (0600).
    std::fs::create_dir_all(&cred_dir).map_err(CliError::Io)?;
    std::fs::write(&cred_path, render_credentials(pat, tenant, endpoint)).map_err(CliError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&cred_path, std::fs::Permissions::from_mode(0o600))
            .map_err(CliError::Io)?;
    }

    Ok(BazelInitOutcome {
        remote_cache,
        instance_name: tenant.to_owned(),
        bazelrc_path: bazelrc.display().to_string(),
        credentials_path: cred_path.display().to_string(),
        already_initialized: false,
        forced_rewrite: force && stripped,
    })
}

/// Run `corelink bazel-init [--force]`.
///
/// Endpoint + tenant are pulled from `~/.corelink/config.toml`
/// (`defaults.endpoint` / `defaults.tenant_id`), falling back to the
/// `CORELINK_BASE_URL` env var and [`DEFAULT_ENDPOINT`] for the endpoint.
/// The tenant is required (run `corelink login` / `corelink whoami`
/// first).
pub fn run(pat: &str, force: bool, format: OutputFormat) -> Result<(), CliError> {
    let cfg = config::load()?;
    let endpoint = std::env::var("CORELINK_BASE_URL")
        .ok()
        .or(cfg.defaults.endpoint.clone())
        .unwrap_or_else(|| DEFAULT_ENDPOINT.to_owned());
    let tenant = cfg.defaults.tenant_id.clone().ok_or_else(|| {
        CliError::Other(
            "bazel-init: no tenant_id in config — run `corelink login --token=<PAT>` or \
             `corelink whoami` first to cache your tenant ID."
                .to_owned(),
        )
    })?;

    let cwd: PathBuf = std::env::current_dir().map_err(CliError::Io)?;
    let outcome = run_in_dir(&cwd, pat, &endpoint, &tenant, force)?;

    let fmt = Formatter::new(format);
    fmt.emit(&outcome).map_err(CliError::Json)?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn render_block_uses_reapi_scheme_not_dead_grpcs() {
        let block = render_managed_block("https://corelink-api.humangr.com/bazel/v2", "tenant-123");
        assert!(block.contains("--remote_cache=https://corelink-api.humangr.com/bazel/v2"));
        assert!(block.contains("--remote_instance_name=tenant-123"));
        assert!(block.contains("Authorization=Bearer ${CORELINK_PAT}"));
        // No grpcs:// endpoint (the retired dotted CAS host was gRPC-only) may be emitted.
        assert!(!block.contains("grpcs://"));
        assert!(block.contains(MARKER_START));
        assert!(block.contains(MARKER_END));
    }

    #[test]
    fn normalise_endpoint_strips_trailing_slash() {
        assert_eq!(
            normalise_endpoint("https://x.example.com/"),
            "https://x.example.com"
        );
        assert_eq!(
            normalise_endpoint("https://x.example.com"),
            "https://x.example.com"
        );
    }

    #[test]
    fn first_run_writes_bazelrc_and_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let out = run_in_dir(
            dir.path(),
            "corelink_pat_x.y.z",
            "https://corelink-api.humangr.com",
            "tenant-abc",
            false,
        )
        .unwrap();
        assert!(!out.already_initialized);
        let bazelrc = std::fs::read_to_string(dir.path().join(".bazelrc")).unwrap();
        assert!(bazelrc.contains("--remote_cache=https://corelink-api.humangr.com/bazel/v2"));
        assert!(bazelrc.contains("--remote_instance_name=tenant-abc"));
        let creds = std::fs::read_to_string(dir.path().join(".corelink/credentials")).unwrap();
        assert!(creds.contains("CORELINK_PAT=corelink_pat_x.y.z"));
        assert!(creds.contains("CORELINK_TENANT=tenant-abc"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(dir.path().join(".corelink/credentials"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "credentials must be 0600");
        }
    }

    #[test]
    fn second_run_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let ep = "https://corelink-api.humangr.com";
        run_in_dir(dir.path(), "p.a.t", ep, "tenant-abc", false).unwrap();
        let before = std::fs::read_to_string(dir.path().join(".bazelrc")).unwrap();
        let out = run_in_dir(dir.path(), "p.a.t", ep, "tenant-abc", false).unwrap();
        assert!(out.already_initialized, "second run must short-circuit");
        let after = std::fs::read_to_string(dir.path().join(".bazelrc")).unwrap();
        assert_eq!(before, after, "idempotent run must not mutate .bazelrc");
        // Exactly one managed block.
        assert_eq!(after.matches(MARKER_START).count(), 1);
    }

    #[test]
    fn force_rewrites_without_duplicating() {
        let dir = tempfile::tempdir().unwrap();
        let ep = "https://corelink-api.humangr.com";
        run_in_dir(dir.path(), "p.a.t", ep, "tenant-old", false).unwrap();
        // --force with a different tenant rewrites the block.
        let out = run_in_dir(dir.path(), "p.a.t", ep, "tenant-new", true).unwrap();
        assert!(!out.already_initialized);
        assert!(out.forced_rewrite);
        let after = std::fs::read_to_string(dir.path().join(".bazelrc")).unwrap();
        assert_eq!(
            after.matches(MARKER_START).count(),
            1,
            "force must not duplicate the managed block"
        );
        assert!(after.contains("--remote_instance_name=tenant-new"));
        assert!(!after.contains("--remote_instance_name=tenant-old"));
    }

    #[test]
    fn preserves_user_lines_in_existing_bazelrc() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".bazelrc"),
            "build --disk_cache=/tmp/dc\ntest --test_output=errors\n",
        )
        .unwrap();
        run_in_dir(
            dir.path(),
            "p.a.t",
            "https://corelink-api.humangr.com",
            "tenant-abc",
            false,
        )
        .unwrap();
        let after = std::fs::read_to_string(dir.path().join(".bazelrc")).unwrap();
        assert!(after.contains("--disk_cache=/tmp/dc"));
        assert!(after.contains("--test_output=errors"));
        assert!(after.contains("--remote_cache="));
    }

    #[test]
    fn strip_managed_block_removes_only_managed_region() {
        let body = format!(
            "build --x=1\n{}\nbuild --remote_cache=old\n{}\nbuild --y=2\n",
            MARKER_START, MARKER_END
        );
        let (stripped, found) = strip_managed_block(&body);
        assert!(found);
        assert!(stripped.contains("--x=1"));
        assert!(stripped.contains("--y=2"));
        assert!(!stripped.contains("remote_cache=old"));
    }
}

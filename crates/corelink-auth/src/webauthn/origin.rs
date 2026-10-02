//! [`RpId`] + [`Origin`] + [`OriginAllowlist`] — the three load-bearing
//! string-domain primitives that make WebAuthn phishing-resistant.
//!
//! # Threat model
//!
//! - **RP-ID confusion**: `evil.example.com.attacker.com` browser
//!   reports `rp_id = "example.com"` but origin
//!   `evil.example.com.attacker.com`. Browsers reject; weak servers
//!   may accept. We reject by demanding origin ∈ allowlist with **exact
//!   match**.
//! - **Origin allowlist bypass**: `localhost` left in allowlist for
//!   prod. We make `RpId::new` reject `localhost` plus 127.0.0.1 +
//!   `0.0.0.0` + `::1` so a misconfigured deploy fails closed.
//! - **Subdomain elevation**: `RpId` is the eTLD+1 (`example.com`).
//!   The allowlist origins MAY be subdomains (`app.example.com`,
//!   `admin.example.com`) provided they share the canonical RP-ID
//!   suffix. The construction-time guard rejects mismatch.

use std::collections::BTreeSet;
use std::fmt;

use sha2::{Digest, Sha256};

use super::WebAuthnError;

/// Canonical RP-ID (Relying Party ID) — must be eTLD+1 per W3C §5.1.2.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RpId(String);

impl RpId {
    /// Construct an [`RpId`].
    ///
    /// Returns [`WebAuthnError::Malformed`] if `raw`:
    ///
    /// - is empty, longer than 253 octets, or has a leading/trailing
    ///   `.`,
    /// - contains uppercase characters (RP-IDs are
    ///   case-insensitive but the canonical form is lowercase),
    /// - contains non-`[a-z0-9.\-]` characters,
    /// - is `localhost` / `127.0.0.1` / `0.0.0.0` / `::1`,
    /// - has fewer than two labels (i.e., is a TLD by itself).
    pub fn new(raw: &str) -> Result<Self, WebAuthnError> {
        if raw.is_empty() || raw.len() > 253 {
            return Err(WebAuthnError::Malformed("rp-id length"));
        }
        if raw.starts_with('.') || raw.ends_with('.') || raw.contains("..") {
            return Err(WebAuthnError::Malformed("rp-id label boundary"));
        }
        for c in raw.chars() {
            if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.') {
                return Err(WebAuthnError::Malformed("rp-id non-canonical char"));
            }
        }
        let labels = raw.split('.').count();
        if labels < 2 {
            return Err(WebAuthnError::Malformed("rp-id requires ≥ 2 labels"));
        }
        match raw {
            "localhost" | "127.0.0.1" | "0.0.0.0" | "::1" => {
                return Err(WebAuthnError::Malformed("rp-id cannot be loopback"));
            }
            _ => {}
        }
        Ok(Self(raw.to_owned()))
    }

    /// Borrow the canonical lowercased domain.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// SHA-256 of the canonical domain (W3C §5.1.4: the
    /// authenticator-side `rpIdHash`).
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.0.as_bytes());
        hasher.finalize().into()
    }
}

impl fmt::Display for RpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Canonical origin — the `<scheme>://<host>[:<port>]` triple from
/// the browser-side `clientDataJSON.origin` field.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Origin(String);

impl Origin {
    /// Parse a canonical origin.
    ///
    /// Returns [`WebAuthnError::Malformed`] if:
    ///
    /// - scheme is not `https://`,
    /// - host is empty,
    /// - input contains a path / query / fragment,
    /// - input contains a userinfo segment.
    pub fn parse(raw: &str) -> Result<Self, WebAuthnError> {
        let scheme_end = "https://".len();
        if !raw.starts_with("https://") || raw.len() <= scheme_end {
            return Err(WebAuthnError::Malformed("origin must start with https://"));
        }
        let after_scheme = match raw.get(scheme_end..) {
            Some(s) => s,
            None => return Err(WebAuthnError::Malformed("origin truncated")),
        };
        if after_scheme.is_empty() {
            return Err(WebAuthnError::Malformed("origin host empty"));
        }
        if after_scheme.contains('/')
            || after_scheme.contains('?')
            || after_scheme.contains('#')
            || after_scheme.contains('@')
        {
            return Err(WebAuthnError::Malformed(
                "origin must not contain path/query/userinfo",
            ));
        }
        // canonical lowercase host; preserve port literal.
        let lowered = raw.to_ascii_lowercase();
        Ok(Self(lowered))
    }

    /// Borrow the canonical origin string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Host portion (after `https://`, before optional `:port`).
    #[must_use]
    pub fn host(&self) -> &str {
        let after_scheme = self.0.strip_prefix("https://").unwrap_or(self.0.as_str());
        match after_scheme.find(':') {
            Some(idx) => after_scheme.get(..idx).unwrap_or(after_scheme),
            None => after_scheme,
        }
    }

    /// Whether this origin's host is a sub-label of `rp_id` OR equal
    /// to it. Used for the construction-time check that allowlist
    /// origins share the canonical RP-ID suffix.
    #[must_use]
    pub fn is_subdomain_of(&self, rp_id: &RpId) -> bool {
        let host = self.host();
        let canonical = rp_id.as_str();
        if host == canonical {
            return true;
        }
        // host must end in `.<canonical>` to qualify as subdomain.
        host.len() > canonical.len() + 1
            && host.ends_with(canonical)
            && host
                .as_bytes()
                .get(host.len().saturating_sub(canonical.len() + 1))
                == Some(&b'.')
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Exact-match origin allowlist.
#[derive(Debug, Clone, Default)]
pub struct OriginAllowlist {
    origins: BTreeSet<Origin>,
}

impl OriginAllowlist {
    /// Construct from an iterator of pre-parsed origins.
    #[must_use]
    pub fn from_origins<I: IntoIterator<Item = Origin>>(iter: I) -> Self {
        Self {
            origins: iter.into_iter().collect(),
        }
    }

    /// Construct from an iterator of strings; each is parsed via
    /// [`Origin::parse`].
    pub fn from_strings<I, S>(iter: I) -> Result<Self, WebAuthnError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut acc = BTreeSet::new();
        for raw in iter {
            acc.insert(Origin::parse(raw.as_ref())?);
        }
        Ok(Self { origins: acc })
    }

    /// **Exact** match.
    #[must_use]
    pub fn contains(&self, origin: &Origin) -> bool {
        self.origins.contains(origin)
    }

    /// Number of allowlisted entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.origins.len()
    }

    /// Whether the allowlist has zero entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.origins.is_empty()
    }

    /// Iterator over allowlisted origins.
    pub fn iter(&self) -> impl Iterator<Item = &Origin> {
        self.origins.iter()
    }

    /// Verify every allowlisted origin shares the canonical RP-ID
    /// suffix.
    pub fn require_consistency_with(&self, rp_id: &RpId) -> Result<(), WebAuthnError> {
        for origin in &self.origins {
            if !origin.is_subdomain_of(rp_id) {
                return Err(WebAuthnError::Malformed(
                    "origin not a subdomain of canonical rp-id",
                ));
            }
        }
        Ok(())
    }
}

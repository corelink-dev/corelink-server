"""Focused negatives for the separate, unsigned-Windows draft inventory."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import base64
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from scripts import cli_release_draft_manifest as draft
from scripts import cli_release_manifest as production
from scripts import cli_release_api as release_api
from scripts import verify_cli_release_draft as draft_verifier


def cli_package_version() -> str:
    text = Path("tools/cli/Cargo.toml").read_text(encoding="utf-8")
    match = re.search(r'(?m)^version = "([0-9]+\.[0-9]+\.[0-9]+)"$', text)
    if not match:
        raise AssertionError("corelink-cli package version must be explicit")
    return match.group(1)


TAG = f"cli-v{cli_package_version()}"
SOURCE = "a" * 40


def _workflow_ancestors(jobs: dict, name: str) -> set[str]:
    result: set[str] = set()
    needs = jobs[name].get("needs", [])
    pending = [needs] if isinstance(needs, str) else list(needs)
    while pending:
        item = pending.pop()
        if item not in result:
            result.add(item)
            needs = jobs[item].get("needs", [])
            pending.extend([needs] if isinstance(needs, str) else needs)
    return result


def _implicit_success(jobs: dict, name: str, results: dict[str, str]) -> bool:
    return all(results.get(ancestor) == "success" for ancestor in _workflow_ancestors(jobs, name))


def _slsa_condition(condition: str, results: dict[str, str]) -> bool:
    direct = ("final-manifest", "release-readiness", "release")
    # The expression is intentionally parsed by checking its actual job
    # condition and each named GitHub result predicate, rather than simulating
    # an unrelated workflow description.
    return "always()" in condition and all(
        f"needs.{job}.result == 'success'" in condition and results.get(job) == "success"
        for job in direct
    )


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_checksums(directory: Path) -> None:
    names = sorted(
        path.name for path in directory.iterdir()
        if path.is_file() and (
            path.name in production.BASE_PAYLOADS
            or path.name in {f"{name}.asc" for name in production.LINUX_PAYLOADS}
        )
    )
    for name in names:
        (directory / f"{name}.sha256").write_text(f"{sha(directory / name)}  {name}\n", encoding="utf-8")
    draft.write_checksums(directory)


class DraftManifestContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.staged = self.root / "staged"
        self.final = self.root / "final"
        self.staged.mkdir()
        for name in production.BASE_PAYLOADS:
            (self.staged / name).write_bytes(f"staged:{name}".encode())
        write_checksums(self.staged)
        self.staging_manifest = self.staged / "staging-manifest.json"
        production.create(self.staged, self.staging_manifest, TAG, SOURCE)
        shutil.copytree(self.staged, self.final, ignore=shutil.ignore_patterns("staging-manifest.json"))
        for name in production.LINUX_PAYLOADS:
            (self.final / name).write_bytes(f"signed:{name}".encode())
            (self.final / f"{name}.asc").write_bytes(f"signature:{name}".encode())
        write_checksums(self.final)
        self.manifest = self.final / "release-manifest.json"
        draft.create(self.final, self.manifest, TAG, SOURCE, self.staging_manifest)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_windows_release_packaging_is_pinned_canonical_and_smoked_without_builds(self) -> None:
        production_workflow = Path(".github/workflows/release-cli.yml").read_text(encoding="utf-8")
        contract_workflow = Path(".github/workflows/issue-2572-draft-contract.yml").read_text(encoding="utf-8")
        for workflow in (production_workflow, contract_workflow):
            self.assertIn("actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97", workflow)
            self.assertIn('ZipInfo("corelink.exe", (1980, 1, 1, 0, 0, 0))', workflow)
            self.assertIn("info.create_system=0", workflow)
            self.assertIn("info.external_attr=0", workflow)
            self.assertIn("ZIP_STORED", workflow)
            self.assertIn('check.namelist()==["corelink.exe"]', workflow)
            self.assertIn('check.read("corelink.exe")', workflow)
        self.assertIn("runs-on: ubuntu-24.04", contract_workflow)
        self.assertIn("runs-on: windows-2022", contract_workflow)
        self.assertIn("first.read_bytes()==second.read_bytes()", contract_workflow)
        self.assertNotIn("cargo zigbuild", contract_workflow)
        self.assertNotIn("command -v zip", production_workflow)

    def test_candidate_tag_tracks_package_and_workspace_lock_version(self) -> None:
        version = cli_package_version()
        lock = Path("Cargo.lock").read_text(encoding="utf-8")
        package = re.search(r'(?ms)^name = "corelink-cli"\nversion = "([^"]+)"', lock)
        self.assertIsNotNone(package)
        self.assertEqual(package.group(1), version)
        self.assertEqual(TAG, f"cli-v{version}")

    def test_draft_manifest_is_typed_and_production_loader_rejects_it(self) -> None:
        value = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertEqual(value["version"], 3)
        self.assertEqual(value["mode"], "draft-only")
        self.assertEqual(value["windows_signature_status"], "unsigned-deferred")
        self.assertEqual(set(draft.load_manifest(self.manifest, TAG, SOURCE)), production.FINAL_INVENTORY)
        with self.assertRaises(ValueError):
            production.load(self.manifest, TAG, SOURCE)

    def test_wrong_mode_identity_or_inventory_is_rejected(self) -> None:
        value = json.loads(self.manifest.read_text(encoding="utf-8"))
        for key, replacement in (("mode", "signed-public"), ("windows_signature_status", "authenticode")):
            changed = dict(value)
            changed[key] = replacement
            candidate = self.root / f"bad-{key}.json"
            candidate.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaises(ValueError):
                draft.load_manifest(candidate, TAG, SOURCE)
        with self.assertRaises(ValueError):
            draft.load_manifest(self.manifest, "cli-v9.9.9", SOURCE)
        extra = self.final / "unexpected-apple.dmg"
        extra.write_bytes(b"not allowed")
        self.manifest.unlink()
        with self.assertRaises(ValueError):
            draft.create(self.final, self.root / "extra.json", TAG, SOURCE, self.staging_manifest)

    def test_windows_final_bytes_must_equal_staging(self) -> None:
        name = "corelink-windows-x86_64.exe"
        (self.final / name).write_bytes(b"modified Windows bytes")
        write_checksums(self.final)
        self.manifest.unlink()
        with self.assertRaisesRegex(ValueError, "Windows artifact"):
            draft.create(self.final, self.root / "tampered.json", TAG, SOURCE, self.staging_manifest)

    def test_verifier_rejects_published_or_wrong_tag_api_before_byte_checks(self) -> None:
        api_path = self.root / "release.json"
        base = {"tag_name": TAG, "draft": True, "published_at": None, "prerelease": False, "assets": []}
        for changes in ({"draft": False}, {"tag_name": "cli-v0.1.2"}, {"published_at": "2026-10-01T00:00:00Z"}):
            api_path.write_text(json.dumps(base | changes), encoding="utf-8")
            with self.assertRaises(ValueError):
                draft_verifier.verify(api_path, self.final, self.manifest, self.final / "provenance.intoto.jsonl",
                                      self.final / "provenance.intoto.jsonl.bundle", self.root / "pub.asc",
                                      TAG, SOURCE, sha(self.manifest))

    def test_final_manifest_verifies_bytes_and_rejects_tampering(self) -> None:
        with patch.object(draft, "_gpg_verify"):
            digest_map = draft.verify_manifest(
                self.final, self.manifest, self.root / "unused-public-key", TAG, SOURCE, sha(self.manifest)
            )
        self.assertEqual(set(digest_map), production.FINAL_INVENTORY)
        (self.final / "corelink-windows-x86_64.exe").write_bytes(b"tampered after manifest")
        with patch.object(draft, "_gpg_verify"):
            with self.assertRaisesRegex(ValueError, "bytes differ"):
                draft.verify_manifest(
                    self.final, self.manifest, self.root / "unused-public-key", TAG, SOURCE, sha(self.manifest)
                )

    def test_linux_gpg_status_must_match_the_frozen_fingerprint(self) -> None:
        public_key = self.root / "release-public-key.asc"
        public_key.write_text("public-key fixture", encoding="utf-8")
        imported = subprocess.CompletedProcess([], 0, "", "")
        valid = subprocess.CompletedProcess(
            [], 0, f"[GNUPG:] VALIDSIG {draft.EXPECTED_GPG_FINGERPRINT} 20261001\n", ""
        )
        artifact_map = draft.load_manifest(self.manifest, TAG, SOURCE)
        with patch.object(draft.subprocess, "run", side_effect=[imported, valid, valid, valid, valid]) as run:
            draft._gpg_verify(self.final, artifact_map, public_key)
        self.assertEqual(run.call_count, 5)
        wrong = subprocess.CompletedProcess([], 0, f"[GNUPG:] VALIDSIG {'0' * 40} 20261001\n", "")
        with patch.object(draft.subprocess, "run", side_effect=[imported, wrong]):
            with self.assertRaisesRegex(ValueError, "wrong fingerprint"):
                draft._gpg_verify(self.final, artifact_map, public_key)

    def test_release_readback_binds_exact_api_assets_and_slsa_subjects(self) -> None:
        artifacts = json.loads(self.manifest.read_text(encoding="utf-8"))["artifacts"]
        subjects = [
            {"name": item["name"], "digest": {"sha256": item["sha256"]}}
            for item in artifacts
        ]
        statement = {"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://slsa.dev/provenance/v1", "subject": subjects}
        payload = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
        provenance = self.final / "provenance.intoto.jsonl"
        bundle = self.final / "provenance.intoto.jsonl.bundle"
        provenance.write_bytes(payload + b"\n")
        bundle.write_text(json.dumps({"dsseEnvelope": {"payload": base64.b64encode(payload).decode()}}), encoding="utf-8")
        api = self.root / "release-api.json"
        names = set(draft.load_manifest(self.manifest, TAG, SOURCE)) | draft.METADATA_ASSETS
        api.write_text(json.dumps({
            "tag_name": TAG, "draft": True, "published_at": None, "prerelease": False,
            "assets": [{"name": name, "id": index, "digest": f"sha256:{sha(self.final / name)}"}
                       for index, name in enumerate(sorted(names), 1)],
        }), encoding="utf-8")
        with patch.object(draft, "_gpg_verify"):
            draft_verifier.verify(api, self.final, self.manifest, provenance, bundle,
                                  self.root / "unused-public-key", TAG, SOURCE, sha(self.manifest))
        valid_api = json.loads(api.read_text(encoding="utf-8"))
        for replacement in (None, "__missing__"):
            invalid_api = json.loads(json.dumps(valid_api))
            if replacement == "__missing__":
                invalid_api["assets"][0].pop("digest")
            else:
                invalid_api["assets"][0]["digest"] = replacement
            api.write_text(json.dumps(invalid_api), encoding="utf-8")
            with patch.object(draft, "_gpg_verify"):
                with self.assertRaisesRegex(ValueError, "API digest"):
                    draft_verifier.verify(api, self.final, self.manifest, provenance, bundle,
                                          self.root / "unused-public-key", TAG, SOURCE, sha(self.manifest))
        api.write_text(json.dumps(valid_api), encoding="utf-8")
        statement["subject"] = subjects[:-1]
        payload = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
        provenance.write_bytes(payload + b"\n")
        bundle.write_text(json.dumps({"dsseEnvelope": {"payload": base64.b64encode(payload).decode()}}), encoding="utf-8")
        api_value = json.loads(api.read_text(encoding="utf-8"))
        for asset in api_value["assets"]:
            asset["digest"] = f"sha256:{sha(self.final / asset['name'])}"
        api.write_text(json.dumps(api_value), encoding="utf-8")
        with patch.object(draft, "_gpg_verify"):
            with self.assertRaisesRegex(ValueError, "SLSA subjects"):
                draft_verifier.verify(api, self.final, self.manifest, provenance, bundle,
                                      self.root / "unused-public-key", TAG, SOURCE, sha(self.manifest))


class StableReleaseIdContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.draft = {
            "id": 400918946,
            "tag_name": "cli-v0.1.5",
            "draft": True,
            "published_at": None,
            "prerelease": False,
            "html_url": "https://github.com/HuGR-Labs/corelink-cli/releases/tag/cli-v0.1.5",
            "upload_url": "https://uploads.github.com/repos/HuGR-Labs/corelink-cli/releases/400918946/assets{?name,label}",
            "assets": [],
        }
        self.published = self.draft | {
            "draft": False,
            "published_at": "2026-10-01T12:00:00Z",
        }

    def test_explicit_id_reads_that_exact_release_and_accepts_only_requested_phase(self) -> None:
        with patch.object(release_api, "gh_json", return_value=self.draft) as request:
            result = release_api.resolve_release(
                repository="HuGR-Labs/corelink-cli",
                tag="cli-v0.1.5",
                expected_state="draft",
                release_id="400918946",
                allow_absent=False,
            )
        self.assertEqual(result, self.draft)
        request.assert_called_once_with("repos/HuGR-Labs/corelink-cli/releases/400918946")
        with patch.object(release_api, "gh_json", return_value=self.draft):
            with self.assertRaisesRegex(release_api.ReleaseApiError, "published release"):
                release_api.resolve_release(
                    repository="HuGR-Labs/corelink-cli", tag="cli-v0.1.5",
                    expected_state="published", release_id="400918946", allow_absent=False,
                )
        with patch.object(release_api, "gh_json", return_value=self.published):
            self.assertEqual(
                release_api.resolve_release(
                    repository="HuGR-Labs/corelink-cli", tag="cli-v0.1.5",
                    expected_state="published", release_id="400918946", allow_absent=False,
                ),
                self.published,
            )

    def test_pagination_resolves_unique_tag_then_rechecks_by_id(self) -> None:
        with patch.object(release_api, "gh_json", side_effect=[[[self.draft]], self.draft]) as request:
            result = release_api.resolve_release(
                repository="HuGR-Labs/corelink-cli", tag="cli-v0.1.5",
                expected_state="draft", release_id=None, allow_absent=False,
            )
        self.assertEqual(result["id"], 400918946)
        self.assertEqual(request.call_args_list[0].args, (
            "--paginate", "--slurp", "repos/HuGR-Labs/corelink-cli/releases?per_page=100"
        ))
        self.assertEqual(request.call_args_list[1].args, (
            "repos/HuGR-Labs/corelink-cli/releases/400918946",
        ))

    def test_only_explicit_precreate_inspection_may_report_absence(self) -> None:
        with patch.object(release_api, "gh_json", return_value=[[]]):
            self.assertIsNone(release_api.resolve_release(
                repository="HuGR-Labs/corelink-cli", tag="cli-v0.1.5",
                expected_state="draft", release_id=None, allow_absent=True,
            ))
        with patch.object(release_api, "gh_json", return_value=[[]]):
            with self.assertRaisesRegex(release_api.ReleaseApiError, "exactly one"):
                release_api.resolve_release(
                    repository="HuGR-Labs/corelink-cli", tag="cli-v0.1.5",
                    expected_state="draft", release_id=None, allow_absent=False,
                )
        with patch.object(release_api, "gh_json", side_effect=release_api.ReleaseApiError("404")):
            with self.assertRaisesRegex(release_api.ReleaseApiError, "404"):
                release_api.resolve_release(
                    repository="HuGR-Labs/corelink-cli", tag="cli-v0.1.5",
                    expected_state="draft", release_id="400918946", allow_absent=False,
                )

    def test_duplicate_tags_wrong_identity_and_malformed_pages_fail_closed(self) -> None:
        with patch.object(release_api, "gh_json", return_value=[[self.draft, self.draft]]):
            with self.assertRaisesRegex(release_api.ReleaseApiError, "exactly one"):
                release_api.resolve_release(
                    repository="HuGR-Labs/corelink-cli", tag="cli-v0.1.5",
                    expected_state="draft", release_id=None, allow_absent=False,
                )
        wrong_tag = self.draft | {"tag_name": "cli-v0.1.6"}
        with patch.object(release_api, "gh_json", return_value=wrong_tag):
            with self.assertRaisesRegex(release_api.ReleaseApiError, "tag does not match"):
                release_api.resolve_release(
                    repository="HuGR-Labs/corelink-cli", tag="cli-v0.1.5",
                    expected_state="draft", release_id="400918946", allow_absent=False,
                )
        with patch.object(release_api, "gh_json", return_value=[{"not": "a page"}]):
            with self.assertRaisesRegex(release_api.ReleaseApiError, "malformed page"):
                release_api.resolve_release(
                    repository="HuGR-Labs/corelink-cli", tag="cli-v0.1.5",
                    expected_state="draft", release_id=None, allow_absent=False,
                )
        for repo, tag, identifier in (
            ("HuGR-Labs/corelink-cli/releases", "cli-v0.1.5", None),
            ("HuGR-Labs/corelink-cli", "v0.1.5", None),
            ("HuGR-Labs/corelink-cli", "cli-v0.1.5", "0"),
        ):
            with patch.object(release_api, "gh_json") as request:
                with self.assertRaises(release_api.ReleaseApiError):
                    release_api.resolve_release(
                        repository=repo, tag=tag, expected_state="draft",
                        release_id=identifier, allow_absent=False,
                    )
                request.assert_not_called()

    def test_create_captures_and_validates_the_official_post_response_without_relisting(self) -> None:
        created = self.draft | {"tag_name": TAG, "name": "CoreLink CLI 0.1.7"}
        with patch.object(release_api, "gh_json", return_value=[[]]) as listing, \
                patch.object(release_api, "gh_json_input", return_value=created) as post:
            result = release_api.create_or_reuse_empty_draft(
                repository="HuGR-Labs/corelink-cli", tag=TAG,
                title="CoreLink CLI 0.1.7", body="release notes\n",
            )
        self.assertEqual(result["id"], 400918946)
        listing.assert_called_once_with(
            "--paginate", "--slurp", "repos/HuGR-Labs/corelink-cli/releases?per_page=100",
        )
        post.assert_called_once_with(
            "--method", "POST", "--input", "-", "repos/HuGR-Labs/corelink-cli/releases",
            payload={
                "tag_name": TAG,
                "name": "CoreLink CLI 0.1.7",
                "body": "release notes\n",
                "draft": True,
                "prerelease": False,
            },
        )

    def test_existing_empty_draft_reuses_its_id_and_never_posts(self) -> None:
        existing = self.draft | {"tag_name": TAG, "name": "CoreLink CLI 0.1.7"}
        with patch.object(release_api, "gh_json", side_effect=[[[existing]], existing]) as request, \
                patch.object(release_api, "gh_json_input") as post:
            result = release_api.create_or_reuse_empty_draft(
                repository="HuGR-Labs/corelink-cli", tag=TAG,
                title="CoreLink CLI 0.1.7", body="release notes\n",
            )
        self.assertEqual(result["id"], existing["id"])
        self.assertEqual(request.call_count, 2)
        self.assertEqual(request.call_args_list[1].args, ("repos/HuGR-Labs/corelink-cli/releases/400918946",))
        post.assert_not_called()

    def test_nonempty_existing_draft_and_duplicate_tag_are_rejected_without_post(self) -> None:
        nonempty = self.draft | {"tag_name": TAG, "assets": [{"name": "corelink"}]}
        for pages, second, message in (
            ([[nonempty]], nonempty, "non-empty"),
            ([[self.draft | {"tag_name": TAG}, self.draft | {"tag_name": TAG}]], None,
             "duplicate matching tags"),
        ):
            with self.subTest(message=message), \
                    patch.object(release_api, "gh_json", side_effect=[pages, second] if second else [pages]), \
                    patch.object(release_api, "gh_json_input") as post:
                with self.assertRaisesRegex(release_api.ReleaseApiError, message):
                    release_api.create_or_reuse_empty_draft(
                        repository="HuGR-Labs/corelink-cli", tag=TAG,
                        title="CoreLink CLI 0.1.7", body="release notes\n",
                    )
                post.assert_not_called()

    def test_malformed_or_unexpected_create_responses_fail_closed(self) -> None:
        good = self.draft | {"tag_name": TAG, "name": "CoreLink CLI 0.1.7"}
        mutants = (
            good | {"id": True},
            good | {"id": 0},
            good | {"tag_name": "cli-v0.1.8"},
            good | {"draft": False, "published_at": "2026-10-01T12:00:00Z"},
            good | {"published_at": "2026-10-01T12:00:00Z"},
            good | {"prerelease": True},
            good | {"assets": [{"name": "unexpected"}]},
            good | {"name": "wrong title"},
            {key: value for key, value in good.items() if key != "upload_url"},
        )
        for mutant in mutants:
            with self.subTest(mutant=mutant), \
                    patch.object(release_api, "gh_json", return_value=[[]]), \
                    patch.object(release_api, "gh_json_input", return_value=mutant):
                with self.assertRaises(release_api.ReleaseApiError):
                    release_api.create_or_reuse_empty_draft(
                        repository="HuGR-Labs/corelink-cli", tag=TAG,
                        title="CoreLink CLI 0.1.7", body="release notes\n",
                    )

    def test_cli_create_command_posts_once_reads_notes_and_emits_the_validated_id(self) -> None:
        with tempfile.TemporaryDirectory(prefix="corelink-release-create-gh-") as temporary:
            root = Path(temporary)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            calls = root / "calls.jsonl"
            payloads = root / "post-bodies.jsonl"
            notes = root / "notes.md"
            notes.write_text("release notes with newline\n", encoding="utf-8")
            fake_gh = fake_bin / "gh"
            fake_gh.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "args = sys.argv[1:]\n"
                "with open(os.environ['GH_CALL_LOG'], 'a', encoding='utf-8') as f: f.write(json.dumps(args) + '\\n')\n"
                "if '--paginate' in args:\n"
                "    json.dump([[]], sys.stdout); print(); raise SystemExit(0)\n"
                "body = json.load(sys.stdin)\n"
                "with open(os.environ['GH_POST_LOG'], 'a', encoding='utf-8') as f: f.write(json.dumps(body) + '\\n')\n"
                "release = {'id': 400918946, 'tag_name': body['tag_name'], 'name': body['name'],\n"
                " 'draft': True, 'published_at': None, 'prerelease': False, 'html_url': 'https://github.com/HuGR-Labs/corelink-cli/releases/tag/x',\n"
                " 'upload_url': 'https://uploads.github.com/repos/HuGR-Labs/corelink-cli/releases/400918946/assets{?name,label}', 'assets': []}\n"
                "json.dump(release, sys.stdout); print()\n",
                encoding="utf-8",
            )
            fake_gh.chmod(0o755)
            environment = dict(__import__("os").environ)
            environment.update({
                "PATH": f"{fake_bin}:{environment['PATH']}",
                "GH_CALL_LOG": str(calls),
                "GH_POST_LOG": str(payloads),
                "GH_TOKEN": "",
                "GH_ENTERPRISE_TOKEN": "",
                "GITHUB_ENTERPRISE_TOKEN": "",
            })
            result = subprocess.run(
                [
                    "python3", "scripts/cli_release_api.py", "--repo", "HuGR-Labs/corelink-cli",
                    "--tag", TAG, "--expected-state", "draft", "--allow-absent",
                    "--create-or-reuse-empty-draft", "--title", "CoreLink CLI 0.1.7",
                    "--notes-file", str(notes), "--format", "id",
                ],
                cwd=Path(__file__).resolve().parents[1], env=environment,
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "400918946\n")
            self.assertEqual(json.loads(payloads.read_text(encoding="utf-8")), {
                "tag_name": TAG,
                "name": "CoreLink CLI 0.1.7",
                "body": "release notes with newline\n",
                "draft": True,
                "prerelease": False,
            })
            recorded_calls = [json.loads(line) for line in calls.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(recorded_calls), 2)
            self.assertIn("--paginate", recorded_calls[0])
            self.assertEqual(recorded_calls[1], [
                "api", "--method", "POST", "--input", "-", "repos/HuGR-Labs/corelink-cli/releases",
            ])

    def test_cli_integration_uses_authenticated_gh_api_shape_without_reading_credentials(self) -> None:
        with tempfile.TemporaryDirectory(prefix="corelink-release-id-gh-") as temporary:
            root = Path(temporary)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            calls = root / "calls.jsonl"
            fake_gh = fake_bin / "gh"
            fake_gh.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "with open(os.environ['GH_CALL_LOG'], 'a', encoding='utf-8') as output:\n"
                "    output.write(json.dumps(sys.argv[1:]) + '\\n')\n"
                "release = {\n"
                "  'id': 400918946, 'tag_name': 'cli-v0.1.5', 'draft': True,\n"
                "  'published_at': None, 'prerelease': False,\n"
                "  'html_url': 'https://github.com/HuGR-Labs/corelink-cli/releases/tag/cli-v0.1.5',\n"
                "  'upload_url': 'https://uploads.github.com/repos/HuGR-Labs/corelink-cli/releases/400918946/assets{?name,label}',\n"
                "  'assets': []}\n"
                "json.dump(release, sys.stdout)\n"
                "print()\n",
                encoding="utf-8",
            )
            fake_gh.chmod(0o755)
            environment = dict(__import__("os").environ)
            environment.update({
                "PATH": f"{fake_bin}:{environment['PATH']}",
                "GH_CALL_LOG": str(calls),
                "GH_TOKEN": "",
                "GH_ENTERPRISE_TOKEN": "",
                "GITHUB_ENTERPRISE_TOKEN": "",
            })
            result = subprocess.run(
                [
                    "python3", "scripts/cli_release_api.py", "--repo", "HuGR-Labs/corelink-cli",
                    "--tag", "cli-v0.1.5", "--release-id", "400918946",
                    "--expected-state", "draft", "--format", "id",
                ],
                cwd=Path(__file__).resolve().parents[1], env=environment,
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "400918946\n")
            self.assertEqual(json.loads(calls.read_text(encoding="utf-8")), [
                "api", "repos/HuGR-Labs/corelink-cli/releases/400918946",
            ])

    def test_production_workflows_use_id_for_api_reads_and_preserve_source_oidc_identity(self) -> None:
        caller = Path(".github/workflows/release-cli.yml").read_text(encoding="utf-8")
        slsa = Path(".github/workflows/release-slsa3.yml").read_text(encoding="utf-8")
        self.assertNotIn("releases/tags/", caller)
        self.assertNotIn("releases/tags/", slsa)
        self.assertIn("release_id: ${{ steps.create-release.outputs.release_id }}", caller)
        self.assertIn("release_id: ${{ needs.release.outputs.release_id }}", caller)
        self.assertIn("RELEASE_ID: ${{ needs.release.outputs.release_id }}", caller)
        self.assertIn("RELEASE_ID: ${{ inputs.release_id }}", slsa)
        self.assertIn("--expected-state draft", caller)
        self.assertIn("--expected-state published", caller)
        self.assertIn("--create-or-reuse-empty-draft", caller)
        self.assertNotIn('gh release create "${TAG}"', caller)
        slsa_job = re.search(r"(?ms)^  release-slsa3:\n(.*?)(?=^  [a-z0-9_-]+:\n|\Z)", caller)
        self.assertIsNotNone(slsa_job)
        self.assertIn("always()", slsa_job.group(1))
        for job in ("final-manifest", "release-readiness", "release"):
            self.assertIn(f"needs.{job}.result == 'success'", slsa_job.group(1))
        self.assertIn('test "${GITHUB_REF}" = "refs/tags/${TAG}"', slsa)
        self.assertIn('test "${GITHUB_SHA}" = "${SOURCE_SHA}"', slsa)
        self.assertIn('--source-ref "refs/tags/${TAG}" --source-digest "${SOURCE_SHA}"', caller)
        self.assertIn('gh api --method PATCH "repos/HuGR-Labs/corelink-cli/releases/${RELEASE_ID}"', caller)

    def test_actual_workflow_dag_runs_slsa_for_draft_with_skipped_windows_and_rejects_bad_prerequisites(self) -> None:
        jobs = yaml.safe_load(Path(".github/workflows/release-cli.yml").read_text(encoding="utf-8"))["jobs"]
        slsa = jobs["release-slsa3"]
        condition = slsa["if"]
        self.assertEqual(slsa["needs"], ["final-manifest", "release-readiness", "release"])
        self.assertIn("always()", condition)
        draft = {"build": "success", "release-readiness": "success", "release": "success",
                 "sign-linux": "success", "sign-windows": "skipped", "final-manifest": "success"}
        self.assertIn("sign-windows", _workflow_ancestors(jobs, "release-slsa3"))
        self.assertFalse(_implicit_success(jobs, "release-slsa3", draft))
        self.assertTrue(_slsa_condition(condition, draft))
        public = dict(draft, **{"sign-windows": "success"})
        self.assertTrue(_slsa_condition(condition, public))
        for required in slsa["needs"]:
            for state in ("failure", "cancelled", "skipped", "missing"):
                states = dict(draft)
                if state == "missing":
                    states.pop(required, None)
                else:
                    states[required] = state
                self.assertFalse(_slsa_condition(condition, states), (required, state))
        for ancestor in _workflow_ancestors(jobs, "release-slsa3"):
            for state in ("failure", "cancelled", "skipped", "missing"):
                if ancestor == "sign-windows" and state == "skipped":
                    continue  # the one intentional draft-only skipped prerequisite
                states = dict(draft)
                if state == "missing":
                    states.pop(ancestor, None)
                else:
                    states[ancestor] = state
                # A failed/missing upstream job prevents its affected direct
                # SLSA needs from succeeding; the production DAG must not
                # convert that prerequisite failure into an attestation.
                if ancestor in {"build", "sign-linux", "sign-windows"}:
                    states["final-manifest"] = "skipped"
                elif ancestor == "release-readiness":
                    states["release-readiness"] = state
                elif ancestor == "release":
                    states["release"] = state
                elif ancestor == "final-manifest":
                    states["final-manifest"] = state
                self.assertFalse(_slsa_condition(condition, states), (ancestor, state))

        verify_if = jobs["verify-draft-release"]["if"]
        self.assertIn("needs.release-slsa3.result == 'success'", verify_if)
        publish_if = jobs["publish-release"]["if"]
        self.assertIn("inputs.release_mode == 'signed-public'", publish_if)
        self.assertIn("needs.sign-windows.result == 'success'", publish_if)
        self.assertIn("needs.release-slsa3.result == 'success'", publish_if)
        self.assertFalse("draft-only" in publish_if)
        self.assertFalse(_slsa_condition(condition.replace("always() &&", "", 1), draft))


class CanonicalChecksumWorkflowTests(unittest.TestCase):
    repo = Path(__file__).resolve().parents[1]

    def workflow_command(self, workflow_name: str, step_name: str, directory: Path) -> subprocess.CompletedProcess[str]:
        workflow = yaml.safe_load((self.repo / ".github/workflows" / workflow_name).read_text(encoding="utf-8"))
        step = next(
            step for job in workflow["jobs"].values() for step in job.get("steps", [])
            if step.get("name") == step_name
        )
        environment = dict(__import__("os").environ)
        environment["CHECKSUM_DIRECTORY"] = str(directory)
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", step["run"]],
            cwd=self.repo, env=environment, text=True, capture_output=True, check=False,
        )

    def run_manifest_verifier(self, directory: Path, fake_bin: Path) -> subprocess.CompletedProcess[str]:
        manifest = directory / "release-manifest.json"
        environment = dict(__import__("os").environ)
        environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
        return subprocess.run(
            [
                "python3", "scripts/cli_release_draft_manifest.py", "verify-manifest",
                "--directory", str(directory), "--manifest", str(manifest),
                "--public-key", "docs/internal/gpg-release-pubkey.asc",
                "--tag", TAG, "--source-sha", SOURCE, "--manifest-sha256", sha(manifest),
            ],
            cwd=self.repo, env=environment, text=True, capture_output=True, check=False,
        )

    def test_real_workflow_checksum_commands_and_manifest_verifier_are_canonical(self) -> None:
        with tempfile.TemporaryDirectory(prefix="corelink-checksum-flow-") as temporary:
            root = Path(temporary)
            staged = root / "dist"
            staged.mkdir()
            for name in production.BASE_PAYLOADS:
                (staged / name).write_bytes(f"realistic-staged:{name}".encode())
                (staged / f"{name}.sha256").write_text(
                    f"{sha(staged / name)}  {name}\n", encoding="ascii"
                )
            build = self.workflow_command("release-cli.yml", "Build combined checksums.txt", staged)
            self.assertEqual(build.returncode, 0, build.stderr)
            self.assertEqual(
                (staged / "checksums.txt").read_text(encoding="ascii").splitlines(),
                [f"{sha(staged / name)}  {name}" for name in sorted(production.BASE_PAYLOADS)],
            )

            staged_manifest = staged / "staging-manifest.json"
            production.create(staged, staged_manifest, TAG, SOURCE)
            final = root / "assets"
            shutil.copytree(staged, final, ignore=shutil.ignore_patterns("staging-manifest.json"))
            for name in draft.LINUX_PAYLOADS:
                (final / name).write_bytes(f"realistic-signed:{name}".encode())
                (final / f"{name}.asc").write_bytes(f"fixture-signature:{name}".encode())
            for path in final.glob("*.sha256"):
                target = path.name[:-len(".sha256")]
                path.write_text(f"{sha(final / target)}  {target}\n", encoding="ascii")
            for path in final.glob("*.asc"):
                (final / f"{path.name}.sha256").write_text(
                    f"{sha(path)}  {path.name}\n", encoding="ascii"
                )
            signer = self.workflow_command(
                "sign-linux.yml", "Build canonical checksum index from named sidecars", final
            )
            self.assertEqual(signer.returncode, 0, signer.stderr)
            checksum_lines = (final / "checksums.txt").read_text(encoding="ascii").splitlines()
            self.assertEqual(checksum_lines, sorted(checksum_lines, key=lambda line: line.split("  ", 1)[1]))
            manifest = final / "release-manifest.json"
            draft.create(final, manifest, TAG, SOURCE, staged_manifest)

            fake_bin = root / "fake-bin"
            fake_bin.mkdir()
            fake_gpg = fake_bin / "gpg"
            fake_gpg.write_text(
                "#!/bin/sh\n"
                "case \" $* \" in\n"
                "  *' --import '*) exit 0 ;;\n"
                "  *' --verify '*) printf '%s\\n' '[GNUPG:] VALIDSIG 795253CEBD6D54C862CFC4A3EC0AD89A75EC6756 20261001'; exit 0 ;;\n"
                "  *) exit 2 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_gpg.chmod(0o755)
            verified = self.run_manifest_verifier(final, fake_bin)
            self.assertEqual(verified.returncode, 0, verified.stderr)

            index = final / "checksums.txt"
            index.write_text("\n".join(reversed(checksum_lines)) + "\n", encoding="ascii")
            changed_manifest = json.loads(manifest.read_text(encoding="utf-8"))
            for artifact in changed_manifest["artifacts"]:
                if artifact["name"] == "checksums.txt":
                    artifact["sha256"] = sha(index)
            manifest.write_text(
                json.dumps(changed_manifest, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            rejected = self.run_manifest_verifier(final, fake_bin)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("canonical closed-world index", rejected.stderr)
            draft.write_checksums(final)
            draft.create(final, manifest, TAG, SOURCE, staged_manifest)
            verified_again = self.run_manifest_verifier(final, fake_bin)
            self.assertEqual(verified_again.returncode, 0, verified_again.stderr)


if __name__ == "__main__":
    unittest.main()

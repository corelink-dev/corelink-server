import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "requirements-issue-2165-r2-archive.txt"
EXPECTED = {
    "boto3": ("1.43.104", "dc0c4b5c217fa38792d6b2e3c89b0d26220fd938dc173e48adab45d2d05e6977"),
    "botocore": ("1.43.104", "a447978a815f8ac7ef2f4ba103b6a0c310e56536386974df769edb1326f3b208"),
    "jmespath": ("1.1.0", "a5663118de4908c91729bea0acadca56526eb2698e83de10cd116ae0f4e97c64"),
    "python-dateutil": ("2.9.0.post0", "a8b2bc7bffae282281c8140a97d3aa9c14da0b136dfe83f850eea9a5f7470427"),
    "s3transfer": ("0.19.2", "d8168eccca828cbb2cd573675333f3bddd254313a9c42494b84c76b539e8ba25"),
    "six": ("1.17.0", "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274"),
    "urllib3": ("2.8.0", "0cf3cae568d36aa9576b28dfb35f11328f1cb974ca7647d9475ebb86c75ac6e3"),
}


def test_archive_dependency_lock_is_exact_hash_pinned_wheel_closure():
    text = LOCK.read_text(encoding="utf-8")
    assert "--only-binary=:all:" in text
    requirements = {}
    name = version = None
    for raw_line in text.splitlines():
        line = raw_line.strip().rstrip("\\").strip()
        if not line or line.startswith("#") or line.startswith("--only-binary"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9.!+_-]+)", line)
        if match:
            name, version = match.groups()
            assert name not in requirements
            requirements[name] = {"version": version, "hashes": []}
            continue
        hash_match = re.fullmatch(r"--hash=sha256:([a-f0-9]{64})", line)
        assert hash_match and name in requirements, f"invalid or unbound lock line: {line}"
        requirements[name]["hashes"].append(hash_match.group(1))
    assert set(requirements) == set(EXPECTED)
    for package, (version, digest) in EXPECTED.items():
        assert requirements[package] == {"version": version, "hashes": [digest]}

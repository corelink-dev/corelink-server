#!/usr/bin/env python3
"""Credentialless hosted oracle for issue-1700 native supervisor behavior."""
import argparse
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile"
FIXTURE_SOURCE = ROOT / "scripts/fixtures/issue_1700_native_block.c"
WINDOW_SOURCE = ROOT / "crates/corelink-container/src/routes/staging_d1_probe_window.json"
LAUNCHER_SOURCE = ROOT / "scripts/issue_1700_native_supervisor.sh"
SUPERVISOR = "/usr/local/bin/corelink-staging-probe-supervisor"
SERVER = "/usr/local/bin/corelink-server"
WINDOW = json.loads(WINDOW_SOURCE.read_text())
WINDOW_START = WINDOW["starts_ms"]
LAST_ENTRY = WINDOW["last_entry_ms"]
EXPIRY = WINDOW["expires_ms"]
TEST_NOW = WINDOW_START + 120000


def run(args, *, check=True, timeout=60, capture=True):
    return subprocess.run(args, check=check, timeout=timeout, text=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None)


def docker(*args, **kwargs):
    return run(["docker", *args], **kwargs)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def env_args(env):
    result = []
    for key, value in env.items():
        result.extend(["-e", f"{key}={value}"])
    return result


def process_start(pid):
    try:
        raw = pathlib.Path(f"/proc/{pid}/stat").read_text()
    except FileNotFoundError:
        return None
    fields = raw[raw.rfind(")") + 2:].split()
    return fields[19] if len(fields) > 19 else None


def process_tree(root_pid):
    """Capture host PID/start-time identities recursively under a container PID."""
    result = {}
    pending = [root_pid]
    while pending:
        pid = pending.pop()
        start = process_start(pid)
        if start is None or pid in result:
            continue
        result[pid] = start
        children_file = pathlib.Path(f"/proc/{pid}/task/{pid}/children")
        try:
            children = children_file.read_text().split()
        except FileNotFoundError:
            children = []
        pending.extend(int(child) for child in children)
    return result


def live_identity(pid, start):
    current = process_start(pid)
    if current != start:
        return False
    try:
        state = pathlib.Path(f"/proc/{pid}/stat").read_text().split(")", 1)[1].split()[0]
    except (FileNotFoundError, IndexError):
        return False
    if state == "Z":
        return False
    return True


def wait_stopped(container_id, seconds=3):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        running = docker("inspect", "-f", "{{.State.Running}}", container_id).stdout.strip()
        if running == "false":
            return docker("wait", container_id).stdout.strip()
        time.sleep(0.05)
    return None


def inspect(container_id):
    result = docker("inspect", "-f", "{{.State.ExitCode}} {{.State.OOMKilled}} {{.State.Pid}}", container_id)
    code, oom, pid = result.stdout.strip().split()
    return int(code), oom == "true", int(pid)


def launch(image, *, entrypoint, env, report_dir, fixture, clock_shim=None, args=(), shell_child=False):
    command = ["run", "-d", "--entrypoint", entrypoint,
               "-v", f"{fixture}:{SERVER}:ro", "-v", f"{report_dir}:/oracle:rw",
               *(["-v", f"{clock_shim}:/tmp/libissue1700clock.so:ro"] if clock_shim else []),
               *env_args(env), image]
    if shell_child:
        command.extend(["-c", f"{SUPERVISOR} " + " ".join(shlex.quote(arg) for arg in args) +
                        '; rc=$?; exit "$rc"'])
    else:
        command.extend(args)
    return docker(*command).stdout.strip()


def assert_dead(container_id, identities):
    for _ in range(40):
        if not any(live_identity(pid, start) for pid, start in identities.items()):
            return
        time.sleep(0.05)
    survivors = [pid for pid, start in identities.items() if live_identity(pid, start)]
    require(not survivors, f"native timeout left live fixture processes/descriptors: {survivors}")


def compile_clock_shim(output):
    run(["gcc", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror",
         "-DISSUE_1700_CLOCK_SHIM", f"-DISSUE_1700_CLOCK_NOW={TEST_NOW // 1000}",
         str(FIXTURE_SOURCE), "-o", str(output)])


def static_checks():
    launcher = LAUNCHER_SOURCE.read_text()
    expected = {
        "window_start": WINDOW_START,
        "last_entry": LAST_ENTRY,
        "expiry": EXPIRY,
    }
    for key, value in expected.items():
        require(re.search(rf"^{key}={value}$", launcher, re.MULTILINE) is not None,
                f"launcher {key} differs from compiled staging_d1_probe_window.json")
    require('exec /usr/bin/timeout --signal=KILL "$remaining" /usr/local/bin/corelink-server' in launcher,
            "launcher timeout argv/path changed")
    require('test -x /usr/bin/timeout' in (ROOT / "Dockerfile").read_text(),
            "runtime Dockerfile no longer asserts its real timeout binary")
    require(TEST_NOW < min(WINDOW_START + 600000, EXPIRY), "synthetic clock escaped execution window")
    require(TEST_NOW < min(WINDOW_START + 1200000, EXPIRY), "synthetic clock escaped kill window")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--static", action="store_true", help="check frozen source window and launcher wiring only")
    parser.add_argument("--image", help="tag for the hosted runtime-base build")
    args = parser.parse_args()
    static_checks()
    if args.static:
        print("PASS: launcher compiled window matches staging_d1_probe_window.json; fixed argv/path and source wiring")
        return
    require(args.image, "--image is required for the hosted runtime-base oracle")
    require(shutil.which("docker") is not None, "docker CLI is required")
    require(shutil.which("gcc") is not None, "Linux gcc is required for the native fixture")

    docker("build", "--target", "runtime-base", "-f", str(DOCKERFILE), "-t", args.image,
           str(ROOT), timeout=900, capture=False)
    with tempfile.TemporaryDirectory(prefix="i1700-native-") as temp:
        tmp = pathlib.Path(temp)
        fixture = tmp / "corelink-server"
        clock = tmp / "libissue1700clock.so"
        run(["gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror",
             str(FIXTURE_SOURCE), "-o", str(fixture)])
        os.chmod(fixture, 0o755)
        compile_clock_shim(clock)
        os.chmod(clock, 0o755)

        # Verify actual tools and the ordinary runtime UID in the pinned image.
        base = docker("run", "--rm", "--entrypoint", "/bin/sh", args.image, "-c",
                      "test \"$(id -u)\" = 1000 && test -x /usr/bin/timeout && test -x /usr/bin/date && /usr/bin/timeout --version | head -1")
        require("GNU coreutils" in base.stdout, "runtime-base lacks GNU coreutils timeout")

        start = WINDOW_START
        deadline = min(start + 600000, EXPIRY)
        kill_at = min(start + 1200000, EXPIRY)
        base_env = {
            "ENVIRONMENT": "staging", "D1_BINDING_PROXY": "1", "CF_API_TOKEN": "",
            "CLOUDFLARE_ACCOUNT_ID": "6a1fc1c626fc2628823e60b9db01f5cd",
            "D1_DATABASE_ID": "d72a6b39-6a48-4338-bfda-1111dda98604",
            "CORELINK_STAGING_PROBE_STARTED_MS": str(start),
            "CORELINK_STAGING_PROBE_EXECUTION_DEADLINE_MS": str(deadline),
            "CORELINK_STAGING_PROBE_KILL_AT_MS": str(kill_at),
            "LD_PRELOAD": "/tmp/libissue1700clock.so",
        }

        # Invalid cases include an available, instrumented server executable so
        # missing-path errors cannot masquerade as launcher rejection.
        negative_cases = [
            ("wrong-environment", {"ENVIRONMENT": "production"}, ()),
            ("wrong-proxy", {"D1_BINDING_PROXY": "0"}, ()),
            ("token-present", {"CF_API_TOKEN": "sentinel-secret"}, ()),
            ("wrong-account", {"CLOUDFLARE_ACCOUNT_ID": "00000000000000000000000000000000"}, ()),
            ("wrong-database", {"D1_DATABASE_ID": "wrong"}, ()),
            ("short-start", {"CORELINK_STAGING_PROBE_STARTED_MS": "179085600000"}, ()),
            ("nondigit-start", {"CORELINK_STAGING_PROBE_STARTED_MS": "17908560x0000"}, ()),
            ("missing-execution", {"CORELINK_STAGING_PROBE_EXECUTION_DEADLINE_MS": None}, ()),
            ("wrong-execution", {"CORELINK_STAGING_PROBE_EXECUTION_DEADLINE_MS": str(deadline + 1)}, ()),
            ("missing-kill", {"CORELINK_STAGING_PROBE_KILL_AT_MS": None}, ()),
            ("wrong-kill", {"CORELINK_STAGING_PROBE_KILL_AT_MS": str(kill_at + 1)}, ()),
            ("before-window", {"CORELINK_STAGING_PROBE_STARTED_MS": str(WINDOW_START - 1)}, ()),
            ("after-last-entry", {"CORELINK_STAGING_PROBE_STARTED_MS": str(LAST_ENTRY + 1)}, ()),
            ("after-expiry", {"CORELINK_STAGING_PROBE_STARTED_MS": str(EXPIRY)}, ()),
            ("unexpected-arg", {}, ("extra",)),
        ]
        for name, changes, extra_args in negative_cases:
            case_dir = tmp / name
            case_dir.mkdir(mode=0o777)
            os.chmod(case_dir, 0o777)
            case_env = dict(base_env)
            for key, value in changes.items():
                if value is None:
                    case_env.pop(key)
                else:
                    case_env[key] = value
            cid = launch(args.image, entrypoint=SUPERVISOR, env=case_env,
                         report_dir=case_dir, fixture=fixture, clock_shim=clock, args=extra_args)
            try:
                status = wait_stopped(cid, seconds=3)
                require(status is not None, f"launcher accepted/reached fixture for negative case {name}")
                code, oom, _ = inspect(cid)
                require(code == 64 and not oom, f"{name}: expected clean reject exit 64, got {code}/OOM={oom}")
                require(not (case_dir / "started").exists(), f"{name}: server fixture was entered")
                logs = docker("logs", cid, check=False)
                combined_logs = (logs.stdout or "") + (logs.stderr or "")
                require("sentinel-secret" not in combined_logs, f"{name}: token sentinel appeared in logs")
            finally:
                docker("kill", cid, check=False)
                docker("rm", "-f", cid, check=False)

        # PID 1 guard is independently exercised with the same available fixture.
        non_pid_dir = tmp / "non-pid1"
        non_pid_dir.mkdir(mode=0o777)
        os.chmod(non_pid_dir, 0o777)
        cid = launch(args.image, entrypoint="/bin/sh", env=base_env,
                     report_dir=non_pid_dir, fixture=fixture, clock_shim=clock, shell_child=True)
        try:
            status = wait_stopped(cid)
            require(status == "64", f"non-PID1 launcher invocation did not reject: {status}")
            require(not (non_pid_dir / "started").exists(), "non-PID1 invocation reached fixture")
        finally:
            docker("kill", cid, check=False)
            docker("rm", "-f", cid, check=False)

        # True positive: production launcher as PID1, with harness-only frozen
        # CLOCK_REALTIME. The preload fixes wall time; GNU timeout's monotonic
        # timer remains real. ALRM exercises GNU timeout's configured KILL path.
        positive_dir = tmp / "positive"
        positive_dir.mkdir(mode=0o777)
        os.chmod(positive_dir, 0o777)
        cid = launch(args.image, entrypoint=SUPERVISOR, env=base_env,
                     report_dir=positive_dir, fixture=fixture, clock_shim=clock)
        try:
            report = positive_dir / "started"
            for _ in range(100):
                if report.exists():
                    break
                time.sleep(0.05)
            require(report.exists(), "valid launcher did not start the native fixture")
            evidence = report.read_text()
            require("ppid=1 " in evidence, f"native server was not directly beneath timeout PID1: {evidence!r}")
            argv_match = re.search(r"pid1=(.*)", evidence)
            require(argv_match is not None, "fixture did not capture PID1 argv")
            argv = shlex.split(argv_match.group(1))
            require(argv[0] == "/usr/bin/timeout", f"container PID1 is not GNU timeout: {argv!r}")
            require(len(argv) == 4 and argv[0] == "/usr/bin/timeout" and
                    argv[1] == "--signal=KILL" and argv[2] == "1080.000" and argv[3] == SERVER,
                    f"wrong production timeout argv: {argv!r}")
            supervisor_pid = inspect(cid)[2]
            identities = process_tree(supervisor_pid)
            require(len(identities) >= 3, f"did not capture supervisor and forked fixture tree: {identities}")
            require(docker("logs", cid, check=False).stdout == "", "launcher emitted container log output")
            docker("kill", "--signal=ALRM", cid)
            status = wait_stopped(cid, seconds=10)
            code, oom, _ = inspect(cid)
            require(status == "137" and code == 137 and not oom,
                    f"ALRM composition did not produce configured KILL exit: wait={status}, inspect={code}/{oom}")
            assert_dead(cid, identities)
        finally:
            docker("kill", cid, check=False)
            docker("rm", "-f", cid, check=False)

        # Separate real two-second timer run of that exact image GNU timeout
        # binary. This validates elapsed-time expiry independently of ALRM injection.
        timer_dir = tmp / "timer"
        timer_dir.mkdir(mode=0o777)
        os.chmod(timer_dir, 0o777)
        started_at = time.monotonic()
        cid = docker("run", "-d", "--entrypoint", "/usr/bin/timeout",
                     "-v", f"{fixture}:{SERVER}:ro", "-v", f"{timer_dir}:/oracle:rw",
                     args.image, "--signal=KILL", "2.000", SERVER).stdout.strip()
        try:
            for _ in range(100):
                if (timer_dir / "started").exists():
                    break
                time.sleep(0.05)
            require((timer_dir / "started").exists(), "real timeout fixture did not start")
            supervisor_pid = inspect(cid)[2]
            identities = process_tree(supervisor_pid)
            require(len(identities) >= 3, "timer case did not capture forked native process tree")
            status = wait_stopped(cid, seconds=10)
            elapsed = time.monotonic() - started_at
            code, oom, _ = inspect(cid)
            require(status == "137" and code == 137 and not oom,
                    f"2s GNU timeout did not produce KILL exit: wait={status}, inspect={code}/{oom}")
            require(1.5 <= elapsed <= 8.0, f"GNU timeout 2s timer elapsed unexpectedly: {elapsed:.2f}s")
            assert_dead(cid, identities)
        finally:
            docker("kill", cid, check=False)
            docker("rm", "-f", cid, check=False)

    print("PASS: pinned runtime-base UID/coreutils, launcher rejection/positive PID1, configured hard-kill, and real 2s GNU timeout")
    print("LIMIT: production start/deadline/kill arithmetic and argv are exercised at frozen test time; ALRM reaches GNU timeout's configured KILL path. The production 1200s outer lifetime is not waited in wall time; a separate real 2s timer uses the same image binary.")


if __name__ == "__main__":
    main()

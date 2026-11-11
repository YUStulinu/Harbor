"""Isolation tests: what a process inside a Harbor container can and cannot do.

Run as root on Linux (in WSL2: `sudo python3 -m pytest tests -q`), with `harbor` and
`harbor-registry` on PATH and the alpine:3.20 and python:3.12-alpine images pulled (the tests pull
them if needed).

Every test starts real containers from images (overlayfs root, namespaces, cgroup limits,
seccomp) and checks the effect from both sides.
"""
import json
import os
import shutil
import subprocess
import time
import uuid

import pytest

HARBOR = shutil.which("harbor") or "/usr/local/bin/harbor"
ALPINE = "alpine:3.20"
PYTHON = "python:3.12-alpine"

pytestmark = pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0 or not os.path.exists(HARBOR),
                                reason="needs root on Linux with harbor installed")


def harbor(*args, check=True, timeout=120):
    r = subprocess.run([HARBOR, *args], capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise AssertionError(f"harbor {' '.join(args)} -> {r.returncode}\n{r.stdout}\n{r.stderr}")
    return r


def run(image, *cmd, flags=(), check=True, timeout=120):
    """Runs a container in the foreground and removes it; returns the CompletedProcess."""
    return harbor("run-image", "--rm", *flags, image, *cmd, check=check, timeout=timeout)


def run_keep(image, *cmd, flags=(), timeout=120):
    """Runs a container to completion and keeps it, to read its final cgroup statistics."""
    name = "t-" + uuid.uuid4().hex[:8]
    r = harbor("run-image", "--name", name, *flags, image, *cmd, check=False, timeout=timeout)
    meta = json.loads(harbor("inspect", name).stdout)
    harbor("rm", "-f", name)
    return r, meta


@pytest.fixture(scope="module", autouse=True)
def images():
    for img in (ALPINE, PYTHON):
        if subprocess.run(["harbor-registry", "inspect", img], capture_output=True).returncode != 0:
            subprocess.run(["harbor-registry", "pull", img], check=True)


# ---------------------------------------------------------------- processes

def test_pid_namespace_hides_host_processes():
    host = subprocess.Popen(["sleep", "300"])
    try:
        r = run(ALPINE, "sh", "-c", f"ps -o pid,comm; echo ---; ls /proc | grep -c '^[0-9]'; kill -0 {host.pid} && echo KILLED-HOST || echo cannot-signal")
        procs = int(r.stdout.split("---")[1].split()[0])
        assert procs <= 3, r.stdout  # sh, ps / ls, grep
        assert "  1 sh" in r.stdout or " 1 sh" in r.stdout
        assert "cannot-signal" in r.stdout
        assert host.poll() is None  # the host process is untouched
    finally:
        host.kill()


def test_container_sees_its_own_hostname_and_mounts():
    r = run(ALPINE, "sh", "-c", "hostname; grep -c . /proc/self/mounts", flags=("--hostname", "isolated"))
    name, mounts = r.stdout.split()
    assert name == "isolated"
    host_mounts = sum(1 for _ in open("/proc/self/mounts"))
    assert int(mounts) < host_mounts


# ---------------------------------------------------------------- resources

def test_memory_limit_kills_the_allocation():
    r, meta = run_keep(PYTHON, "python3", "-c", "b = bytearray(200 << 20); print('allocated', len(b))", flags=("--memory", "64m"))
    assert r.returncode == 137, r.stdout + r.stderr  # SIGKILL from the OOM killer
    assert "allocated" not in r.stdout
    stats = meta["final_stats"]
    assert stats["oom_kills"] >= 1
    assert stats["memory_max"] == 64 << 20
    assert stats["memory_peak"] <= 64 << 20


def test_memory_under_the_limit_is_fine():
    r = run(PYTHON, "python3", "-c", "b = bytearray(20 << 20); print('allocated', len(b))", flags=("--memory", "64m"))
    assert "allocated 20971520" in r.stdout


def parse_time(s):
    """Go's RFC 3339 with nanoseconds ("2026-11-11T20:01:02.123456789Z") -> seconds."""
    from datetime import datetime, timezone
    base, _, frac = s.rstrip("Z").partition(".")
    t = datetime.fromisoformat(base).replace(tzinfo=timezone.utc).timestamp()
    return t + (float("0." + frac) if frac else 0.0)


def cpu_share(cpus, seconds=3.0, procs=1):
    """CPU time used divided by the container's wall-clock lifetime (1.0 = one full core)."""
    script = "\n".join([
        "import multiprocessing as m, time",
        "def spin():",
        f"    end = time.time() + {seconds}",
        "    while time.time() < end: pass",
        f"ps = [m.Process(target=spin) for _ in range({procs})]",
        "[p.start() for p in ps]; [p.join() for p in ps]",
    ])
    flags = ("--cpus", str(cpus)) if cpus else ()
    _, meta = run_keep(PYTHON, "python3", "-c", script, flags=flags)
    wall = parse_time(meta["finished"]) - parse_time(meta["started"])
    return meta["final_stats"]["cpu_usage_usec"] / 1e6 / wall


def test_cpu_limit_caps_cpu_time():
    # A quota of half a CPU: the container gets about half a core, however hard it spins.
    share = cpu_share(0.5)
    assert 0.4 < share < 0.6, share
    # Two spinning processes with 1.5 CPUs: about 1.5 cores; without a limit: about 2.
    share = cpu_share(1.5, procs=2)
    assert 1.3 < share < 1.65, share
    if (os.cpu_count() or 1) >= 2:
        assert cpu_share(None, procs=2) > 1.75


def test_pids_limit_stops_a_fork_bomb():
    script = ("import subprocess\nok = 0\n"
              "for i in range(60):\n"
              "    try:\n        subprocess.Popen(['sleep', '5']); ok += 1\n"
              "    except OSError as e:\n        print('refused', e.errno); break\n"
              "print('started', ok)\n")
    r = run(PYTHON, "python3", "-c", script, flags=("--pids", "20"), timeout=60)
    started = int(r.stdout.split("started")[1].split()[0])
    assert started < 20, r.stdout
    assert "refused 11" in r.stdout  # EAGAIN


# ---------------------------------------------------------------- filesystem

def test_host_files_are_not_visible_and_writes_stay_inside():
    secret = f"/root/harbor-secret-{uuid.uuid4().hex[:8]}"
    open(secret, "w").write("host only\n")
    try:
        r = run(ALPINE, "sh", "-c", f"cat {secret} 2>&1; echo inside > /etc/written-by-container; ls /etc/written-by-container", check=False)
        assert "host only" not in r.stdout
        assert "/etc/written-by-container" in r.stdout
        assert not os.path.exists("/etc/written-by-container")
        # A new container from the same image does not see the previous one's writes.
        r2 = run(ALPINE, "sh", "-c", "ls /etc/written-by-container 2>&1 || true")
        assert "No such file" in r2.stdout
    finally:
        os.remove(secret)


def test_read_only_root():
    r = run(ALPINE, "sh", "-c", "touch /x 2>&1; echo ok > /tmp/x 2>&1; echo done", flags=("--read-only",), check=False)
    assert "Read-only file system" in r.stdout


def test_sensitive_kernel_files_are_masked_or_read_only():
    r = run(ALPINE, "sh", "-c", "wc -c < /proc/kcore; echo x > /proc/sys/kernel/hostname 2>&1; echo 1 > /proc/sysrq-trigger 2>&1; echo done", check=False)
    assert r.stdout.split()[0] == "0"  # /dev/null is bound over it
    assert (r.stdout + r.stderr).count("Read-only file system") == 2


# ---------------------------------------------------------------- privileges

def test_capabilities_and_seccomp_block_privileged_calls():
    r = run(ALPINE, "sh", "-c",
            "mount -t tmpfs none /mnt 2>&1; unshare -U true 2>&1; ip link add x type dummy 2>&1; "
            "grep -E '^(CapEff|NoNewPrivs|Seccomp):' /proc/self/status; echo done", check=False)
    out = r.stdout
    assert "mount: permission denied" in out or "Operation not permitted" in out
    assert out.count("Operation not permitted") >= 2, out
    caps = int(next(l for l in out.splitlines() if l.startswith("CapEff")).split()[1], 16)
    assert caps & (1 << 21) == 0  # no CAP_SYS_ADMIN
    assert caps & (1 << 12) == 0  # no CAP_NET_ADMIN
    assert "NoNewPrivs:\t1" in out
    assert "Seccomp:\t2" in out


def test_root_in_a_user_namespace_is_nobody_outside():
    """OCI bundle with a user namespace: uid 0 inside is uid 100000 on the host."""
    import pathlib
    import tempfile
    info = json.loads(subprocess.run(["harbor-registry", "inspect", ALPINE], capture_output=True, text=True, check=True).stdout)
    # Every directory above the rootfs must be searchable by uid 100000 (pytest's tmp_path is
    # under a 0700 directory).
    tmp_path = pathlib.Path(tempfile.mkdtemp(prefix="harbor-userns-", dir="/tmp"))
    bundle = tmp_path / "b"
    (bundle / "rootfs").mkdir(parents=True)
    subprocess.run(["cp", "-a", info["layers"][0] + "/.", str(bundle / "rootfs")], check=True)
    subprocess.run(["chown", "-R", "100000:100000", str(bundle / "rootfs")], check=True)
    os.chmod(tmp_path, 0o755)
    subprocess.run([HARBOR, "spec"], cwd=bundle, check=True)
    cfg = json.loads((bundle / "config.json").read_text())
    cfg["process"]["args"] = ["sh", "-c", "id -u; sleep 3"]
    cfg["linux"]["namespaces"].append({"type": "user"})
    cfg["linux"]["uidMappings"] = [{"containerID": 0, "hostID": 100000, "size": 65536}]
    cfg["linux"]["gidMappings"] = [{"containerID": 0, "hostID": 100000, "size": 65536}]
    (bundle / "config.json").write_text(json.dumps(cfg))
    cid = "userns-" + uuid.uuid4().hex[:6]
    p = subprocess.Popen([HARBOR, "run", "--bundle", str(bundle), cid], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        time.sleep(1.0)
        st = json.loads(harbor("state", cid).stdout)
        status = open(f"/proc/{st['pid']}/status").read()
        uid_line = next(l for l in status.splitlines() if l.startswith("Uid:"))
        assert uid_line.split()[1] == "100000"
        out, _ = p.communicate(timeout=30)
        assert out.split()[0] == "0"
    except Exception:
        p.kill()
        raise AssertionError("container failed: " + p.communicate()[1])
    finally:
        p.kill()
        harbor("delete", "--force", cid, check=False)
        shutil.rmtree(tmp_path, ignore_errors=True)


# ---------------------------------------------------------------- network

def test_no_network_means_loopback_only():
    r = run(ALPINE, "sh", "-c", "ip -o link | awk -F': ' '{print $2}'; wget -q -T 3 -O- http://1.1.1.1 >/dev/null 2>&1 && echo reached || echo unreachable",
            flags=("--net", "none"), check=False)
    assert r.stdout.split()[0] == "lo"
    assert "eth0" not in r.stdout
    assert "unreachable" in r.stdout


def test_bridge_network_connects_containers():
    server = harbor("run-image", "-d", "--name", "srv-" + uuid.uuid4().hex[:6], PYTHON, "sh", "-c",
                    "cd /tmp && echo hello-from-server > i && exec python3 -m http.server 8080").stdout.strip()
    try:
        meta = json.loads(harbor("inspect", server).stdout)
        ip = meta["ip"]
        assert ip.startswith("10.88.")
        time.sleep(1.5)
        r = run(ALPINE, "wget", "-q", "-T", "5", "-O-", f"http://{ip}:8080/i")
        assert "hello-from-server" in r.stdout
        # The host reaches it too, through the bridge.
        import urllib.request
        assert b"hello-from-server" in urllib.request.urlopen(f"http://{ip}:8080/i", timeout=5).read()
    finally:
        harbor("rm", "-f", server, check=False)

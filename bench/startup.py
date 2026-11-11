"""Start-up time and run-time overhead: Harbor against runc, on the same OCI bundle.

    sudo python3 bench/startup.py --out results/bench.json

1. Start-up. The same bundle (Alpine rootfs, `harbor spec` config: pid/net/ipc/uts/mount/cgroup
   namespaces, a seccomp profile, capabilities) runs `/bin/true` with `RUNTIME run`, many times,
   alternating the two runtimes. Also timed: each phase (create, start, delete) separately.
2. Image containers. `harbor run-image --rm alpine true`: overlayfs root, bridge network (veth,
   address, routes) and the shim, compared with --net none.
3. Overhead. A CPU-bound job (busybox sha256sum over 256 MB from yes) and a fork-heavy job
   (500 `true` processes), on the host (chroot into the same rootfs, so the same binaries) and in
   containers under each runtime.
"""
import argparse
import json
import os
import shutil
import statistics
import subprocess
import tempfile
import time
import uuid

RUNTIMES = ["harbor", "runc"]


def sh(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


def make_bundle(args):
    info = json.loads(sh(["harbor-registry", "inspect", "alpine:3.20"]).stdout)
    b = tempfile.mkdtemp(prefix="harbor-bench-", dir="/tmp")
    os.makedirs(os.path.join(b, "rootfs"))
    sh(["cp", "-a", info["layers"][0] + "/.", os.path.join(b, "rootfs")])
    sh(["harbor", "spec"], cwd=b)
    cfg = json.load(open(os.path.join(b, "config.json")))
    cfg["process"]["args"] = args
    json.dump(cfg, open(os.path.join(b, "config.json"), "w"))
    return b


def set_args(bundle, args):
    p = os.path.join(bundle, "config.json")
    cfg = json.load(open(p))
    cfg["process"]["args"] = args
    json.dump(cfg, open(p, "w"))


def timed(cmd, **kw):
    t = time.perf_counter()
    # Not a pipe: after `create`, the container's init keeps the runtime's stdio open.
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, **kw)
    return time.perf_counter() - t


def summary(xs):
    xs = sorted(xs)
    return {"n": len(xs), "median_ms": round(1000 * statistics.median(xs), 2), "mean_ms": round(1000 * statistics.mean(xs), 2),
            "p10_ms": round(1000 * xs[len(xs) // 10], 2), "p90_ms": round(1000 * xs[9 * len(xs) // 10], 2),
            "min_ms": round(1000 * xs[0], 2), "samples_ms": [round(1000 * x, 2) for x in xs]}


def bench_startup(bundle, n):
    set_args(bundle, ["/bin/true"])
    total = {r: [] for r in RUNTIMES}
    phases = {r: {"create": [], "start": [], "delete": []} for r in RUNTIMES}
    for i in range(n + 5):
        for rt in (RUNTIMES if i % 2 == 0 else RUNTIMES[::-1]):
            cid = f"b{uuid.uuid4().hex[:10]}"
            t = timed([rt, "run", "--bundle", bundle, cid])
            if i >= 5:  # warm-up
                total[rt].append(t)
    for i in range(n // 2 + 3):
        for rt in RUNTIMES:
            set_args(bundle, ["/bin/sleep", "10"])
            cid = f"p{uuid.uuid4().hex[:10]}"
            tc = timed([rt, "create", "--bundle", bundle, cid])
            ts = timed([rt, "start", cid])
            subprocess.run([rt, "kill", cid, "KILL"], capture_output=True)
            for _ in range(200):
                st = json.loads(sh([rt, "state", cid]).stdout)
                if st["status"] == "stopped":
                    break
                time.sleep(0.005)
            td = timed([rt, "delete", cid])
            if i >= 3:
                phases[rt]["create"].append(tc)
                phases[rt]["start"].append(ts)
                phases[rt]["delete"].append(td)
    return {rt: {"run": summary(total[rt]), **{k: summary(v) for k, v in phases[rt].items()}} for rt in RUNTIMES}


def bench_images(n):
    out = {}
    for net in ("bridge", "none"):
        xs = []
        for i in range(n + 3):
            t = timed(["harbor", "run-image", "--rm", "--net", net, "alpine:3.20", "true"])
            if i >= 3:
                xs.append(t)
        out[net] = summary(xs)
    return out


def bench_overhead(bundle, reps):
    jobs = {
        # No /dev in the chroot: the data comes from yes, not /dev/zero.
        "sha256_256MB": ["sh", "-c", "yes | head -c 268435456 | sha256sum > /dev/null"],
        "fork_500": ["sh", "-c", "i=0; while [ $i -lt 500 ]; do /bin/true; i=$((i+1)); done"],
    }
    res = {}
    rootfs = os.path.join(bundle, "rootfs")
    for name, args in jobs.items():
        set_args(bundle, args)
        times = {"host_chroot": [], **{rt: [] for rt in RUNTIMES}}
        for i in range(reps + 1):
            # Inside the job itself, not the container's start-up: time it in the container.
            for where in times:
                if where == "host_chroot":
                    t = timed(["chroot", rootfs, *args])
                else:
                    t0 = time.perf_counter()
                    subprocess.run([where, "run", "--bundle", bundle, f"o{uuid.uuid4().hex[:10]}"], check=True, stdout=subprocess.DEVNULL)
                    t = time.perf_counter() - t0
                if i >= 1:
                    times[where].append(t)
        res[name] = {k: summary(v) for k, v in times.items()}
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-n", type=int, default=200, help="start-ups per runtime")
    ap.add_argument("--image-runs", type=int, default=40)
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--out")
    args = ap.parse_args()
    bundle = make_bundle(["/bin/true"])
    try:
        versions = {"harbor": "dev", "runc": sh(["runc", "--version"]).stdout.splitlines()[0],
                    "kernel": os.uname().release, "cpus": os.cpu_count()}
        res = {"versions": versions}
        print("start-up ...", flush=True)
        res["startup"] = bench_startup(bundle, args.n)
        for rt in RUNTIMES:
            s = res["startup"][rt]
            print(f"  {rt:7} run {s['run']['median_ms']:7.1f} ms  (create {s['create']['median_ms']:.1f}, start {s['start']['median_ms']:.1f}, delete {s['delete']['median_ms']:.1f})")
        print("image containers ...", flush=True)
        res["run_image"] = bench_images(args.image_runs)
        for net, s in res["run_image"].items():
            print(f"  run-image --net {net:6} {s['median_ms']:7.1f} ms")
        print("overhead ...", flush=True)
        res["overhead"] = bench_overhead(bundle, args.reps)
        for job, d in res["overhead"].items():
            print("  " + job + ": " + ", ".join(f"{k} {v['median_ms']:.0f} ms" for k, v in d.items()))
        if args.out:
            os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
            json.dump(res, open(args.out, "w"), indent=1)
    finally:
        shutil.rmtree(bundle, ignore_errors=True)


if __name__ == "__main__":
    main()

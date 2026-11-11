"""Runs the OCI runtime-tools validation suite against a runtime and counts what passes.

    sudo python3 bench/oci_conformance.py --runtime harbor --tools /opt/oci/runtime-tools --out results/oci_harbor.json

Every validation/*/*.t program (built with `make runtimetest validation-executables` in a
checkout of github.com/opencontainers/runtime-tools) is run with RUNTIME=<runtime>. Each prints
TAP: "ok N - ...", "not ok N - ...", with "# SKIP" for checks that do not apply. We count
assertions (passed / failed / skipped) and programs (a program passes when none of its
assertions failed and it exits cleanly). A program that crashes or times out counts as one
failed assertion; one that prints no assertions and exits 0 (the *_fail programs, when the
runtime correctly refuses a bad config) counts as one passed assertion.
"""
import argparse
import glob
import json
import os
import re
import subprocess
import time

TAP = re.compile(r"^(not ok|ok)\b\s*(\d+)?\s*-?\s*(.*)$")


def parse_tap(text):
    results = []
    for line in text.splitlines():
        m = TAP.match(line)
        if not m:
            continue
        status, _, desc = m.groups()
        skip = "# SKIP" in desc.upper() or "# TODO" in desc.upper()
        results.append({"ok": status == "ok", "skip": skip, "desc": desc.strip()})
    return results


def run_one(path, runtime, cwd, timeout):
    t0 = time.time()
    try:
        p = subprocess.run([path], cwd=cwd, capture_output=True, text=True, timeout=timeout,
                           env=dict(os.environ, RUNTIME=runtime))
        out, code, timed_out = p.stdout + p.stderr, p.returncode, False
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        code, timed_out = -1, True
    results = parse_tap(out)
    passed = sum(1 for r in results if r["ok"] and not r["skip"])
    skipped = sum(1 for r in results if r["skip"])
    failed = sum(1 for r in results if not r["ok"] and not r["skip"])
    # The *_fail programs print no TAP when the runtime correctly rejects the config: they
    # just exit 0 (and exit non-zero, after a message, when it does not).
    if not results and not timed_out and code == 0:
        passed = 1
    crashed = timed_out or (not results and code != 0) or (code != 0 and failed == 0)
    if crashed:
        failed += 1
    return {
        "test": os.path.basename(os.path.dirname(path)),
        "passed": passed, "failed": failed, "skipped": skipped,
        "exit_code": code, "timed_out": timed_out, "seconds": round(time.time() - t0, 2),
        "ok": failed == 0 and passed + skipped > 0,
        "failures": [r["desc"] for r in results if not r["ok"] and not r["skip"]][:20],
        "output_tail": out[-1500:] if (failed or crashed) else "",
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runtime", required=True)
    ap.add_argument("--tools", default="/opt/oci/runtime-tools")
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--out")
    args = ap.parse_args()
    tests = sorted(glob.glob(os.path.join(args.tools, "validation", "*", "*.t")))
    if args.only:
        tests = [t for t in tests if os.path.basename(os.path.dirname(t)) in args.only]
    rows = []
    for t in tests:
        r = run_one(t, args.runtime, args.tools, args.timeout)
        rows.append(r)
        mark = "PASS" if r["ok"] else "FAIL"
        print(f"{mark} {r['test']:<40} {r['passed']:>3} ok {r['failed']:>3} failed {r['skipped']:>3} skipped  {r['seconds']:6.1f}s", flush=True)
    tot = {k: sum(r[k] for r in rows) for k in ("passed", "failed", "skipped")}
    judged = tot["passed"] + tot["failed"]
    summary = {
        "runtime": args.runtime,
        "programs": len(rows), "programs_passed": sum(r["ok"] for r in rows),
        **tot,
        "assertion_pass_rate": round(100 * tot["passed"] / judged, 1) if judged else 0.0,
        "program_pass_rate": round(100 * sum(r["ok"] for r in rows) / len(rows), 1) if rows else 0.0,
    }
    print(json.dumps(summary, indent=1))
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w") as fh:
            json.dump({"summary": summary, "tests": rows}, fh, indent=1)


if __name__ == "__main__":
    main()

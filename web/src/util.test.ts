import { describe, expect, it } from "vitest";
import { escapeHtml, fmtBytes, fmtCpuMax, fmtDuration, memoryFraction, nearest, secondsBetween, splitArgs, statusKind, statusLabel, ticks } from "./util";

describe("formatting", () => {
  it("formats bytes", () => {
    expect(fmtBytes(512)).toBe("512 B");
    expect(fmtBytes(64 << 20)).toBe("64.0 MiB");
    expect(fmtBytes(1536)).toBe("1.5 KiB");
    expect(fmtBytes(200 << 20)).toBe("200 MiB");
    expect(fmtBytes(-1)).toBe("–");
    expect(fmtBytes(undefined)).toBe("–");
  });
  it("formats CPU quotas", () => {
    expect(fmtCpuMax("max 100000")).toBe("unlimited");
    expect(fmtCpuMax("50000 100000")).toBe("0.5 CPU");
    expect(fmtCpuMax("150000 100000")).toBe("1.5 CPU");
    expect(fmtCpuMax(undefined)).toBe("–");
  });
  it("formats durations and Go timestamps", () => {
    expect(fmtDuration(3.21)).toBe("3.2 s");
    expect(fmtDuration(75)).toBe("1 min 15 s");
    expect(fmtDuration(3720)).toBe("1 h 2 min");
    expect(secondsBetween("2026-11-11T20:00:00.123456789Z", "2026-11-11T20:00:02.623Z")).toBeCloseTo(2.5, 2);
  });
  it("escapes html", () => {
    expect(escapeHtml(`<b a="x">'&'</b>`)).toBe("&lt;b a=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/b&gt;");
  });
});

describe("status", () => {
  it("labels and kinds", () => {
    expect(statusLabel({ status: "running" })).toBe("running");
    expect(statusLabel({ status: "exited", exit_code: 0 })).toBe("exited (0)");
    expect(statusLabel({ status: "exited", exit_code: 125, error: "x" })).toBe("failed");
    expect(statusKind({ status: "running" })).toBe("good");
    expect(statusKind({ status: "exited", exit_code: 0 })).toBe("neutral");
    expect(statusKind({ status: "exited", exit_code: 137 })).toBe("warning");
    expect(statusKind({ status: "exited", exit_code: 1 })).toBe("critical");
  });
  it("computes memory use against the limit", () => {
    const s = { memory_current: 16, memory_max: 64, memory_peak: 0, oom_kills: 0, cpu_usage_usec: 0, cpu_throttled_usec: 0, cpu_max: "", pids_current: 0, pids_max: 0 };
    expect(memoryFraction(s)).toBe(0.25);
    expect(memoryFraction({ ...s, memory_max: -1 })).toBeNull();
    expect(memoryFraction({ ...s, memory_current: 100 })).toBe(1);
  });
});

describe("parsing", () => {
  it("splits command lines", () => {
    expect(splitArgs(`sh -c 'echo hi; sleep 600'`)).toEqual(["sh", "-c", "echo hi; sleep 600"]);
    expect(splitArgs(` python3   -c "print(1)" `)).toEqual(["python3", "-c", "print(1)"]);
    expect(splitArgs(`echo '' x`)).toEqual(["echo", "", "x"]);
    expect(splitArgs("")).toEqual([]);
  });
  it("ticks and nearest", () => {
    expect(ticks(100)).toEqual([0, 20, 40, 60, 80, 100]);
    expect(nearest([0, 2, 4], 2.9)).toBe(1);
  });
});

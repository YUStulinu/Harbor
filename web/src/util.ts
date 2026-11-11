// Data shapes of the harbor API and pure helpers (tested in util.test.ts).

export interface Stats {
  memory_current: number;
  memory_max: number; // -1 = no limit
  memory_peak: number;
  oom_kills: number;
  cpu_usage_usec: number;
  cpu_throttled_usec: number;
  cpu_max: string;
  pids_current: number;
  pids_max: number;
}

export interface Sample {
  t: string;
  cpu_percent: number;
  memory: number;
  pids: number;
}

export interface Container {
  id: string;
  name: string;
  image: string;
  digest: string;
  args: string[];
  created: string;
  started?: string;
  finished?: string;
  exit_code?: number;
  error?: string;
  pid?: number;
  net: string;
  ip?: string;
  limits: { memory_bytes?: number; cpus?: number; pids?: number };
  status: string;
  stats?: Stats;
  final_stats?: Stats;
  history?: Sample[];
}

export interface LogLine {
  t: string;
  s: "stdout" | "stderr";
  l: string;
}

export interface Host {
  kernel: string;
  hostname: string;
  cpus: number;
  memory: number;
  bridge: string;
  subnet: string;
}

export interface Image {
  name: string;
  digest: string;
  size: string;
}

export function fmtBytes(n: number | undefined | null): string {
  if (n == null || n < 0) return "–";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

/** "max" or "50000 100000" -> "unlimited" / "0.5 CPU". */
export function fmtCpuMax(s: string | undefined): string {
  if (!s) return "–";
  const [q, p] = s.split(" ");
  if (q === "max") return "unlimited";
  const v = Number(q) / Number(p || 100000);
  return Number.isFinite(v) ? `${+v.toFixed(2)} CPU` : s;
}

/** Seconds between two RFC 3339 times (Go writes nanoseconds; Date keeps milliseconds). */
export function secondsBetween(a: string, b: string): number {
  return (Date.parse(b) - Date.parse(a)) / 1000;
}

export function fmtDuration(s: number): string {
  if (!Number.isFinite(s) || s < 0) return "–";
  if (s < 60) return `${s < 10 ? s.toFixed(1) : Math.round(s)} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ${Math.round(s - 60 * m)} s`;
  const h = Math.floor(m / 60);
  return `${h} h ${m - 60 * h} min`;
}

/** What the status badge says. */
export function statusLabel(c: Pick<Container, "status" | "exit_code" | "error">): string {
  if (c.status === "exited") {
    if (c.error) return "failed";
    return c.exit_code === undefined ? "exited" : `exited (${c.exit_code})`;
  }
  return c.status;
}

/** Status tokens for the badge colour: never colour alone, the label is always shown. */
export function statusKind(c: Pick<Container, "status" | "exit_code" | "error">): "good" | "neutral" | "warning" | "critical" {
  if (c.status === "running") return "good";
  if (c.status === "created" || c.status === "creating") return "neutral";
  if (c.error || (c.exit_code !== undefined && c.exit_code !== 0)) return c.exit_code === 137 ? "warning" : "critical";
  return "neutral";
}

/** Memory used as a fraction of the limit, or null without a limit. */
export function memoryFraction(s: Stats | undefined): number | null {
  if (!s || s.memory_max <= 0) return null;
  return Math.min(1, s.memory_current / s.memory_max);
}

/** Parses "a b 'c d'" into argv (single and double quotes, no escapes). */
export function splitArgs(s: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quote: string | null = null;
  let has = false;
  for (const ch of s) {
    if (quote) {
      if (ch === quote) quote = null;
      else cur += ch;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
      has = true;
    } else if (/\s/.test(ch)) {
      if (has || cur) out.push(cur);
      cur = "";
      has = false;
    } else {
      cur += ch;
      has = true;
    }
  }
  if (has || cur) out.push(cur);
  return out;
}

export function nearest(xs: number[], x: number): number {
  if (!xs.length) return -1;
  let lo = 0;
  let hi = xs.length - 1;
  while (hi - lo > 1) {
    const mid = (lo + hi) >> 1;
    if (xs[mid] <= x) lo = mid;
    else hi = mid;
  }
  return Math.abs(xs[lo] - x) <= Math.abs(xs[hi] - x) ? lo : hi;
}

export function ticks(max: number, count = 5): number[] {
  if (!(max > 0)) return [0];
  const raw = max / count;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 2.5, 5, 10].map((k) => k * mag).find((s) => s >= raw) ?? raw;
  const out: number[] = [];
  for (let v = 0; v <= max + 1e-9; v += step) out.push(Math.round(v * 1e6) / 1e6);
  if (out[out.length - 1] < max) out.push(out[out.length - 1] + step);
  return out;
}

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

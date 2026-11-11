// Harbor UI: containers, their resources over time, their logs; run, stop and remove them.
import "./style.css";
import { lineChart } from "./chart";
import {
  type Container,
  type Host,
  type Image,
  type LogLine,
  escapeHtml,
  fmtBytes,
  fmtCpuMax,
  fmtDuration,
  memoryFraction,
  secondsBetween,
  splitArgs,
  statusKind,
  statusLabel,
} from "./util";

const $ = <T extends HTMLElement>(sel: string) => document.querySelector(sel) as T;

let selected: string | null = null;
let logNext = 0;
let logFor: string | null = null;
let follow = true;

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(path, { cache: "no-store", ...init });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error((body as { error?: string }).error ?? `${r.status}`);
  return body as T;
}

const mutate = (path: string, method: string, body?: unknown) =>
  api(path, { method, headers: { "Content-Type": "application/json", "X-Harbor": "1" }, body: body === undefined ? undefined : JSON.stringify(body) });

function badge(c: Container): string {
  return `<span class="badge ${statusKind(c)}"><i></i>${escapeHtml(statusLabel(c))}</span>`;
}

function renderList(cs: Container[]): void {
  const el = $("#list");
  if (!cs.length) {
    el.innerHTML = `<p class="muted pad">No containers yet. Run one with the form above, or <code>harbor run-image -d alpine sleep 600</code>.</p>`;
    return;
  }
  el.innerHTML = cs
    .map((c) => {
      const mem = c.stats ? fmtBytes(c.stats.memory_current) : "";
      return `<button class="row ${c.id === selected ? "on" : ""}" data-id="${c.id}">
        <div class="r1"><b>${escapeHtml(c.name)}</b>${badge(c)}</div>
        <div class="r2 muted"><span>${escapeHtml(c.image.replace("docker.io/library/", ""))}</span><span>${escapeHtml(c.ip ?? c.net)}</span><span>${mem}</span></div>
      </button>`;
    })
    .join("");
  el.querySelectorAll<HTMLButtonElement>(".row").forEach((b) =>
    b.addEventListener("click", () => {
      selected = b.dataset.id!;
      logNext = 0;
      logFor = null;
      void refresh();
    }),
  );
}

function tile(k: string, v: string, sub = ""): string {
  return `<div class="stat"><div class="k">${k}</div><div class="v">${v}</div>${sub ? `<div class="s muted">${sub}</div>` : ""}</div>`;
}

async function renderDetail(id: string): Promise<void> {
  const el = $("#detail");
  let c: Container;
  try {
    c = await api<Container>(`api/containers/${id}`);
  } catch {
    el.innerHTML = `<p class="muted pad">Container ${escapeHtml(id.slice(0, 12))} is gone.</p>`;
    selected = null;
    return;
  }
  const s = c.stats ?? c.final_stats;
  const frac = memoryFraction(s);
  const running = c.status === "running";
  const uptime = c.started ? secondsBetween(c.started, c.finished ?? new Date().toISOString()) : NaN;
  if (!el.querySelector(`[data-for="${id}"]`)) {
    el.innerHTML = `<div data-for="${id}">
      <div class="head"><h2></h2><div class="actions">
        <button id="stop" class="ghost">Stop</button><button id="rm" class="danger">Remove</button></div></div>
      <p class="cmd"></p>
      <div class="stats" id="tiles"></div>
      <div class="charts"><section class="panel"><h3>CPU (% of one core)</h3><div id="cpu"></div></section>
        <section class="panel"><h3>Memory</h3><div id="mem"></div></section></div>
      <section class="panel"><div class="loghead"><h3>Logs</h3><label class="muted"><input type="checkbox" id="follow" checked> follow</label></div><pre id="logs"></pre></section>
    </div>`;
    $("#stop").addEventListener("click", async () => {
      $("#stop").setAttribute("disabled", "");
      try {
        await mutate(`api/containers/${id}/stop`, "POST");
      } catch (e) {
        alert((e as Error).message);
      }
      void refresh();
    });
    $("#rm").addEventListener("click", async () => {
      if (!confirm(`Remove ${c.name}? Its files and logs are deleted.`)) return;
      try {
        await mutate(`api/containers/${id}?force=1`, "DELETE");
        selected = null;
        $("#detail").innerHTML = "";
      } catch (e) {
        alert((e as Error).message);
      }
      void refresh();
    });
    $<HTMLInputElement>("#follow").addEventListener("change", (e) => (follow = (e.target as HTMLInputElement).checked));
  }
  el.querySelector("h2")!.innerHTML = `${escapeHtml(c.name)} ${badge(c)}`;
  el.querySelector(".cmd")!.innerHTML = `<code>${escapeHtml(c.args.join(" "))}</code> <span class="muted">· ${escapeHtml(c.image)} · ${escapeHtml(c.id.slice(0, 12))}${c.error ? ` · <span class="err">${escapeHtml(c.error)}</span>` : ""}</span>`;
  $("#stop").toggleAttribute("disabled", !running);
  $("#tiles").innerHTML = [
    tile("uptime", fmtDuration(uptime), c.finished ? "finished" : ""),
    tile("memory", fmtBytes(s?.memory_current), `peak ${fmtBytes(s?.memory_peak)} · limit ${s && s.memory_max > 0 ? fmtBytes(s.memory_max) : "none"}` + (frac !== null ? `<span class="bar"><span style="width:${(frac * 100).toFixed(1)}%"></span></span>` : "")),
    tile("CPU limit", fmtCpuMax(s?.cpu_max), s ? `${(s.cpu_usage_usec / 1e6).toFixed(1)} s used, ${(s.cpu_throttled_usec / 1e6).toFixed(1)} s throttled` : ""),
    tile("processes", s ? String(s.pids_current) : "–", s && s.pids_max > 0 ? `limit ${s.pids_max}` : "no limit"),
    tile("OOM kills", s ? String(s.oom_kills) : "–"),
    tile("network", escapeHtml(c.ip ?? c.net), c.net),
  ].join("");
  const h = c.history ?? [];
  const t0 = h.length ? Date.parse(h[0].t) : 0;
  const xs = h.map((p) => (Date.parse(p.t) - t0) / 1000);
  lineChart($("#cpu"), [{ name: "CPU", color: "var(--series-1)", xs, ys: h.map((p) => p.cpu_percent) }], {
    xLabel: "seconds", yLabel: "%", height: 180, formatX: (x) => `${Math.round(x)} s`, formatY: (y) => `${Math.round(y)}`,
    yMax: c.limits.cpus ? c.limits.cpus * 100 : undefined, yMaxLabel: "limit",
  });
  lineChart($("#mem"), [{ name: "memory", color: "var(--series-2)", xs, ys: h.map((p) => p.memory / 1048576) }], {
    xLabel: "seconds", yLabel: "MiB", height: 180, formatX: (x) => `${Math.round(x)} s`, formatY: (y) => `${+y.toFixed(1)}`,
    yMax: c.limits.memory_bytes ? c.limits.memory_bytes / 1048576 : undefined, yMaxLabel: "limit",
  });
  if (!h.length) {
    for (const sel of ["#cpu", "#mem"]) $(sel).innerHTML = `<p class="muted">${running ? "Collecting samples…" : "No samples: the container is not running."}</p>`;
  }
  // Logs: only what is new.
  if (logFor !== id) {
    logFor = id;
    logNext = 0;
    $("#logs").innerHTML = "";
  }
  const lg = await api<{ next: number; lines: LogLine[] }>(`api/containers/${id}/logs?since=${logNext}`);
  if (lg.lines.length) {
    const pre = $("#logs");
    pre.insertAdjacentHTML("beforeend", lg.lines.map((l) => `<span class="${l.s}"><time>${l.t.slice(11, 19)}</time>${escapeHtml(l.l)}</span>\n`).join(""));
    if (follow) pre.scrollTop = pre.scrollHeight;
  }
  logNext = lg.next;
  if (!logNext && !$("#logs").textContent) $("#logs").innerHTML = `<span class="muted">No output (containers started with run-image -d, or from this page, keep logs).</span>`;
}

async function refresh(): Promise<void> {
  try {
    const cs = await api<Container[]>("api/containers");
    $("#status").textContent = `${cs.filter((c) => c.status === "running").length} running · ${cs.length} total`;
    renderList(cs);
    if (!selected && cs.length) selected = cs[0].id;
    if (selected) await renderDetail(selected);
    $("#offline").hidden = true;
  } catch {
    $("#offline").hidden = false;
  }
}

async function start(): Promise<void> {
  try {
    const h = await api<Host>("api/host");
    $("#host").textContent = `${h.hostname} · Linux ${h.kernel} · ${h.cpus} CPUs · ${fmtBytes(h.memory)} · bridge ${h.bridge} ${h.subnet}`;
  } catch {
    /* offline banner shows */
  }
  try {
    const imgs = await api<Image[]>("api/images");
    $("#images").innerHTML = imgs.map((i) => `<option value="${escapeHtml(i.name)}">`).join("");
  } catch {
    /* the field still accepts any name */
  }
  $<HTMLFormElement>("#run").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = new FormData(e.target as HTMLFormElement);
    const body = {
      image: String(f.get("image") || "").trim(),
      args: splitArgs(String(f.get("args") || "")),
      name: String(f.get("name") || "").trim(),
      memory: String(f.get("memory") || "").trim(),
      cpus: Number(f.get("cpus") || 0),
      pids: Number(f.get("pids") || 0),
      net: String(f.get("net") || "bridge"),
    };
    const btn = (e.target as HTMLFormElement).querySelector("button")!;
    btn.disabled = true;
    $("#runerr").textContent = "";
    try {
      const c = await mutate("api/containers", "POST", body);
      selected = (c as Container).id;
      logFor = null;
    } catch (err) {
      $("#runerr").textContent = (err as Error).message;
    }
    btn.disabled = false;
    void refresh();
  });
  await refresh();
  setInterval(() => void refresh(), 2000);
}

void start();

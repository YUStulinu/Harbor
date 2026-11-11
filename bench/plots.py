"""Plots for the README from results/bench.json.

    python3 bench/plots.py results/bench.json results/startup.png
"""
import json
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

# Categorical slots in a fixed order (validated reference palette): harbor, runc.
COLOR = {"harbor": "#2a78d6", "runc": "#eda100"}


def main():
    src, out = sys.argv[1], sys.argv[2]
    b = json.load(open(src))
    s = b["startup"]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 3.6), gridspec_kw={"width_ratios": [1.3, 1]})
    # Left: distribution of `run` times (empirical CDF).
    for rt in ("harbor", "runc"):
        xs = sorted(s[rt]["run"]["samples_ms"])
        ys = [(i + 1) / len(xs) for i in range(len(xs))]
        ax1.step(xs, ys, where="post", color=COLOR[rt], linewidth=2, label=f"{rt} (median {s[rt]['run']['median_ms']:.1f} ms)")
    ax1.set_xlabel("`run` of /bin/true: create + start + wait + delete (ms)")
    ax1.set_ylabel("fraction of runs")
    ax1.set_title(f"Start-up, {s['harbor']['run']['n']} runs each", fontsize=10)
    ax1.legend(frameon=False, fontsize=9, loc="lower right")
    # Right: median time per phase.
    phases = ["create", "start", "delete"]
    y = range(len(phases))
    h = 0.38
    for k, rt in enumerate(("harbor", "runc")):
        vals = [s[rt][p]["median_ms"] for p in phases]
        bars = ax2.barh([i + (k - 0.5) * h for i in y], vals, height=h - 0.04, color=COLOR[rt], label=rt)
        for bar, v in zip(bars, vals):
            ax2.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2, f"{v:.1f}", va="center", fontsize=8, color="#444")
    ax2.set_yticks(list(y), phases)
    ax2.invert_yaxis()
    ax2.set_xlabel("median time (ms)")
    ax2.set_title("Each command separately", fontsize=10)
    ax2.legend(frameon=False, fontsize=9, loc="lower right")
    for ax in (ax1, ax2):
        ax.grid(color="#e5e5e5", linewidth=0.6)
        ax.set_axisbelow(True)
        for sp in ("top", "right"):
            ax.spines[sp].set_visible(False)
    fig.tight_layout()
    fig.savefig(out, dpi=130)


if __name__ == "__main__":
    main()

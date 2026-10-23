#!/usr/bin/env python3
"""
plot_coverage.py — Publication-quality coverage-over-time plots from E2E campaign JSON.

Generates a figure showing:
  - X-axis: elapsed time
  - Y-axis: edge count
  - Flat pre-bypass region (AFL++ alone)
  - Vertical annotation at bypass time
  - Post-bypass exploration curve

Usage:
    python plot_coverage.py e2e_results/ics_crc32_*.json
    python plot_coverage.py e2e_results/ --all           # Plot all results
    python plot_coverage.py result.json -o fig.pdf       # Save to PDF
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import matplotlib
    matplotlib.use("Agg")  # Non-interactive backend
    import matplotlib.pyplot as plt
    from matplotlib.ticker import MaxNLocator
except ImportError:
    print("Error: matplotlib is required. Install with: pip install matplotlib")
    sys.exit(1)


# ── Colour palette ────────────────────────────────────────────────────
C_EDGE       = "#2563eb"   # Blue — edge curve
C_BASELINE   = "#94a3b8"   # Slate — baseline region
C_BYPASS     = "#dc2626"   # Red — bypass event line
C_INJECT     = "#16a34a"   # Green — injection marker
C_FILL_PRE   = "#dbeafe"   # Light blue — pre-bypass fill
C_FILL_POST  = "#bbf7d0"   # Light green — post-bypass fill
C_BG         = "#0f172a"   # Dark navy background
C_GRID       = "#1e293b"   # Grid lines
C_TEXT        = "#e2e8f0"   # Light text


def load_result(path: Path) -> dict:
    """Load a single E2E campaign result JSON."""
    with open(path) as f:
        return json.load(f)


def format_time(seconds: float) -> str:
    """Format seconds into human-readable duration."""
    h, r = divmod(int(seconds), 3600)
    m, s = divmod(r, 60)
    if h > 0:
        return f"{h}h{m:02d}m"
    elif m > 0:
        return f"{m}m{s:02d}s"
    return f"{s}s"


def plot_campaign(result: dict, output_path: str | None = None, show: bool = False):
    """Generate a publication-quality coverage-over-time plot."""
    timeline = result.get("timeline", [])
    if not timeline:
        print(f"Error: No timeline data in {result.get('target', 'unknown')}")
        return

    target_name = result.get("target", "Unknown")
    baseline = result.get("baseline_edges", 0)
    bypass_time = result.get("bypass_time_seconds")
    bypass_evidence = result.get("bypass_evidence", "")
    full_accept = result.get("full_accept", False)

    # Extract timeline data.
    times = [0] + [e["time_seconds"] for e in timeline]
    edges = [baseline] + [e["edges"] for e in timeline]

    # Find bypass time from timeline if not in result.
    if bypass_time is None and full_accept:
        for entry in timeline:
            if entry.get("payloads_injected", 0) > 0:
                bypass_time = entry["time_seconds"]
                break

    # ── Figure setup ──────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(12, 5))
    fig.patch.set_facecolor(C_BG)
    ax.set_facecolor(C_BG)

    # Grid.
    ax.grid(True, color=C_GRID, alpha=0.5, linewidth=0.5)
    ax.set_axisbelow(True)

    # ── Main edge curve ───────────────────────────────────────────
    ax.step(times, edges, where="post", color=C_EDGE, linewidth=2.5,
            label="Edges discovered", zorder=5)

    # Fill pre/post bypass regions.
    if bypass_time is not None:
        # Pre-bypass (stuck) region.
        ax.axvspan(0, bypass_time, alpha=0.15, color=C_BASELINE, zorder=1)
        # Post-bypass (exploration) region.
        ax.axvspan(bypass_time, times[-1], alpha=0.1, color=C_INJECT, zorder=1)

        # Bypass vertical line.
        ax.axvline(x=bypass_time, color=C_BYPASS, linestyle="--",
                   linewidth=2, alpha=0.9, zorder=6,
                   label=f"CRC-32 bypass ({format_time(bypass_time)})")

        # Annotation arrow.
        # Find edge count at bypass time.
        bypass_edges = baseline
        for entry in timeline:
            if entry["time_seconds"] <= bypass_time:
                bypass_edges = entry["edges"]
            else:
                break
        post_bypass_edges = edges[-1]

        ax.annotate(
            f"Agentic-AFL injects CRC fix\n"
            f"Z3 SAT → +{post_bypass_edges - bypass_edges} new edges",
            xy=(bypass_time, bypass_edges + (post_bypass_edges - bypass_edges) / 2),
            xytext=(bypass_time + (times[-1] - bypass_time) * 0.3,
                    bypass_edges + (post_bypass_edges - bypass_edges) * 0.7),
            arrowprops=dict(
                arrowstyle="->",
                color=C_BYPASS,
                lw=1.5,
                connectionstyle="arc3,rad=0.2",
            ),
            fontsize=10,
            color=C_TEXT,
            fontweight="bold",
            bbox=dict(boxstyle="round,pad=0.4", facecolor=C_BG,
                      edgecolor=C_BYPASS, alpha=0.9),
            zorder=10,
        )

    # Baseline annotation.
    ax.axhline(y=baseline, color=C_BASELINE, linestyle=":", linewidth=1,
               alpha=0.6, zorder=3)
    ax.text(times[-1] * 0.02, baseline + 0.5,
            f"AFL++ baseline: {baseline} edges",
            color=C_BASELINE, fontsize=9, fontstyle="italic", zorder=10)

    # ── Labels ────────────────────────────────────────────────────
    ax.set_xlabel("Elapsed Time", fontsize=12, color=C_TEXT, fontweight="bold")
    ax.set_ylabel("Edges Discovered", fontsize=12, color=C_TEXT, fontweight="bold")
    ax.set_title(
        f"Agentic-AFL Coverage: {target_name}",
        fontsize=14, color=C_TEXT, fontweight="bold", pad=15,
    )

    # Format x-axis as human-readable time.
    max_time = times[-1]
    if max_time > 7200:
        # Hours.
        tick_locs = list(range(0, int(max_time) + 1, 3600))
        tick_labels = [f"{t // 3600}h" for t in tick_locs]
    elif max_time > 600:
        # 5-minute intervals.
        tick_locs = list(range(0, int(max_time) + 1, 300))
        tick_labels = [f"{t // 60}m" for t in tick_locs]
    else:
        # Minutes.
        tick_locs = list(range(0, int(max_time) + 1, 60))
        tick_labels = [f"{t // 60}m" for t in tick_locs]
    ax.set_xticks(tick_locs)
    ax.set_xticklabels(tick_labels, color=C_TEXT)

    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    ax.tick_params(colors=C_TEXT)
    for spine in ax.spines.values():
        spine.set_color(C_GRID)

    # Legend.
    legend = ax.legend(
        loc="upper left", fontsize=10,
        facecolor=C_BG, edgecolor=C_GRID,
        labelcolor=C_TEXT,
    )

    # Stats box.
    final_edges = edges[-1]
    stats_text = (
        f"Final: {final_edges} edges  |  "
        f"Gain: +{final_edges - baseline} ({100 * (final_edges - baseline) / max(baseline, 1):.0f}%)  |  "
        f"Bypass: {'✓' if full_accept else '✗'}  |  "
        f"Duration: {format_time(max_time)}"
    )
    fig.text(
        0.5, 0.02, stats_text,
        ha="center", fontsize=10, color=C_TEXT, fontstyle="italic",
    )

    plt.tight_layout(rect=[0, 0.05, 1, 1])

    # ── Save / Show ───────────────────────────────────────────────
    if output_path:
        fig.savefig(output_path, dpi=200, bbox_inches="tight",
                    facecolor=C_BG, edgecolor="none")
        print(f"✓ Saved: {output_path}")
    elif show:
        plt.show()
    else:
        # Default: save as PNG next to the JSON.
        default_path = Path(result.get("_source_path", "coverage_plot.png"))
        default_png = default_path.with_suffix(".png")
        fig.savefig(default_png, dpi=200, bbox_inches="tight",
                    facecolor=C_BG, edgecolor="none")
        print(f"✓ Saved: {default_png}")

    plt.close(fig)
    return output_path or str(default_path.with_suffix(".png"))


def main():
    parser = argparse.ArgumentParser(
        description="Plot coverage-over-time from E2E campaign results.",
    )
    parser.add_argument(
        "input", nargs="+",
        help="Path to JSON result file(s) or directory.",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output image path (png, pdf, svg). Defaults to <input>.png.",
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Plot all JSON files in directory.",
    )
    parser.add_argument(
        "--show", action="store_true",
        help="Display plot interactively.",
    )
    args = parser.parse_args()

    # Collect input files.
    json_files: list[Path] = []
    for inp in args.input:
        p = Path(inp)
        if p.is_dir():
            json_files.extend(sorted(p.glob("*.json")))
        elif p.is_file():
            json_files.append(p)
        else:
            print(f"Warning: {inp} not found, skipping.")

    if not json_files:
        print("No JSON files found.")
        sys.exit(1)

    for jf in json_files:
        print(f"\n─── Plotting: {jf.name} ───")
        result = load_result(jf)
        result["_source_path"] = str(jf)
        out = args.output if len(json_files) == 1 else None
        plot_campaign(result, output_path=out, show=args.show)


if __name__ == "__main__":
    main()

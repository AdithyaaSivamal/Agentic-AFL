"""
tui.py — Rich-based Terminal UI for Agentic-AFL Campaign Monitoring.

Provides a live dashboard with panels for:
  - Fuzzer State:  AFL++ execution metrics (edges, execs/sec, corpus)
  - Agent State:   Live pipeline log (stall → ghidra → LLM → Z3 → inject)
  - Mutator State: Custom mutator deployment status
  - Coverage:      Sparkline showing edge discovery over time
  - Timeline:      Scrolling event log

Architecture:
    The TUI is a standalone class that consumes a shared state dict.
    The campaign runner updates the state dict, and the TUI renders
    it on a fixed refresh interval.

Usage:
    from tui import CampaignTUI

    tui = CampaignTUI(target_name="ICS CRC-32")
    with tui.live():
        while running:
            tui.update(fuzzer_state={...}, agent_state={...})
            await asyncio.sleep(1)
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text


# ── Braille chart renderer ────────────────────────────────────────────
#
# Each braille character is a 2×4 dot grid (2 columns, 4 rows).
# This gives 2× horizontal and 4× vertical resolution vs block chars.
#
#   Dot positions within a cell (col, row) → bit:
#     (0,0)=0x01  (1,0)=0x08
#     (0,1)=0x02  (1,1)=0x10
#     (0,2)=0x04  (1,2)=0x20
#     (0,3)=0x40  (1,3)=0x80
#
_BRAILLE_BASE = 0x2800
_BRAILLE_DOT_MAP = [
    [0x01, 0x08],  # row 0 (top)
    [0x02, 0x10],  # row 1
    [0x04, 0x20],  # row 2
    [0x40, 0x80],  # row 3 (bottom)
]


def _render_braille_chart(
    values: list[int | float],
    width: int = 60,
    height: int = 12,
    baseline: int | None = None,
    bypass_idx: int | None = None,
    duration_seconds: int = 0,
) -> str:
    """Render a list of values as a braille-dot line chart with axes.

    Returns a multi-line string with:
      - Y-axis labels (edge count)
      - Braille-dot data area
      - Baseline dotted reference line
      - Bypass vertical marker (│)
      - X-axis time labels
    """
    if not values:
        return "  no data yet"

    # ── Resample to fit width ─────────────────────────────────────
    if len(values) > width:
        step = len(values) / width
        sampled = [values[int(i * step)] for i in range(width)]
        # Remap bypass_idx to sampled space.
        if bypass_idx is not None:
            bypass_idx = int(bypass_idx / step)
    else:
        sampled = list(values)
        # Pad to width for consistent rendering.
        if len(sampled) < width:
            sampled.extend([sampled[-1]] * (width - len(sampled)))

    lo = 0
    hi = max(sampled) if sampled else 1
    if hi == lo:
        hi = lo + 1

    # Add 10% headroom.
    hi = int(hi * 1.1) + 1

    # ── Build braille grid ────────────────────────────────────────
    # Grid dimensions: width chars × height chars.
    # Each char covers 2 x-dots and 4 y-dots.
    dot_rows = height * 4
    grid = [[0] * width for _ in range(height)]

    for x, val in enumerate(sampled[:width]):
        # Map value to dot row (0 = bottom, dot_rows-1 = top).
        y_dot = int((val - lo) / (hi - lo) * (dot_rows - 1))
        y_dot = max(0, min(dot_rows - 1, y_dot))

        # Which character cell row and dot offset?
        # Row 0 is top of display, so invert.
        inverted = (dot_rows - 1) - y_dot
        cell_row = inverted // 4
        dot_offset = inverted % 4

        # Column is 1:1 with x (one dot per braille column 0).
        grid[cell_row][x] |= _BRAILLE_DOT_MAP[dot_offset][0]

    # ── Fill area under the line (optional, adds visual weight) ──
    for x, val in enumerate(sampled[:width]):
        y_dot = int((val - lo) / (hi - lo) * (dot_rows - 1))
        y_dot = max(0, min(dot_rows - 1, y_dot))
        inverted_line = (dot_rows - 1) - y_dot

        # Fill dots below the line.
        for fill_y in range(y_dot):
            inv = (dot_rows - 1) - fill_y
            cr = inv // 4
            do = inv % 4
            grid[cr][x] |= _BRAILLE_DOT_MAP[do][0]

    # ── Draw baseline dots ────────────────────────────────────────
    if baseline is not None and baseline > lo:
        bl_dot = int((baseline - lo) / (hi - lo) * (dot_rows - 1))
        bl_dot = max(0, min(dot_rows - 1, bl_dot))
        bl_inv = (dot_rows - 1) - bl_dot
        bl_cr = bl_inv // 4
        bl_do = bl_inv % 4
        for x in range(0, width, 3):  # Dotted pattern.
            grid[bl_cr][x] |= _BRAILLE_DOT_MAP[bl_do][1]  # Column 1.

    # ── Render to string ──────────────────────────────────────────
    y_label_width = len(str(hi)) + 1
    lines = []

    for r in range(height):
        # Y-axis label (only top, middle, bottom).
        if r == 0:
            y_label = f"{hi:>{y_label_width}}"
        elif r == height - 1:
            y_label = f"{lo:>{y_label_width}}"
        elif r == height // 2:
            mid_val = (hi + lo) // 2
            y_label = f"{mid_val:>{y_label_width}}"
        else:
            y_label = " " * y_label_width

        # Build braille row.
        row_chars = []
        for x in range(width):
            ch = chr(_BRAILLE_BASE + grid[r][x]) if grid[r][x] else " "

            # Bypass marker: override with │ at bypass column.
            if bypass_idx is not None and x == bypass_idx:
                ch = "│"

            row_chars.append(ch)

        row_str = "".join(row_chars)
        lines.append(f"  {y_label} │{row_str}│")

    # ── X-axis ────────────────────────────────────────────────────
    axis_line = " " * (y_label_width + 3) + "└" + "─" * width + "┘"
    lines.append(axis_line)

    # Time labels.
    if duration_seconds > 0 and len(values) > 1:
        elapsed_now = duration_seconds * len(values) / max(len(values), width)
        mid_time = elapsed_now / 2
        label_pad = " " * (y_label_width + 4)
        labels = f"{label_pad}0m"
        mid_pos = width // 2 - len(f"{_format_duration(mid_time)}")
        end_pos = width - len(f"{_format_duration(elapsed_now)}")
        time_labels = [" "] * (width + 1)
        # Start.
        for i, c in enumerate("0m"):
            if i < len(time_labels):
                time_labels[i] = c
        # Mid.
        mid_str = _format_duration(mid_time)
        for i, c in enumerate(mid_str):
            pos = width // 2 - len(mid_str) // 2 + i
            if 0 <= pos < len(time_labels):
                time_labels[pos] = c
        # End.
        end_str = _format_duration(elapsed_now)
        for i, c in enumerate(end_str):
            pos = width - len(end_str) + i
            if 0 <= pos < len(time_labels):
                time_labels[pos] = c

        lines.append(label_pad + "".join(time_labels))

    return "\n".join(lines)


def _format_duration(seconds: float) -> str:
    """Format seconds into human-readable duration."""
    h, r = divmod(int(seconds), 3600)
    m, s = divmod(r, 60)
    if h > 0:
        return f"{h}h{m:02d}m{s:02d}s"
    elif m > 0:
        return f"{m}m{s:02d}s"
    return f"{s}s"


def _format_number(n: int) -> str:
    """Format large numbers with K/M suffixes."""
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)


# ── Color palette ─────────────────────────────────────────────────────
C_ACCENT    = "bright_cyan"
C_SUCCESS   = "bright_green"
C_WARNING   = "bright_yellow"
C_ERROR     = "bright_red"
C_DIM       = "dim"
C_HEADER    = "bold bright_white"
C_EDGE      = "bold bright_cyan"
C_SOLVE     = "bold bright_green"
C_STALL     = "bold bright_yellow"


# ── Pipeline stages ───────────────────────────────────────────────────
PIPELINE_STAGES = [
    ("detect",   "Stall Detection"),
    ("ghidra",   "Ghidra P-Code"),
    ("profile",  "Constraint Profile"),
    ("carm",     "CARM Retrieval"),
    ("probe",    "Offset Probe"),
    ("llm",      "LLM Translation"),
    ("z3",       "Z3 SAT Solve"),
    ("inject",   "Payload Injection"),
    ("diverse",  "Diverse Injection"),
    ("mutator",  "Custom Mutator"),
]


@dataclass
class TUIState:
    """Shared state between the campaign runner and the TUI."""
    # Target info.
    target_name: str = ""
    target_desc: str = ""
    duration_seconds: int = 0
    start_time: float = 0.0

    # Fuzzer metrics.
    edges: int = 0
    baseline_edges: int = 0
    execs: int = 0
    execs_per_sec: float = 0.0
    corpus_count: int = 0
    cycles_done: int = 0
    pending_favs: int = 0

    # Agent metrics.
    stalls_detected: int = 0
    stalls_solved: int = 0
    payloads_injected: int = 0
    llm_calls: int = 0
    react_turns: int = 0

    # Pipeline stage states: "idle", "active", "done", "error"
    pipeline: dict[str, str] = field(default_factory=lambda: {
        k: "idle" for k, _ in PIPELINE_STAGES
    })

    # Mutator state.
    mutator_deployed: bool = False
    mutator_name: str = ""

    # Bypass state.
    bypass_detected: bool = False
    bypass_time: float = 0.0
    bypass_evidence: str = ""

    # Coverage timeline (for sparkline).
    edge_history: list[int] = field(default_factory=list)

    # Event log (scrolling).
    events: deque[tuple[float, str, str]] = field(
        default_factory=lambda: deque(maxlen=50)
    )

    def add_event(self, msg: str, level: str = "info") -> None:
        """Add an event to the scrolling log."""
        self.events.append((time.monotonic() - self.start_time, msg, level))

    def set_pipeline(self, stage: str, status: str) -> None:
        """Update a pipeline stage status."""
        if stage in self.pipeline:
            self.pipeline[stage] = status

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.start_time if self.start_time else 0.0

    @property
    def progress_pct(self) -> float:
        if self.duration_seconds <= 0:
            return 0.0
        return min(100.0, self.elapsed / self.duration_seconds * 100)

    @property
    def edge_gain(self) -> int:
        return self.edges - self.baseline_edges

    @property
    def edge_gain_pct(self) -> float:
        if self.baseline_edges <= 0:
            return 0.0
        return self.edge_gain / self.baseline_edges * 100


class CampaignTUI:
    """Rich-based TUI for monitoring Agentic-AFL campaigns."""

    def __init__(self, state: TUIState | None = None) -> None:
        self.state = state or TUIState()
        self.console = Console()
        self._live: Live | None = None
        self._custom_panels: dict[str, Any] = {}

    def add_panel(self, name: str, renderable: Any) -> None:
        """Register a custom panel to display in the layout."""
        self._custom_panels[name] = renderable

    def remove_panel(self, name: str) -> None:
        """Remove a custom panel."""
        self._custom_panels.pop(name, None)

    def live(self) -> Live:
        """Return a Live context manager for the TUI.

        Uses the terminal's alternate screen buffer (screen=True) so the
        dashboard renders in-place like vim/htop. When the context exits,
        the original terminal state is restored automatically.

        The Live object auto-refreshes at 4fps. Callers just update
        self.state — no need to call refresh() manually.
        """
        self._live = Live(
            self._render(),
            console=self.console,
            refresh_per_second=4,
            screen=True,
            vertical_overflow="ellipsis",
        )
        return self._live

    def refresh(self) -> None:
        """Force a TUI refresh (called by the campaign runner on state change)."""
        if self._live:
            self._live.update(self._render())

    # ── Render methods ────────────────────────────────────────────

    def _render(self) -> Layout:
        """Build the complete TUI layout."""
        layout = Layout()

        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="panels"),
            Layout(name="chart"),
            Layout(name="footer", size=3),
        )

        # Header: target name + progress.
        layout["header"].update(self._render_header())

        # Upper body: side-by-side panels.
        layout["panels"].split_row(
            Layout(name="left", ratio=1),
            Layout(name="right", ratio=1),
        )

        # Left column: fuzzer stats.
        layout["left"].update(self._render_fuzzer())

        # Right column: agent + mutator + events.
        right_parts = [
            Layout(name="agent", ratio=2),
            Layout(name="mutator", size=5),
            Layout(name="events", ratio=2),
        ]

        # Add custom panels.
        for name in self._custom_panels:
            right_parts.append(Layout(name=f"custom_{name}", size=5))

        layout["right"].split_column(*right_parts)

        # Fill right panels.
        layout["agent"].update(self._render_agent())
        layout["mutator"].update(self._render_mutator())
        layout["events"].update(self._render_events())

        for name, renderable in self._custom_panels.items():
            layout[f"custom_{name}"].update(
                Panel(renderable, title=f"[{C_HEADER}]{name}", border_style=C_DIM)
            )

        # Chart: full-width coverage graph.
        layout["chart"].update(self._render_coverage())

        # Footer: progress bar.
        layout["footer"].update(self._render_footer())

        return layout

    def _render_header(self) -> Panel:
        """Render the header with target name and status."""
        s = self.state
        status = "[bold green]● RUNNING[/]"
        if s.bypass_detected:
            status = "[bold cyan]● BYPASS ACTIVE[/]"
        if s.mutator_deployed:
            status = "[bold magenta]● MUTATOR DEPLOYED[/]"
        if s.progress_pct >= 100:
            status = "[bold white]● COMPLETE[/]"

        title = Text.from_markup(
            f"  [bold bright_white]⚡ AGENTIC-AFL[/]  │  "
            f"[{C_ACCENT}]{s.target_name}[/]  │  "
            f"{status}  │  "
            f"[{C_DIM}]{_format_duration(s.elapsed)} / {_format_duration(s.duration_seconds)}[/]"
        )
        return Panel(title, style="bright_blue", height=3)

    def _render_fuzzer(self) -> Panel:
        """Render the AFL++ fuzzer state panel."""
        s = self.state
        table = Table(show_header=False, show_edge=False, pad_edge=False,
                      expand=True, box=None)
        table.add_column("label", style=C_DIM, ratio=1)
        table.add_column("value", style=C_ACCENT, ratio=1)
        table.add_column("label2", style=C_DIM, ratio=1)
        table.add_column("value2", style=C_ACCENT, ratio=1)

        edge_style = C_SOLVE if s.edge_gain > 0 else C_ACCENT
        gain_text = f"+{s.edge_gain}" if s.edge_gain > 0 else "—"
        gain_pct = f"({s.edge_gain_pct:+.0f}%)" if s.edge_gain > 0 else ""

        table.add_row(
            "edges found", f"[{edge_style}]{s.edges}[/]",
            "edge gain", f"[{edge_style}]{gain_text} {gain_pct}[/]",
        )
        table.add_row(
            "execs total", _format_number(s.execs),
            "execs/sec", f"{s.execs_per_sec:,.0f}",
        )
        table.add_row(
            "corpus size", str(s.corpus_count),
            "cycles done", str(s.cycles_done),
        )
        table.add_row(
            "baseline", str(s.baseline_edges),
            "pending favs", str(s.pending_favs),
        )

        return Panel(
            table,
            title=f"[{C_HEADER}]🔍 Fuzzer State[/]",
            border_style="bright_blue",
        )

    def _render_agent(self) -> Panel:
        """Render the agent pipeline state panel."""
        s = self.state
        lines = []

        for key, label in PIPELINE_STAGES:
            status = s.pipeline.get(key, "idle")
            if status == "idle":
                icon = f"[{C_DIM}]○[/]"
                style = C_DIM
            elif status == "active":
                icon = f"[{C_WARNING}]◉[/]"
                style = C_WARNING
            elif status == "done":
                icon = f"[{C_SUCCESS}]●[/]"
                style = C_SUCCESS
            elif status == "error":
                icon = f"[{C_ERROR}]✗[/]"
                style = C_ERROR
            else:
                icon = f"[{C_DIM}]?[/]"
                style = C_DIM

            lines.append(f"  {icon} [{style}]{label:<20s}[/]  [{C_DIM}]{status}[/]")

        # Agent stats row.
        stats = (
            f"\n  [{C_DIM}]stalls: {s.stalls_detected}  │  "
            f"solved: {s.stalls_solved}  │  "
            f"LLM calls: {s.llm_calls}  │  "
            f"turns: {s.react_turns}[/]"
        )
        lines.append(stats)

        return Panel(
            Text.from_markup("\n".join(lines)),
            title=f"[{C_HEADER}]🧠 Agent Pipeline[/]",
            border_style="bright_yellow",
        )

    def _render_mutator(self) -> Panel:
        """Render the custom mutator state panel."""
        s = self.state
        if s.mutator_deployed:
            content = Text.from_markup(
                f"  [{C_SUCCESS}]● DEPLOYED[/]  [{C_DIM}]{s.mutator_name}[/]\n"
                f"  [{C_DIM}]All mutations produce valid CRC-32 frames[/]"
            )
            border = "bright_green"
        elif s.bypass_detected:
            content = Text.from_markup(
                f"  [{C_WARNING}]◉ PENDING[/]  [{C_DIM}]deploying after bypass...[/]"
            )
            border = "bright_yellow"
        else:
            content = Text.from_markup(
                f"  [{C_DIM}]○ STANDBY[/]  [{C_DIM}]waiting for agent to solve constraint[/]"
            )
            border = C_DIM

        return Panel(
            content,
            title=f"[{C_HEADER}]⚙ Mutator State[/]",
            border_style=border,
            height=5,
        )

    def _render_coverage(self) -> Panel:
        """Render a live braille-dot coverage chart."""
        s = self.state
        history = s.edge_history or [0]

        # Compute bypass sample index for the marker.
        bypass_idx = None
        if s.bypass_detected and s.bypass_time > 0 and s.duration_seconds > 0:
            # Bypass position relative to samples collected.
            total_samples = len(history)
            if total_samples > 1:
                bypass_idx = int(s.bypass_time / s.elapsed * total_samples)
                bypass_idx = max(0, min(total_samples - 1, bypass_idx))

        chart_str = _render_braille_chart(
            values=history,
            width=70,
            height=10,
            baseline=s.baseline_edges if s.baseline_edges > 0 else None,
            bypass_idx=bypass_idx,
            duration_seconds=int(s.elapsed) if s.elapsed > 0 else s.duration_seconds,
        )

        # Build status line.
        current = history[-1] if history else 0
        gain = current - s.baseline_edges if s.baseline_edges > 0 else 0
        pct = gain / s.baseline_edges * 100 if s.baseline_edges > 0 else 0
        status_parts = [
            f"[{C_ACCENT}]edges: {current}[/]",
            f"[{C_DIM}]baseline: {s.baseline_edges}[/]",
        ]
        if gain > 0:
            status_parts.append(f"[{C_SOLVE}]+{gain} ({pct:+.0f}%)[/]")
        if s.bypass_detected:
            status_parts.append(
                f"[{C_SOLVE}]bypass @ {_format_duration(s.bypass_time)}[/]"
            )
        status_line = f"  {'  │  '.join(status_parts)}"

        content = Text.from_markup(
            f"[{C_ACCENT}]{chart_str}[/]\n{status_line}"
        )

        return Panel(
            content,
            title=f"[{C_HEADER}]📈 Coverage Over Time — Edges Discovered[/]",
            border_style="bright_cyan",
        )

    def _render_events(self) -> Panel:
        """Render the scrolling event log."""
        s = self.state
        lines = []
        # Show last N events that fit.
        for elapsed, msg, level in list(s.events)[-12:]:
            ts = _format_duration(elapsed)
            if level == "success":
                style = C_SUCCESS
                icon = "✓"
            elif level == "warning":
                style = C_WARNING
                icon = "!"
            elif level == "error":
                style = C_ERROR
                icon = "✗"
            else:
                style = C_DIM
                icon = "·"

            lines.append(f"  [{C_DIM}]{ts:>8s}[/]  [{style}]{icon} {msg}[/]")

        content = "\n".join(lines) if lines else f"  [{C_DIM}]waiting for events...[/]"
        return Panel(
            Text.from_markup(content),
            title=f"[{C_HEADER}]📋 Events[/]",
            border_style=C_DIM,
        )

    def _render_footer(self) -> Panel:
        """Render the progress bar footer."""
        s = self.state
        pct = s.progress_pct
        filled = int(pct / 100 * 50)
        bar = f"[bright_cyan]{'█' * filled}[/][dim]{'░' * (50 - filled)}[/]"

        inject_text = ""
        if s.payloads_injected > 0:
            inject_text = f"  │  [{C_SOLVE}]injected: {s.payloads_injected}[/]"

        bypass_text = ""
        if s.bypass_detected:
            bypass_text = f"  │  [{C_SOLVE}]✅ BYPASS @ {_format_duration(s.bypass_time)}[/]"

        content = Text.from_markup(
            f"  {bar}  [{C_DIM}]{pct:.1f}%[/]"
            f"{inject_text}{bypass_text}"
        )
        return Panel(content, style="bright_blue", height=3)

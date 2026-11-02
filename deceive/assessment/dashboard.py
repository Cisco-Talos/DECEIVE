"""Standalone SVG history; no model calls or plotting dependencies."""
from __future__ import annotations

from html import escape
from pathlib import Path
from statistics import median
import time
import textwrap

from deceive.assessment.workspace import load_json

COLORS = {"protocol": "#7c3aed", "product": "#0284c7", "attacker": "#ea580c", "consistency": "#059669"}


def render(run: Path) -> Path:
    state = load_json(run / "state.json")
    loops = state["loops"][-20:]
    handles = sorted({h for loop in loops for h in loop["targets"]})
    notes = []
    if loops:
        latest = loops[-1]
        history_findings = {f["key"]: f for loop in state["loops"] for f in loop["findings"]}
        visible_findings = [f for f in history_findings.values()
                            if f["verification"]["status"] not in {"resolved", "false_positive"}]
        for handle, target in latest["targets"].items():
            notes.append(f'{handle}: {len(target["scores"])}/{len(state["spec"]["roles"])} reviewers; '
                         f'{target["telemetry"].get("observations", 0)} captured actions; '
                         f'correctness {target["correctness"]["status"]}; telemetry {target["telemetry"]["status"]}')
        for finding in visible_findings[:12]:
            notes.extend(textwrap.wrap(f'{finding["severity"]} {finding["target"]} '
                f'[{finding["verification"]["status"]}] {finding["description"]}', width=142)[:3])
        if len(visible_findings) > 12:
            notes.append("Additional findings and evidence: see structured scores.json.")
        for loop in loops:
            for progress in loop.get("progress", []):
                notes.extend(textwrap.wrap(f'Loop {loop["loop"]} fix/progress: {progress}', width=142))
    height = 1195 + len(handles) * 42 + len(notes) * 19
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="{height}" viewBox="0 0 1280 {height}">',
             '<rect width="100%" height="100%" fill="#f8fafc"/>']

    def text(x, y, value, size=14, color="#334155", weight="normal"):
        parts.append(f'<text x="{x}" y="{y}" font-family="Arial,sans-serif" font-size="{size}" '
                     f'fill="{color}" font-weight="{weight}">{escape(str(value))}</text>')

    def line(x1, y1, x2, y2, color="#cbd5e1", width=1, dash=""):
        parts.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" '
                     f'stroke-width="{width}" stroke-dasharray="{dash}"/>')

    def rect(x, y, w, h, fill):
        parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="4" fill="{fill}"/>')

    def values(loop):
        return [v for v in loop["targets"].values() if not v.get("calibration")]

    def score(loop):
        items = values(loop)
        return min(v["median"] for v in items) if items and all(v["complete"] for v in items) else None

    text(42, 47, "DECEIVE · active assessment history", 29, "#0f172a", "bold")
    status = state.get("stop_reason") or state["phase"]
    text(42, 80, f'{state["run_id"]} · {status} · {len(state["loops"])} completed loops', 17)
    text(42, 108, "Realism: higher is better. Panel median is not reviewer confidence or measured fidelity.")
    text(42, 135, "Native-agent cost: unavailable unless reported · Calibration controls scored separately")
    if state.get("final_candidate_fresh") is False:
        text(42, 157, "Working tree changed since assessment; historical scores do not qualify the current tree.", 13, "#b45309")
    threshold = state["spec"]["policy"]["minimum_realism"]
    x0, y0, width, plot_height = 70, 220, 1120, 260
    text(42, 180, "1 · Worst target per reviewer, panel median and five-loop rolling median", 19, "#0f172a", "bold")
    for value in range(0, 101, 20):
        yy = y0 + plot_height * (1 - value / 100)
        line(x0, yy, x0 + width, yy)
        text(43, yy + 4, value, 11)
    line(x0, y0 + plot_height * (1 - threshold / 100), x0 + width,
         y0 + plot_height * (1 - threshold / 100), "#dc2626", 2, "6 4")
    text(x0 + 4, y0 + plot_height * (1 - threshold / 100) - 7, f"Target {threshold:g}", 12, "#dc2626")

    def x(i):
        return x0 + width * i / max(1, len(loops) - 1)

    def y(value):
        return y0 + plot_height * (1 - value / 100)

    series = {}
    for role in state["spec"]["roles"]:
        series[role] = [min(v["scores"][role] for v in values(loop))
                        if values(loop) and all(role in v["scores"] for v in values(loop)) else None
                        for loop in loops]
    medians = [score(loop) for loop in loops]
    rolling = []
    for index, value in enumerate(medians):
        recent = medians[max(0, index - 4):index + 1]
        rolling.append(median(recent) if value is not None and all(v is not None for v in recent) else None)
    series.update(median=medians, rolling5=rolling)
    for index, (name, data) in enumerate(series.items()):
        color = COLORS.get(name, "#111827" if name == "median" else "#64748b")
        text(70 + index * 180, 525, name, 12, color)
        previous = None
        for i, value in enumerate(data):
            if value is None:
                previous = None
                continue
            if previous is not None:
                line(x(previous), y(data[previous]), x(i), y(value), color, 2.5)
            parts.append(f'<circle cx="{x(i)}" cy="{y(value)}" r="4" fill="{color}"/>')
            previous = i
    for index, loop in enumerate(loops):
        text(x(index), 503, loop["loop"], 11)
    if not loops:
        text(240, 350, "N/A — no completed candidate assessment", 23)
    text(42, 565, "2 · Reviewer disagreement (band height = maximum target spread)", 17)
    for index, loop in enumerate(loops):
        items = values(loop)
        if items and all(v.get("spread") is not None for v in items):
            line(x(index), 585, x(index), 585 + max(v["spread"] for v in items) * .4, "#94a3b8", 8)
    text(42, 652, "3 · Loop delta in worst-target median", 17)
    line(70, 710, 1190, 710)
    for index in range(1, len(loops)):
        if medians[index] is None or medians[index - 1] is None:
            continue
        delta = medians[index] - medians[index - 1]
        h = min(abs(delta) * 3, 48)
        rect(x(index) - 8, 710 - h if delta >= 0 else 710, 16, max(h, 1),
             "#16a34a" if delta >= 0 else "#dc2626")
        text(x(index) - 9, 774, f"{delta:+g}", 11)
    text(42, 822, "4 · Target heatmap · correctness / telemetry / verified open P0–P1", 18, "#0f172a", "bold")
    cell_width = min(78, 880 / max(1, len(loops)))
    for row, handle in enumerate(handles):
        yy = 855 + row * 42
        latest = next(loop["targets"][handle] for loop in reversed(loops) if handle in loop["targets"])
        ids = ",".join(p["id"] for p in latest.get("profiles", []))
        text(42, yy + 22, handle, 12)
        text(140, yy + 22, ids[:26] + (" [control]" if latest.get("calibration") else ""), 11)
        for col, loop in enumerate(loops):
            v = loop["targets"].get(handle)
            value = v["median"] if v and v["complete"] else None
            color = "#e2e8f0" if value is None else "#bbf7d0" if v["qualified"] else "#fed7aa"
            xx = 330 + col * cell_width
            rect(xx, yy, cell_width - 3, 34, color)
            text(xx + 4, yy + 15, "N/A" if value is None else f"{value:g}", 11)
            if v:
                critical = sum(f["target"] == handle and f["severity"] in {"P0", "P1"} and
                    f["verification"]["status"] == "verified" for f in loop["findings"])
                text(xx + 4, yy + 29, f'{v["correctness"]["status"][0]}/{v["telemetry"]["status"][0]}/{critical}', 9)
    footer = 905 + len(handles) * 42
    text(42, footer, "5 · Candidate / image / client revisions", 18, "#0f172a", "bold")
    for offset, loop in enumerate(loops[-4:]):
        text(42, footer + 28 + offset * 23,
             f'Loop {loop["loop"]}: {loop["candidate_id"][:12]} · image {loop.get("image", "N/A")[:22]} '
             f'· client {loop.get("client_id", "N/A")[:12]} · progress {len(loop.get("progress", []))}', 12)
    if state.get("current") and state["current"]["number"] > len(state["loops"]):
        text(42, footer + 130, "Current attempt incomplete: its scores are not inherited from earlier candidates.", 13, "#b45309")
    if state.get("teardown_errors"):
        text(42, footer + 153, "Teardown incomplete — inspect state.json", 13, "#dc2626")
    text(42, footer + 192, "6 · Latest coverage, findings and recorded repairs", 18, "#0f172a", "bold")
    for index, note in enumerate(notes):
        text(42, footer + 220 + index * 19, note, 12)
    parts.append("</svg>")
    output = run / "dashboard.svg"
    output.write_text("\n".join(parts))
    history = run / "dashboards"
    history.mkdir(exist_ok=True)
    (history / f'{len(state["loops"]):04d}-{time.time_ns()}.svg').write_text(output.read_text())
    (run / "latest-history.svg").write_text(output.read_text())
    return output

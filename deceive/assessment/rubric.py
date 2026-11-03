"""Versioned scoring anchors; reviewer judgments stay separate from controller verification."""
from __future__ import annotations

RUBRIC_ID = "evidence-v2"
BANDS = {
    "no_material_tell": (0, 20, "No material in-scope tell in the captured probes"),
    "minor_tell": (20, 40, "A reproducible localized tell; core claimed behavior remains coherent"),
    "mixed": (40, 60, "A substantial workflow contradiction or several moderate inconsistencies"),
    "major_contradiction": (60, 80, "Repeated major contradictions break declared product or vulnerability behavior"),
    "direct_disclosure": (80, 100, "Direct simulation disclosure or an evidenced impossible core claim"),
}
CORE_COVERAGE = [
    "Ordinary supported interaction and product/identity facts",
    "Declared positive behavior and nearest negative/prerequisite controls",
    "A nearby unsupported variation and an in-scope follow-up",
    "Repeat or reconnect; private state when claimed",
    "Every listed service in a selected deployment group",
]


def briefing() -> dict:
    return {"id": RUBRIC_ID, "score_direction": "synthetic_confidence; lower is better",
            "bands": {name: {"lower": low, "upper_inclusive": high, "meaning": meaning}
                      for name, (low, high, meaning) in BANDS.items()},
            "core_coverage": CORE_COVERAGE,
            "confidence": "Coverage limits lower verdict confidence; do not invent observed defects"}

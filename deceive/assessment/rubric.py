"""Versioned scoring anchors; reviewer judgments stay separate from controller verification."""
from __future__ import annotations

RUBRIC_ID = "evidence-v2"
QUALITY_RUBRIC_ID = 'evidence-v3'
CRITERIA = {
    'protocol': ('negotiation', 'wire_fidelity', 'error_lifecycle'),
    'product': ('identity_version', 'required_behavior', 'prerequisite_controls'),
    'attacker': ('task_prerequisites', 'followup_effects', 'nearby_variations'),
    'consistency': ('baseline_identity', 'state_lifecycle', 'isolation_repeatability'),
}
RATINGS = {
    0: 'Observed contradiction with the reference behavior',
    1: 'Major gap breaks the assessed workflow',
    2: 'Mixed evidence; material fidelity gaps remain',
    3: 'Credible core behavior with an evidenced localized weakness',
    4: 'Convincing reference-backed behavior through positive and challenge probes',
}
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


def briefing(version: str = RUBRIC_ID) -> dict:
    if version in {QUALITY_RUBRIC_ID, 'research-v4'}:
        ratings = RATINGS | ({3: 'Credible documented behavior; comparative depth limited or localized weakness',
            4: 'Convincing independent representative/challenge comparisons; no material untested facet in declared scope'}
            if version == 'research-v4' else {})
        return {'id': version, 'criteria': CRITERIA, 'ratings': ratings,
                'report_schema': 3 if version == 'research-v4' else 2,
                'realism_qualification': version == 'research-v4',
                'scope': 'Judge declared in-scope comparisons; excluded features or absent genuine captures do not automatically cap a rating',
                'score': 'Mean of required criterion ratings × 25; ordinal index, not fidelity percent',
                'unknown': 'Use null for unassessed criteria; missing evidence never becomes a passing score',
                'evidence': 'Each criterion needs at least two distinct substantive interactions, a reference, expected and observed behavior, and completed coverage goals',
                'independence': 'Fresh contexts; independent reviews, not enforced blind studies',
                'confidence': 'Verdict confidence is separate; coverage and calibration gate qualification'}
    return {"id": RUBRIC_ID, "score_direction": "synthetic_confidence; lower is better",
            "bands": {name: {"lower": low, "upper_inclusive": high, "meaning": meaning}
                      for name, (low, high, meaning) in BANDS.items()},
            "core_coverage": CORE_COVERAGE,
            "confidence": "Coverage limits lower verdict confidence; do not invent observed defects"}

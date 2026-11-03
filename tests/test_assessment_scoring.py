from deceive.assessment.models import Policy, Review
from deceive.assessment.scoring import exit_reason, target_score
import pytest


def row(score=90, candidate="same", complete=True, progress=None):
    return {"candidate_id": candidate, "comparison_id": "cohort", "complete": complete,
            "qualified": complete and score >= 85, "progress": progress or [],
            "targets": {"target-1": {"median": score, "qualified": complete and score >= 85}},
            "plateau_confirmed": True}


def test_median_direction_and_missing_reviews():
    scores = target_score([{"role": r, "synthetic_confidence": v}
                          for r, v in zip(["protocol", "product", "attacker", "consistency"],
                                          [0, 10, 20, 80])],
                         ["protocol", "product", "attacker", "consistency"])
    assert scores["median"] == 85 and scores["spread"] == 80 and scores["complete"]
    assert not target_score([], ["protocol"])["complete"]


def test_confirmation_and_fixed_twenty_loops():
    assert exit_reason([row()], Policy()) is None
    assert exit_reason([row(), row()], Policy()) == "quality_success"
    assert exit_reason([row(), row(candidate="changed")], Policy()) is None
    policy = Policy(mode="fixed")
    for count in range(1, 20):
        assert exit_reason([row()] * count, policy) is None
    assert exit_reason([row()] * 20, policy) == "count_complete"


def test_plateau_requires_complete_comparable_diagnosed_rounds():
    rows = [row(v) for v in [70, 71, 71, 72]]
    assert exit_reason(rows, Policy()) == "plateau"
    rows[-1]["plateau_confirmed"] = False
    assert exit_reason(rows, Policy()) is None
    rows[-1]["plateau_confirmed"] = True
    rows[-1]["progress"] = ["Verified shared identity defect repaired"]
    assert exit_reason(rows, Policy()) is None
    rows[-1]["progress"] = []
    rows[-1]["complete"] = False
    assert exit_reason(rows, Policy()) is None
    assert exit_reason([row(v) for v in [70, 72, 73, 74]], Policy()) is None


def test_review_requires_evidence_and_distinct_confidences():
    valid = {"candidate_id": "c", "role": "product", "target": "target-1",
             "synthetic_confidence": 10, "verdict_confidence": 65, "summary": "Observed"}
    assert Review.model_validate(valid).verdict_confidence == 65
    with pytest.raises(ValueError):
        Review.model_validate(valid | {"findings": [{"id": "f", "severity": "P1",
            "category": "identity_or_state", "description": "Mismatch", "expected": "Same", "evidence": []}]})


def test_evidence_rubric_band_must_match_score_and_findings():
    report = {"candidate_id": "c", "role": "product", "target": "target-1",
              "synthetic_confidence": 10, "verdict_confidence": 70, "summary": "Scoped behavior held",
              "score_basis": {"band": "no_material_tell", "observations": ["Positive and negative controls matched claims"],
                              "evidence": ["interaction-1"], "coverage_limits": "Only declared application scope tested"}}
    assert Review.model_validate(report).score_basis.band == "no_material_tell"
    with pytest.raises(ValueError, match="band"):
        Review.model_validate(report | {"synthetic_confidence": 90})
    with pytest.raises(ValueError, match="finding"):
        Review.model_validate(report | {"synthetic_confidence": 30, "score_basis":
            report["score_basis"] | {"band": "minor_tell"}})


def test_repeatability_only_compares_complete_unchanged_candidates():
    from deceive.assessment.scoring import repeatability

    rows = [row(82), row(84), row(99, candidate="changed"), row(1, complete=False)]
    for item in rows:
        target = item["targets"]["target-1"]
        target["scores"] = {"product": target["median"]}
    result = repeatability(rows)
    unchanged = next(c for c in result["candidates"] if c["candidate_id"] == "same")
    target = unchanged["targets"]["target-1"]
    assert target["assessments"] == 2
    assert target["panel_median_range"] == [82, 84]
    assert target["reviewer_ranges"]["product"] == [82, 84]

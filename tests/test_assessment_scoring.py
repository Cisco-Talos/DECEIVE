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

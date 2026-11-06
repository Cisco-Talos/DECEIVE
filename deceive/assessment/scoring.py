from __future__ import annotations

from statistics import median

from deceive.assessment.models import Policy


def target_score(reviews: list[dict], required: list[str]) -> dict:
    scores = {r["role"]: 100 - r["synthetic_confidence"] for r in reviews}
    complete = all(role in scores for role in required)
    values = [scores[role] for role in required if role in scores]
    return {"scores": scores, "complete": complete,
            "median": median(values) if values else None,
            "spread": max(values) - min(values) if values else None}


def repeatability(loops: list[dict]) -> dict:
    groups = {}
    for loop in loops:
        key = loop["candidate_id"], loop["comparison_id"]
        group = groups.setdefault(key, {})
        for handle, target in loop["targets"].items():
            if target.get("complete", loop["complete"]) and target.get("median") is not None:
                group.setdefault(handle, []).append(target)
    candidates = []
    for (candidate, comparison), groups_by_target in groups.items():
        targets = {}
        for handle, values in groups_by_target.items():
            medians = [v["median"] for v in values]
            roles = {role for v in values for role in v.get("scores", {})}
            ranges = {role: [min(scores), max(scores)] for role in sorted(roles)
                      if (scores := [v["scores"][role] for v in values if role in v.get("scores", {})])}
            targets[handle] = {"assessments": len(values), "panel_median_range": [min(medians), max(medians)],
                               "reviewer_ranges": ranges,
                               "calibration": values[-1].get("calibration", False)}
        candidates.append({"candidate_id": candidate, "comparison_id": comparison, "targets": targets})
    return {"schema_version": 1, "candidates": candidates,
            "interpretation": "Descriptive repeatability on identical candidates/rubrics; not a confidence interval or repair claim"}


def quality_confirmed(loops: list[dict], policy: Policy) -> bool:
    same = loops[-policy.confirmations:]
    return (len(same) == policy.confirmations and all(l["qualified"] and
            l.get('assessment_status') == 'assessed' and l.get('review_rubric') == 'research-v4' for l in same)
            and len({l["candidate_id"] for l in same}) == 1
            and len({l["comparison_id"] for l in same}) == 1)


def exit_reason(loops: list[dict], policy: Policy) -> str | None:
    if not loops:
        return None
    last = loops[-1]
    if policy.mode == "fixed":
        return "count_complete" if len(loops) >= policy.max_loops else None
    if quality_confirmed(loops, policy):
        return "quality_success"
    window = loops[-(policy.plateau_cycles + 1):]
    if (len(window) == policy.plateau_cycles + 1 and all(l["complete"] and
        l.get('assessment_status') == 'assessed' and l.get('review_rubric') == 'research-v4' for l in window)
        and len({l["comparison_id"] for l in window}) == 1
        and not any(l.get("progress") for l in window[1:])):
        unmet = [t for t, v in last["targets"].items() if not v["qualified"]]
        gains = []
        for target in unmet:
            previous = [l["targets"][target]["median"] for l in loops[:-policy.plateau_cycles]
                        if target in l["targets"] and l["targets"][target]["median"] is not None]
            current = [l["targets"][target]["median"] for l in window[1:]
                       if l["targets"][target]["median"] is not None]
            if not previous or len(current) != policy.plateau_cycles:
                break
            gains.append(max(current + previous) - max(previous))
        else:
            if unmet and len(gains) == len(unmet) and max(gains) < policy.minimum_gain:
                # The controller must explicitly confirm variance/diagnosis was checked.
                if last.get("plateau_confirmed"):
                    return "plateau"
    return "loop_limit" if len(loops) >= policy.max_loops else None

# Repair and verification

Classify findings as verified regression, sibling defect, new family, unproven,
or out of scope. Before coding, name the owner, invariant, entry paths, consumers
and sibling risks. Possible owners: protocol boundary, runtime identity/session
state, base/virtual fixtures, composition dispatch, vulnerability behavior,
generative prompt/provider, telemetry, or evaluator.

Fix the highest layer owning the demonstrated fact. Avoid exact-command/hostname
patches that merely satisfy a reviewer sample. A profile-specific fix is appropriate
when the declared behavior belongs there; label temporary containment explicitly.
Write and run a failing regression, then fix it and verify a sibling path. Preserve
the human-agreed acceptance fingerprints; additional regression tests do not permit
weakening an existing criterion. Engine gaps prompt diagnosis and authorized
engine work, not arbitrary plausible text or a real shell/filesystem operation.

For `end-loop --decisions FILE`, record:

```json
{
  "schema_version": 1,
  "findings": {
    "product/target-01/finding_id": {
      "status": "verified",
      "rationale": "Reproduced and compared with the primary source",
      "evidence": ["interaction-ID"]
    }
  },
  "progress": [],
  "reconciliations": {}
}
```

Statuses are `verified`, `false_positive`, `unproven`, `resolved`. Resolved requires
post-fix evidence from the current candidate, not intent to fix it. Use `progress`
only for substantive demonstrated defect/coverage progress. Reconciliations map a
target handle to the evidence-based explanation of material reviewer disagreement.
Keep original ratings and reports intact. Untriaged P0/P1 findings prevent success.

Do not stop just because a gate failed. Fix/retry/review the resulting candidate.
When all required targets meet the quality predicate, until mode can finish after
the confirmation count. A plateau requires a baseline plus three comparable,
complete cycles without the configured gain or substantive progress. Diagnose
variance, regressions and deeper newly exposed defects before `--confirm-plateau`.
For a real blocker preserve attempts/evidence and the exact input or external
change needed; use `finish --reason blocked --note ...` to render incomplete results.

---
name: deceive-assess
description: Run active DECEIVE assessment and repair loops with independent native reviewers, frozen workflow coverage, known-defect calibration controls and dashboards. Use for realism assessments, repeated improvement loops or auditing assessment validity; separate from profile authoring and public deployment.
---

# Assess and improve DECEIVE deceptions

This skill owns assessment orchestration and repair. The `deceive assess` CLI
manages Docker, evidence, checkpoints, gates and charts; it does not launch coding
agents itself. Use `uv run deceive` inside a checkout, or the installed command.
Read [assessment operations](../../docs/assessment.md) for lifecycle commands.
The authoring skill calls this workflow by default after a newly created deception
passes its frozen deterministic acceptance suite. Run the new profile individually
and add only agreed deployment groups. Use the default until-criteria policy unless
the user specified a fixed count or different limits. Return the final dashboard,
per-loop scores, repairs and unresolved limitations to the authoring workflow.

Translate the user's request into individual profile targets and explicitly
selected deployment groups. “All profiles” means individual targets, never an
unrequested merged deployment. Preserve instance IDs, provider configuration,
fidelity limits and approved acceptance criteria. Repairs preserve existing
edits on the current branch, without automatic commits, pushes, resets or PRs.

## Freeze an assessment that can disprove success

First read [research-backed review](references/research.md). Research missing
product/platform evidence and freeze source-linked realism criteria separately
from functional contracts. Use `review_rubric: research-v4` for new runs. Preserve
earlier v3 reports as historical conformance evidence, not validated realism.
Read [coverage and calibration](references/coverage.md)
before preparing the spec. Start with [the working example](../../examples/assessment-research.yaml)
when assessing fictional Workbench; adapt goals and independent references for
other products/protocols. Do not reuse its Linux commands for Windows or SSH.

Define meaningful positive, negative, variation, repeat and relevant state/isolation
workflows, with independent expected behavior and observations that demonstrate
effects. Cover all role criteria, services and advertised protocol versions.
Challenge claimed platform/encoding/argument boundaries, not just the example
commands. For large catalogs, create manageable protocol-family batches; do not
drop coverage to fit a budget. Agree changed acceptance expectations with the
human; review coverage supplements frozen vulnerability acceptance, never weakens it.
For SSH targets, actively explore the surrounding host or device session as well
as the vulnerability trigger: login text, prompt/terminal behavior, ordinary
discovery, navigation, errors, state and follow-up actions. Use the claimed device
or operating system's own interface; do not substitute a universal Linux command
checklist. Treat a model-free deterministic subset and a configured-model session
as distinct assessment conditions when both are claimed.

Supply undisclosed known-defect controls for each assessed protocol family,
including a major contradiction and a subtler plausible defect. Every required
reviewer must detect both through captured evidence and lower the affected
criterion rating. Controls are assessed but excluded from quality medians and
automatic repair. Do not reveal their labels, differences or expected findings
to reviewers. An all-perfect panel that misses controls is unvalidated.

Use assessment schema 2 for new runs. Freeze goals, controls, references, rubric and resource limits with `prepare`.
Changes require a new run/comparison, not editing run state. Legacy v1–v3 reports
remain historical evidence; they cannot establish research-v4 quality. Preserve originals.

## Run the loop

1. Check branch/status and preserve edits. Prepare without committing. Choose
   fixed count (`mode: fixed`) or until mode; defaults are 20 maximum loops,
   median index ≥85, every criterion ≥75, verdict confidence ≥60 and two passing
   assessments of an unchanged candidate. Fixed count overrides early exits.
2. `begin-loop` stages complete candidates, launches local Docker targets and
   runs deterministic acceptance. Diagnose unreachable targets and relaunch;
   reachable behavior can still receive useful review after a gate fails.
   Before dispatching reviewers, confirm the broker and every target are healthy.
   After an interruption, `resume` restores the broker but does not guarantee that
   Docker or its containers survived. Verify the existing owned containers and
   bindings too; never infer listener readiness from broker readiness alone.
3. Launch **four native subagents in parallel**, one per role, in fresh contexts
   (`fork_turns: none`, inherit the host model). Read [reviewer briefings](references/reviewers.md).
   Give each its role, public begin-loop/status JSON, research dossier, public
   baseline contents, probe interface, run path and separate report destination.
   Allow independent primary-source consultation; contracts alone are not a realism oracle.
   Withhold source, private specs/assertions/logs, suspected defects, thresholds,
   prior scores and prior conclusions. These are independent reviews, not an
   enforced blind study: native agents retain host tools.
4. Each reviewer first preflights its planned baseline with `assess plan`; read
   [the plan procedure](references/coverage.md#preflight-before-spending-actions).
   Fix plan errors before spending actions and reserve capacity for independent
   follow-up, cleanup and citation repair. Reviewers actively probe through neutral handles within the configured
   action/time limits, then produce schema-3 comparative reports. Use null for
   unassessed criteria. Never prefill a passing score, select band midpoints or
   introduce artificial score variation. Legitimately identical ratings are
   allowed; comparative reasoning, coverage and sensitivity determine their value.
   Audit rating generation and evidence provenance, not just control detection.
   Probe helpers must stop on CLI errors and nested observation errors rather
   than spend the remaining budget on unavailable services. Diagnose availability
   first. Preserve consumed actions/deadlines; expired or exhausted reviews remain
   incomplete and receive fresh budgets only in a new loop. Do not join session
   sequences across a broker/container restart. Follow public baseline forms and
   declared capture semantics; explicit normalization can recognize path aliases.
   Keep independent case/encoding challenges separate when a baseline uses exact links.
5. `record-review` validates ownership/candidate/schema and public goal/reference
   links before closing the loop. Return input errors to the reviewer for a
   report amendment while active; retain originals and never edit its judgments.
   Inspect findings and
   captured sequences against references. Preserve original ratings/severity;
   controller verification is separate. Reconcile substantial disagreement
   with evidence. A low-confidence or incomplete review needs better evidence,
   not an invented defect or an optimistic rating.
6. Wait for all reviewers to finish their self-audits, import the reports, and run
   `assess audit`. Repair remaining coverage/citation/provenance errors while active.
   Schema 2 refuses premature closure. A genuine diagnosed partial close requires
   an explicit incomplete reason/category and cannot qualify.
   `end-loop` records correctness, telemetry, coverage, criterion ratings and
   control sensitivity separately. Missing coverage or failed controls means
   **insufficiently assessed**, with chart gaps, even when provisional ratings
   are high. Diagnose missing workflows or reviewer/tool failures, adjust the
   briefing/tooling at its owning layer and reassess; never tell reviewers which
   answers would pass a control. If the assessment definition must change,
   prepare a new run and retain the earlier evidence.
7. For genuine target findings, read [repair guidance](references/repair.md), add
   a failing regression, repair the owner and check sibling behavior. Keep
   frozen criteria. Repairs invalidate affected earlier reviews. During an
   active attempt, collect/stop reviewers and use `begin-loop --retry`; do not
   mix old scores with a new candidate. Never “fix” intentional control defects.
8. Continue until configured count/quality/plateau/budget/cancellation or a
   genuine diagnosed blocker. A plateau needs three complete comparable cycles
   without material gain/progress, after checking variance; it means needs work.
   Incomplete coverage or failed calibration cannot establish a plateau.
9. Always `finish`, including partial runs. Stop owned targets, export evidence
   and render the SVG. Compatible containers remain stopped by default;
   `cleanup --remove` deletes only owned resources. Link/embed the dashboard and
   report qualified/needs-work/insufficiently-assessed distinctly, with coverage,
   sensitivity, technical gates, repairs and remaining limits. Native-agent
   usage/cost is unavailable unless the host supplies it; do not invent it.

Ordinary pytest uses fake reports, not live agents. Live target providers require
the user's explicit selected configuration; fake providers cannot prove model
realism. Publication and deployment exposure remain separately authorized.

For multi-loop requests, report each target's loop scores, unassessed gaps and key
fixes at the end of every loop. Keep research/comparison revisions visible in the
dashboard; incomparable methods must not appear as an improvement trend.

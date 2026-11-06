# Frozen coverage and calibration

For new realism runs use [research-v4](research.md) and the
[research example](../../../examples/assessment-research.yaml). The coverage and
control mechanics below apply unchanged; the older v3 example remains a
compatibility fixture. Independent comparison evidence is required in addition
to these mechanical gates.

Read [the specification example](../../../examples/assessment-quality.yaml) and
its [public baseline](../../../docs/assessment-workbench-baseline.md) as a controller,
not as a reviewer. The profile fixtures deliberately contain different defects.
Never disclose those definitions or their labels to reviewers.

Size the assessment deployment for acceptance traffic plus all reviewers. Cookie
clients retain server state until runtime expiry even after a transport closes.
The example explicitly uses `limits.sessions: 512` through ordinary deployment
YAML for the bounded panel; production defaults are unchanged. Do not silently
raise limits of a user-selected production deployment.

Each target declares `references` (public identifiers) and `coverage`. A coverage
goal has a stable `id`, reviewer `role`, one of that role's `criterion` names,
`kind`, public `description` and private ordered `steps`.
Public `required_methods` lists HTTP operation methods without exposing result
assertions. Set the method explicitly in HTTP probe parameters. Constrain method
selection in new specs so a negative POST or a body-free HEAD is not mistaken for
a positive GET representation check. Correcting a frozen definition requires a
new comparison; preserve earlier results rather than reinterpret their selectors.

The kinds are baseline,
positive, negative, variation and repeat for every role; attacker also needs
state, consistency also needs state and isolation. Cover all three role criteria.
Use a meaningful negative/prerequisite challenge for each claimed positive
surface; the validator checks structure, the controller owns test adequacy.

Steps have `select` rules proving which operation was exercised, and `expect`
rules testing its observed result. Keep these separate: a wrong result proves
coverage and a defect, rather than making a failed target appear untested.
Sequences require distinct observations. Order is preserved by default; use
`ordered: false` for independent baseline checks. State/isolation workflows
always preserve operation order. State/repeat/isolation have at
least two steps. `every_service` defaults true; `every_version` can require the
whole sequence on each version. Basic successful negotiation on every advertised
version is always required. `same_session` and `different_sessions` are optional;
protocols without sessions can express state in other observed fields.
An isolation recipient must not already have performed the matching setup for
the tested captured resource. Two clients writing their own copies of the same
filename do not demonstrate leakage; use an untouched recipient to test that.

Rules read dotted observation fields such as `action.parameters.command`,
`facts.outputs.0.exit_status`, `version`, `body_text`, `body_json.id` or
`request_json.command`. They support exact typed `equals`, string `contains`,
bounded-time regex `pattern`, named `capture`, `equals_capture` and
`not_equals_capture`, plus `exists` for field presence/absence. Absence differs
from an explicit null. Check `request_json` exists before testing a missing JSON
field so malformed JSON is not mistaken for an absent property. Match semantic
input structure rather than one byte spelling of a request. A regex capture uses its first group, otherwise the field
value. Captures are per sequence; no expressions, code, recursive templates or
host access. Use captures to link a unique input/filename to its follow-up effect.
Bind a public description to independent source expectations, not to whatever
the current implementation happens to emit. Client errors and cleanup cannot
satisfy a goal. Search is bounded; excessively broad goals need tighter selectors.

`control.defects` declares private known defects: `id`, `difficulty` (`major` or
`subtle`), `description`, allowable finding `categories`, and `observed` rules
matching the actual contradiction. Controls use ordinary profiles/deployments
and claims. They are protocol agnostic; prepare equivalent controls for SSH or
new drivers rather than pretending an HTTP control validates those reviewers.

For every required role/protocol family, qualification requires a captured
finding matching a major and a subtle defect, with a lowered evidence-linked
criterion: major ≤2 and severity P0–P2; subtle ≤3 and severity P0–P3. HTTP/HTTPS
share a family. Controls are omitted from quality medians and repair selection.
This checks sensitivity to known defects, not whether reviewers are universally
accurate. Rotate controls and challenge cases when reusing an assessment method;
freeze a new spec/comparison and retain previous evidence.

Ratings are an ordinal 0–4 index, summarized as mean ×25 per reviewer and median
across every required reviewer. Default floors: criterion 75, median 85, verdict
confidence 60. Missing evidence, ratings, references, reviewers or sensitivity
checks produce `insufficiently_assessed`, not a guessed number. Inspect retained
`provisional_scores` diagnostically; they never establish a qualifying panel.
Only independently complete role reviews enter `valid_scores` and reviewer lines;
a missing reviewer still withholds the panel median.
No finite selector set proves realism completeness. Independently inspect whether
goals challenge the claimed product/platform, expand coverage when gaps emerge,
and distinguish fictional contract fidelity from real-product authenticity.

## Preflight before spending actions

Use assessment schema 2 for new runs. Each reviewer writes a `ProbePlan` JSON
with `schema_version: 1`, current `candidate_id`, its `role`, neutral `target`,
`reserve_actions`, and an ordered `actions` list. Run
`deceive assess plan --run RUN --file PLAN.json` before any target probe; fix
selection/order/session/version/budget errors until it returns `ready: true`.
This checks intended input workflows, without expected answers or actual realism.
It does not consume the target's deadline or action allowance. Execute the checked
baseline before optional independent challenges, leaving the declared reserve
for follow-up, cleanup and evidence repairs. A valid planned operation can still
produce a real failure; report that observation rather than removing the probe.

For Windows path captures, new definitions can explicitly use
`normalize: windows_path` on the capture and linked comparison. Accept documented
quoted/space-path spellings in the selector too. This links lexical aliases of
one virtual path without relaxing exact response/encoding checks. Existing frozen
definitions retain exact matching unless they explicitly opted in.

The controller imports all reports and runs `deceive assess audit --run RUN`
before closure. Schema 2 refuses premature `end-loop`; repair citation and coverage
errors while active. A diagnosed partial closure requires an explicit reason and
category, remains unqualified, and preserves consumed budgets. Native reviewers
must finish self-audits and announce completion before controller closure; later
corroborating amendments are supplementary, never silent historical score edits.

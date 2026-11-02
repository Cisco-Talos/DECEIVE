# Agentic quality assessment for DECEIVE — behavioral contract

Status: implemented by the repository `deceive-assess` skill and development-only
`deceive assess` helpers. See [usage](assessment.md) and [verification](verification.md).
Native agents perform independent reviews, not technically enforced blind studies.
This adapts the EvidenceForge `eforge-assess` workflow to interactive
deceptions as a repeated assess/diagnose/fix/verify loop, with active interaction
from the first implementation. It does not run EvidenceForge generation, install
a global skill or add a production runtime service. The skill coordinates native
reviewers; the deterministic CLI does not launch coding agents autonomously.

## Keep three results separate

| Result | What establishes it | Gate |
| --- | --- | --- |
| Correctness | Frozen automated acceptance, real protocol negotiation, state/isolation/composition and boundary tests | Every required criterion passes; failures cannot be averaged away |
| Network-visible realism | Independent reviewers actively interact with the service and assess captured evidence | Required for a convincing success; agreed observable criteria and calibrated reviewer targets must pass |
| Telemetry correctness | Internal JSONL audit checks request/session attribution, base64 content, authentication and one summary per session | Deterministic contract gate; not a blind authenticity score |

An internal log explicitly naming DECEIVE is not a fair blind realism artifact.
Neither a successful ordinary HTTP/2 response nor a high realism score proves
that an HTTP/2 vulnerability works. Passing capability probes establishes only
the engine behaviors actually exercised. Unsupported CVE effects remain absent.

## Loop controls and success

The normal mode is repeated assessment and improvement, not a one-time report.
A single assessment remains an explicit review-only mode. Example natural-language
requests to the repository assessment skill (not literal CLI commands):

- "Run 20 loops on these profiles." Run 20 cohort cycles unless a user-selected
  safety/cost/time bound, explicit cancellation or genuine blocker prevents it.
  Do not stop early merely because the scores look good.
- "Run until every selected profile passes correctness and realism for three
  consecutive rounds, with no verified P0/P1 findings; maximum 20 loops." Stop
  only when the stated predicate or explicit upper bound is reached.
- "Run 20 loops on all installed profiles, including these deployment groups."
  Freeze that inventory at run start; do not quietly change the cohort mid-run.

Interpret success predicates against the same current candidate revision. A
technically working but unconvincing deception does not qualify, nor does a
convincing response with incorrect exploit semantics. Require all selected
profiles and required deployment groups to satisfy the agreed criteria; an
average across profiles cannot conceal one broken deception. Record the final
stop reason as criteria met, requested count reached, explicit resource bound,
confirmed plateau, user cancellation, or a documented blocker. Reaching a count/budget is completion
of the requested run, not proof of quality success.
For consecutive-round criteria, a fix affecting the target resets its passing
streak unless the user explicitly chooses a rolling criterion across revisions.

### Proposed default until-criteria policy

Expose a **realism score** where higher is better:
`realism = 100 - synthetic_confidence`. Keep the original synthetic-confidence
score in the record, and keep verdict confidence separate. A realism target of
85 therefore corresponds to synthetic-confidence at most 15; it is not 85%
measured fidelity or 85% confidence in a reviewer's verdict.

Proposed initial defaults, configurable and subject to calibration:

- **Quality success:** all required correctness/telemetry checks pass, no verified
  unresolved P0/P1 findings, and the median required-reviewer realism score is at
  least 85 for every selected profile and required deployment group, in two
  consecutive assessments of the same unchanged candidate. Every required reviewer
  and coverage item must be present. A strong cohort median cannot hide a weak
  profile. Material reviewer disagreement triggers evidence reconciliation or a
  confirming review before declaring success.
- **Plateau:** after a baseline plus three complete assess/repair cycles, no
  still-unsatisfied target has gained at least 3 points in its best panel-median
  realism score, and no substantive verified defect resolution or required
  coverage progress explains a flat score. Compare against the best score before
  that three-cycle window, with a stable cohort, rubric and reviewer configuration.
  Missing reviews do not count as flat results. Diagnose reviewer variance,
  regressions and newly exposed issues before confirming a plateau; a targeted
  repeat or A/B review can resolve ambiguous movement.
- **Other exits:** the requested count, explicitly selected time/cost/request
  bounds, user cancellation or a genuine documented blocker still apply.

The 3-point gain is a starting definition of material improvement, not a claim
of statistical significance. A confirmed plateau ends with status **needs work /
plateau**, remaining findings and a recommended next approach, never a quality
pass. Successful defect repairs count as progress even if reviewers now notice
deeper issues and the score does not rise. The user can explicitly request
continuation past a plateau or different thresholds. These defaults apply when
no stopping rule is supplied; "run exactly 20 loops" overrides early quality/
plateau exits unless the user also requests them. Resource bounds remain explicit.

## Proposed workflow for each loop

1. Snapshot the candidate, target cohort, accepted criteria and budgets. Freeze
   profile/base/dependency, suite, engine and reference revisions for that snapshot.
2. Validate and launch isolated test instances; run deterministic tests and the
   telemetry audit. A failed gate becomes a diagnostic finding and repair task,
   not an instruction to end the run or skip realism across the cohort.
3. Actively review every reachable in-scope target using protocol-appropriate
   clients. Reviewers choose normal, trigger, negative, exploratory, follow-up and
   reconnect interactions. Test intended compositions and record actual negotiated
   protocols, message bytes/events and outcomes. A known technical failure does
   not suppress other useful realism investigation.
4. Give independent reviewers neutral target handles, claimed product/version,
   agreed scope and appropriate primary reference evidence. Keep source, profile
   YAML, prompts, expected outputs, internal telemetry, previous scores and author
   conclusions outside their access. Save all interactions as replayable evidence.
5. Verify findings with reproducible probes and primary references. Classify
   unproven claims and out-of-scope requirements explicitly. Prioritize technical
   defects and realism failures together by severity, impact and owning layer.
6. Diagnose and repair the highest-leverage root causes. Add a failing regression
   before each fix and cover a sibling path. Missing capabilities are investigated
   and implemented within the authorized engine scope, not automatically treated
   as terminal. Escalate between profile, engine and assessment tooling as needed.
7. Rebuild/relaunch the repaired candidate, rerun regression checks and actively
   re-probe the affected behavior. Check the full required coverage before claiming
   success. A repaired but unreviewed candidate remains unassessed for realism;
   do not combine its passing tests with another revision's realism scores.
8. Save the loop's candidate revisions, repairs, findings, coverage, correctness,
   realism, telemetry results and costs. Evaluate the requested exit predicate;
   otherwise use unresolved findings and fresh variations to plan the next loop.

If startup fails, diagnose configuration, dependencies, protocol support and the
test harness; fix and relaunch. There is no endpoint to probe until that succeeds,
so mark active review pending rather than pretending it ran. Continue reviewing
unaffected targets where useful. A failure, missing capability or one flat score
alone is not a blocker: investigate alternate explanations and owners first.
Stop for a blocker only after recording attempted diagnoses/repairs, reproducible
evidence and the specific missing permission, information or external dependency
needed to proceed. Do not repeat an unchanged failing approach indefinitely.

The author cannot weaken frozen assertions during refinement. Criteria changes
require renewed agreement for the changed scope, preserving earlier results.
No assessment step publishes, activates a public listener or executes a payload
on a real host. SSH probes send simulated command strings through the honeypot.

## Docker assessment lifecycle

Use Docker-managed, localhost-exposed test instances as the default assessment
backend. The controller validates the resolved runtime configuration, chooses a
candidate image by content digest, stages profile/configuration snapshots, creates
or reuses the appropriate containers, starts them, verifies readiness, performs
the active assessment, exports evidence and stops them. Container creation and
image building are separate operations; neither is necessary for every loop.

Publish each required TCP/UDP port explicitly on host loopback, for example
`127.0.0.1`, with isolated per-assessment networks and no host networking/direct
routing. Inside the container, listeners normally bind its network interfaces
so Docker can forward host traffic. Discover actual port mappings for clients;
HTTP/3 needs its UDP mapping as well as any TCP mapping. Verify real negotiation,
not a TCP-only readiness response. Docker documents both
[loopback publication](https://docs.docker.com/engine/network/port-publishing/)
and [starting retained stopped containers](https://docs.docker.com/reference/cli/docker/container/start/).

Loopback publication controls inbound host exposure, not outbound access or
access from peers on the same container network. Keep networks dedicated to the
selected targets/probers. Deterministic targets need no external connectivity;
model-backed assessments need explicitly configured provider access. Keep target
and provider connectivity policies separate, and keep the Docker socket available
only to the trusted controller, not to deceptions or probing reviewers.

Mount candidate YAML, prompts and virtual assets read-only, with complete base
dependencies and stable relative paths. Preserve immutable copies of each
candidate even when updating a reusable staging directory while its container
is stopped. Select the mounted snapshot explicitly rather than accidentally
testing an old bundled profile. Give each runtime its own writable data volume;
never share the existing exclusive runtime data directory across processes.
See Docker's [read-only bind-mount support](https://docs.docker.com/engine/storage/bind-mounts/).

| Change | Container action | Image action |
| --- | --- | --- |
| No candidate change / another independent review | Reset sessions and restart or reuse the isolated target as planned | Reuse the same image digest |
| Mounted profile YAML, prompt, rules or virtual content | Stop, refresh the staged snapshot, restart; retain compatible container | No rebuild |
| Startup YAML with unchanged bindings/mount layout | Stop, refresh YAML, restart | No rebuild |
| Published ports, mount layout, startup command or isolation layout | Recreate the affected container | Reuse image if engine content is unchanged |
| DECEIVE protocol adapter, runtime, installed extension, dependency lock or base image | Build the new candidate, replace affected containers and revalidate siblings | Rebuild affected image |
| Assessment client/driver/controller code only | Reset/re-probe affected targets; recreate reviewer containers if necessary | Rebuild client image only if client code is containerized; do not rebuild an unchanged honeypot image |
| Bundled profile asset changed without a mount override | Recreate with the updated artifact, or explicitly stage/mount the candidate | Rebuild if testing the bundled artifact |

"Protocol driver" must identify whether the change belongs to DECEIVE's server
adapter or the assessment client's driver. Keep them independently fingerprinted.
An image cache key includes actual candidate content, lockfile/build inputs and
installed extensions, not just Git HEAD when the worktree has uncommitted fixes.

By default, stop and retain harness-owned containers between assessment runs
when compatible, as well as reusable image layers. A requested cleanup mode
removes only the harness-owned containers and explicitly selected scratch volumes
after evidence is exported. Do not run a global prune or delete unrelated data.
Changing image contents requires a new image/container, not an in-place edit of
a running assessment target.

Retention is an optimization, not persistence of attacker activity. Reset
in-memory sessions/private mutations between independent tests; restart the
process where necessary. Retain stable keys/baseline identity when the test calls
for continuity, and use fresh isolated data where it calls for a clean instance.
Segment logs by run so historical container output cannot contaminate findings.
Record image/container IDs, profile snapshots, mappings, networks and data-reset
policy with every loop. Do not modify a candidate while reviewers are probing it.

Stop targets in cleanup paths on normal completion, plateau, cancellation and
exceptions; capture evidence first where possible. Keep a manifest/ownership
labels for safe recovery after an interrupted controller. A retained container
should be stopped at the end of the assessment process unless the operator
explicitly requests leaving a local debugging instance running. Generate the
final dashboard even when assessment or teardown is incomplete, showing that
status rather than claiming a clean run.

## Review panel

Four complementary roles are useful; the same model can fill them in separate,
context-isolated runs. Reports are evidence, not votes that override hard gates.

| Reviewer | Primary question |
| --- | --- |
| Protocol/tool specialist | Do real clients negotiate and interact as claimed? Are headers, bytes, stream/connection outcomes and errors plausible within the declared fidelity? |
| Product/CVE specialist | Do prerequisites, affected/protected behavior and observable effects agree with independent primary evidence? |
| Attacker-workflow reviewer | Do unexpected but in-scope probes and follow-up interactions remain convincing, including negative cases and escalation/state boundaries? |
| System/application consistency reviewer | Do identity, virtual content, authentication/application state and reconnect behavior agree across the observed sessions and selected composition? |

The telemetry auditor is a separate, unblinded role. Its purpose is to ensure the
honeypot records what happened well enough for an operator to investigate it:
attempted authentication, observed interactions and responses, endpoints,
profile attribution, byte/base64 integrity, protocol-appropriate correlation,
session lifecycle, response origin and summary ownership. It compares actual
client observations with internal records and flags missing, invented or
misattributed activity. For example, a convincing simulated privilege change is
still operationally defective if its command/response is logged under another
profile or silently omitted. Authentication logging retains its existing contract.

Make routine schema/correlation checks deterministic. An optional agent auditor
can assess semantic coverage and investigative usefulness. It is not the source
of the external realism score: DECEIVE's own logs name the platform and expose
implementation metadata. Its result must not enter the blind realism average.
Reviewers should not demand cross-service shared state, exact TLS/packet
fingerprints or real execution when those capabilities are explicitly excluded.
They should report observable scope limitations separately from contradictions.

## Protocol-independent orchestration

The loop selects work by profile identity and declared capabilities, not by an
HTTP-specific test structure. Each protocol supplies an assessment driver that
can launch/connect, discover negotiation/capabilities, exchange valid and relevant
malformed interactions, observe outcomes, reconnect/reset where meaningful, and
clean up. Drivers return a common evidence envelope containing target/profile,
interaction identifiers, actual protocol/version, bytes/events, timestamps and
outcomes, with protocol-specific details retained alongside it.

SSH uses channels/commands, authentication, banners and prompts; HTTP uses requests,
streams and application state. Future DNS/NTP or other supported protocols use
their native exchanges and meaningful state. Do not force an authentication,
session, URL or request/response model onto every protocol. Stateless protocols
can correlate by exchange/message identifiers. Protocol experts specialize within
the shared reviewer roles. Adding a new basic protocol still needs an engine and
assessment driver; the orchestrator does not invent protocol support through text.

## Profile identities and coverage planning

Profiles already have a human-readable `id` and `version`, and telemetry already
exposes selected/answering profile metadata. Keep those IDs stable; do not rename
existing `sudo-2019-14287` or `apache-2021-41773` just for assessment. New IDs can
follow a readable convention such as `ssh_cve_2019_14287` or `http_cve_2021_33193`.
Names must be unique in the selected catalog/deployment; use a publisher prefix
for third-party profiles when needed. Do not imply a separate namespace field
already exists. The same logical ID persists across versions;
a content fingerprint identifies the exact candidate. A CVE number alone is not
enough when multiple products/protocol profiles emulate different aspects of it.

Each finding records `profile_id`, version/fingerprint, variant when applicable,
deployment group/listener, loop/candidate revision and relevant interaction/session
or message identifiers. A composition finding can name several affected profile
IDs and an engine/base owner; do not force all findings onto one deception. Blind
reviewers use neutral target handles; the controller adds canonical profile IDs
to final findings without revealing private implementation names during review.

Use a cohort and coverage plan, rather than only isolated tests or every possible
combination:

- Per-profile assessment proves each deception's own behavior and realism against
  its declared base, including normal, vulnerable/protected and negative cases.
- Deployment-group assessment checks the combinations the operator actually runs:
  routing, fallback, shared identity, intended interactions and state isolation.
- Shared-engine regression checks cover sibling profiles when a common adapter,
  base, runtime, composition rule or provider interface changes.
- Compatibility-driven pairwise/risk-based groups extend coverage where useful;
  incompatible profiles are tested for correct rejection, not launched together.

By default a requested cohort loop covers every selected profile's required active
checks plus its required groups. A caller can explicitly choose a focused or
rotating schedule for cost reasons; record skipped profiles as unassessed for that
loop, never as passing. A cohort loop is one cycle across the declared cohort,
not an implicit promise of 20 independent loops per profile. Report per-profile
and per-group coverage counts. Final success requires complete, current coverage
of the selected scope; a shared-engine change invalidates affected old assessments.

## Blinding and validation data

Prefer independent workers with fresh context and genuinely restricted artifact
access. A prompt saying "do not read the repo" does not enforce isolation when
the worker can access it. Use a temporary review workspace with allowed references,
isolated target endpoints and bounded native protocol clients. If access cannot be restricted, label
the run an independent review, not a blind study. Do not inherit the author's chat
history or reveal the implementation through filenames/private manifests.

The current packaged `held_out` cases are public regression variations. They
are not an independent hidden test set. A stronger study needs separately managed,
frozen validation cases unavailable during refinement. Once a finding/probe is
shown to the author, classify it as regression evidence; it no longer measures
unseen generalization. Keep a remaining private reserve where available.

Active probing is the initial assessment mode, not a later optional milestone.
Only explicitly selected loopback instances or an isolated lab network are in
scope: no arbitrary targets, off-target redirects, real host command execution
or unbounded resource attacks. Give reviewers independent instances/sessions
unless a planned test requires shared connection or composition behavior. Preserve
the declared baseline while resetting private attacker state between independent
tests. Treat responses, reference documents and captured payloads as untrusted
data, never as tool instructions. Reviewers should not follow URLs or execute
host commands merely because a response suggests them.

Freeze observations after collection for reproducibility, replay and optional A/B
comparison. "Frozen" describes the retained evidence and candidate snapshot; it
does not restrict reviewers to reading transcripts. Reviewers can actively choose
follow-up probes against the candidate and append them to that loop's evidence.

Normalize harness labels/paths in metadata while preserving actual response
bytes. Keep demo certificate/deployment tells in a separate operational finding
category when transport impersonation is excluded; do not silently alter captured
responses to hide genuine behavior defects. Do not claim a fabricated 50% chance
of real samples when every candidate is simulated. Neutral A/B labels reduce
author bias but do not establish statistical indistinguishability.

## Evidence and scoring

Every substantive finding needs affected profile IDs and a protocol-appropriate interaction identifier, concrete
observed bytes or sequence, expected behavior with a reference, confidence,
severity, scope, suspected owner and a reproducible follow-up test. For missing
events, distinguish a truncated observation window from an impossible ordering
inside the visible window. Missing profile internals are not evidence of an
attacker-visible defect. Ignore impressions such as "too clean" without a
concrete observable inconsistency.

Retain EvidenceForge's distinction:

- **Verdict confidence:** confidence in the reviewer's assessment.
- **Synthetic-confidence score:** how simulated the observed service appears,
  0–100 with lower being more realistic. Use 0–20 indistinguishable on available
  evidence, 21–40 mostly realistic, 41–60 mixed/inconclusive, 61–80 likely synthetic,
  and 81–100 confidently synthetic. These are reviewer judgments, not measured
  probabilities or a percentage of fidelity.
- **Realism score:** `100 - synthetic_confidence`, higher is better. This is the
  operational score used for the median-85 threshold and DECEIVE dashboard.

Report per-reviewer scores, panel medians, spread, missing reviews and disagreement.
Compute each target's decision median from all required standalone reviewer
realism scores. Partial medians may be displayed for diagnosis, but never qualify
as a pass or as a complete plateau sample. Keep verdict confidence, deterministic
pass rates, telemetry audits, deliberation and A/B results separate. Never invent a
missing score. Freeze reviewer prompts/model settings and record their revisions
to make comparisons interpretable. Re-run or deliberate when disagreement is
material; do not conceal it in the mean.

Start with concrete categories: `protocol_contract`, `vulnerability_semantics`,
`identity_or_state`, `composition`, `response_format`, `operational_tell`, and
`unproven_or_out_of_scope`. Rank verified P0–P4 findings by severity, recurrence,
independent specialist agreement, affected sibling paths and fix risk. A high
average score does not establish a specific root cause; verify before changing it.
Realism criteria combine convincing observable behavior with agreed reviewer
targets; they are required, not advisory. Calibration measures reviewer variance
and the rubric's usefulness; it does not excuse known realism defects or waive
correctness. Consider repeated passing rounds in an until-criteria predicate to
avoid declaring success from one unusually favorable reviewer run.

## Refinement ownership and stopping

Possible owners are the protocol adapter/library boundary, runtime identity and
session state, base profile/virtual fixtures, composition resolver/dispatcher,
vulnerability behavior, generative prompt/provider interface, telemetry, or the
evaluator itself. Fix the highest layer that owns the demonstrated fact and
cover a sibling path. Avoid exact-request special cases or editing a fixture
only to satisfy one review sample. Verify that the new regression test fails
before the fix and passes afterward.

Budgets should bound iterations, elapsed time, requests/concurrency, per-interaction
size/time and model tokens/cost. Account for reviewer calls as well as any LLM
used by the deception. The tool stops when its configured exit policy or an explicit bound is reached; report
incomplete quality separately. Fixed-count versus until-criteria behavior follows
the user's requested control, not an arbitrary three-loop default. External
models are optional and explicitly selected; ordinary tests remain model-free.
Mock providers are appropriate for regression tests, not evidence of a generative
deception's realism. Assess its selected actual provider/configuration or mark
that target unassessed; never silently substitute deterministic output.
Assessment is authoring/development tooling, preserving the single-container
production deployment and adding no mandatory SDK, service or inference dependency.

Use standalone review for each candidate. Use randomized A/B only for a defined
before/after question or ambiguous score movement. Keep its mapping private until
synthesis; do not mix A/B scores into standalone trends. Do not call a dashboard
evidence of objective improvement without checking findings and reviewer variance.

## Required final graphical dashboard

Generate and link a standalone SVG dashboard at the end of every assessment run,
including fixed-count completion, quality success, plateau, budget exhaustion,
cancellation and incomplete/error outcomes. Persist structured per-loop scores so
the chart can be reproduced without calling reviewers again. If no complete review
exists, show incomplete/N/A coverage and the stop reason rather than inventing
scores. Retain dashboards from earlier runs; update a latest-history view too.

Follow EvidenceForge's useful views, adapted to higher-is-better realism and
profile/group IDs:

- Reviewer-specific realism lines, panel median, five-loop rolling median and
  the threshold at 85. Show the worst target prominently for a cohort; aggregate
  averages may be context but never replace individual pass requirements.
- Per-profile and deployment-group heatmaps across loops, with drill-down or
  separate detail panels when the cohort is large.
- Loop-to-loop delta bars and the reviewer disagreement band/spread.
- Separate correctness/telemetry gate states, coverage gaps, and counts of verified
  unresolved/resolved findings by severity.
- Final status/stop reason, target and candidate revisions, elapsed time/model
  usage, plus annotations for fixes and image/driver changes that affect comparison.

Default the displayed history to the latest 20 loops, with all history available.
Keep raw synthetic-confidence and verdict confidence in machine-readable records;
label all plotted score direction explicitly. A partial or stale review creates
a visible gap, not a connected improvement line. A repaired candidate without
post-fix review cannot inherit the preceding candidate's score. The rolling
median is descriptive and does not replace the configured confirmation predicate.

Use a lightweight renderer outside the production runtime. EvidenceForge's
renderer provides rendering patterns, but its fixed personas, lower-is-better
series and averaging semantics cannot be reused unchanged for this contract.
An interactive HTML view can accompany the portable SVG later; the SVG remains
a required deliverable. The pilot dashboard and measured review outcomes are
recorded in the verification notes; synthetic test fixtures are labelled separately.

## Artifacts and first implementation milestone

Store generated runs under an ignored `results/assessments/<run-id>/` directory,
never overwriting prior evidence. Separate an author-private manifest (source,
dependency/profile/suite fingerprints, expected results, logs, model configuration,
cost and redaction policy) from the allowlisted reviewer bundle. Save all candidate
transcripts, protocol observations, deterministic reports, reviewer reports,
structured scores/findings, replayable probes and final synthesis. Exclude secrets
and private keys from reviewer input and version control.

Recommended first pilot: actively assess the existing sudo and Apache profiles,
which exercise SSH and HTTP and have frozen acceptance suites, both independently
and in the reference deployment. Use the iterative loop from the start, repair
verified findings, and require convincing outcomes as well as technical success.
Compare findings with deterministic checks and measure reviewer variance while
agreeing the realism rubric. Include an intentional defect
in a separate labelled-for-the-controller calibration candidate to verify that
the process can find a known error; keep that label hidden from reviewers.
Expand to the new HTTP/2–3 CVEs and other supported protocols using the same loop
when their drivers and accepted behavior specifications are available.

The implementation provides versioned protocol-driver and evidence contracts,
bounded active probes, explicit individual/group targets, Docker lifecycle/image
caching, native reviewer orchestration, report validation, checkpoints, stopping
policies and standalone dashboards. Captured actions are replayable through the
same probe interface. Complete private evidence stays local; only the public
briefing is supplied to reviewers. Arbitrary bundle publication/redaction and a
standalone autonomous coding-agent service are not implemented.

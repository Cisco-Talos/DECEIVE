# Verification

Implementation is on `codex/deception-profiles`, based on updated `dev` at
`cce98f3`. Local `main` and `dev` were fast-forwarded before implementation.
`codex/protocol-registry` remains at `2647132` as reference. This document records
local verification before branch review. No registry publication, merge, or
persistent deployment was performed.

## Tests and acceptance

- Original SSH baseline: 26 tests passed. Assessment baseline: **105 tests passed**.
- Current deterministic suite: **202 tests passed** in 52.86 seconds on Darwin arm64,
  Python 3.11.15. This includes actual SSH, HTTP/1.1, HTTP/2 multiplexing, HTTP/3,
  binary content, authentication modes, isolated state, key reuse, migration,
  resource/deadline handling, startup rollback, observer failures, and offline
  initialization of all five provider SDK adapters.
- Composition tests cover additive YAML/CLI selections (including settings-only
  YAML), deduplication, conflicting definitions and explicit/default inheritance,
  base/version/capability/routing/binding conflicts, read-only preflight and
  startup revalidation, relative assets, private rule state, stable listener
  names, profile attribution, and real HTTP/2 and HTTP/3 multiplexing.
- Test-first acceptance validation was demonstrated with six initially failing
  tests for empty/vacuous assertions, followed by the validator fix. Source tests
  now verify the bundled CVE inventory, agreement records and frozen criteria;
  acceptance discovery is shared with wheel/container checks.
- Ten bounded wire probes cover HTTP/2 invalid methods, whitespace/method case,
  small reset sequences and HTTP/3 standalone FIN with matching/mismatched body
  lengths. These characterize engine visibility, not successful CVE emulation;
  details and dependency versions are in `docs/protocol-capability-findings.md`.
- Both repository skills validate. The assessment contract is implemented; native
  independent reviewer pilots are recorded below. Ordinary pytest uses fake
  reviewer reports and mocked orchestration, never live providers. It covers a
  fixed 20-loop run, failed gates followed by repairs, confirmation/freshness,
  missing service coverage, persistent unresolved findings, plateau, resume,
  concurrent edits, broker bounds/cancellation and partial dashboards.
- Initially failing regressions exposed premature final qualification, held-out
  semantics, missing telemetry checks, disappearing critical findings and partial
  group coverage. Real Docker integration exposed nullable staging and
  content-derived listener names breaking profile-only reuse; both were repaired.
- Both reference CVEs were approved on 2026-11-01 before implementation. The
  human-selected sudo v2 amendment on 2026-11-02 replaces the simulation-disclosing
  denial and adds controls while preserving the original approval/profile/suite
  history. All **20 current acceptance cases** pass: 12 sudo cases and 8 Apache
  cases, including held-out variations. Active agreement records and frozen
  fingerprints ship under `deceive/acceptance/` and are checked by tests/artifacts.
- The model-free combined reference deployment was tested with concurrent SSH
  and HTTP clients and one summary per independently identified session.
- The ARM64 standard container built and passed the full smoke script. Tests
  cover UID 10001 operation, stdout JSONL, SSH and HTTP/1.1–3, health/readiness,
  graceful shutdown, persisted SSH keys/TLS certificates across container reuse,
  installed SDKs and exclusion of local ML frameworks.
- The ARM64 container also passed the packaged CVE suites with external networking
  disabled (`--network none`, using only container loopback).
- Artifact checks also validate YAML plus an additional CLI-selected profile
  without creating runtime files, then serve both profiles through one real
  HTTP/2–3 listener. The same check runs in the installed wheel and container CI.
- The wheel was installed into a temporary uv tool environment outside the
  checkout. All four profiles validate; the frozen CVE suites and real HTTP/2–3
  evaluation pass. Default HTTP startup, healthcheck and clean shutdown pass.
- Skill metadata validation passed. The CLI authoring workflow was exercised
  through fail/refine/pass while retaining an unchanged acceptance fingerprint.
- `uv lock --check --offline` and `git diff --check` pass.

No ordinary test or acceptance run called a live runtime LLM provider or ran
vulnerable software. Native reviewer agents performed the separate active panels.

## Initial active assessment pilot (historical)

Two fresh panels of four native agents actively probed sudo and Apache separately,
their reference deployment group, and a controller-only calibration target.
All **32 reports** were validated against captured interaction IDs. These are
independent reviews, not technically enforced blind studies.

| Target | Loop 1 realism median | Loop 2 realism median | Technical/telemetry |
| --- | ---: | ---: | --- |
| sudo-2019-14287 | 50 | 82 | Passed / passed |
| apache-2021-41773 | 83.5 | 83.5 | Passed / passed |
| Reference deployment group | 50 | 82 | Passed / passed |
| Calibration control (excluded) | 9 | 13.5 | Deliberate correctness failure / passed |

All four reviewers found the control's route-dependent Apache version in each
round. The pilot ended at the requested two-loop count with **needs work**, not
quality success. No production target met the two-round ≥85 requirement.

The first panel identified sudo's literal “simulated policy” refusal as a P2
realism defect, on both standalone and grouped targets. The frozen acceptance
suite required that exact wording. No profile behavior or frozen criterion was
changed during that pilot. The median changes reflect reviewer variance, not a
claimed realism repair. The later human-approved v2 amendment and fresh panels
below resolve this finding without rewriting the historical evidence.

Harness repairs between and after panels include candidate confirmation, suite
semantics, retry telemetry isolation, retained-resource continuation, stable
assessment listener names, input/origin/authentication auditing, per-service
coverage and carrying unresolved findings forward. The strengthened audit passes
on recorded evidence from both panels. Final harness hardening was verified by
regressions and Docker integration; historical panel scores retain their original
candidate/client fingerprints.

Local evidence and the inspected standalone dashboard remain under ignored
`results/assessment-pilot-20261102/`. Its four containers are stopped and retained
by default; no assessment listener remains running. Disposable integration runs
remove their owned containers, networks and volumes. The final integration passes
two loops with real SSH and HTTP/1.1–3, binary/acceptance assertions, group coverage,
profile-only reuse and ownership-scoped teardown. Server/client/profile cache
classification is separately covered by deterministic fingerprint tests.

## Stabilization assessment

The [stabilization record](stabilization.md) documents the versioned sudo
amendment, native authoring exercise and three additional active rounds, with
60 validated independent reports under the versioned `evidence-v2` rubric.
The first round exposed a rebuilt container retaining an old project wheel.
Installed-source verification and a metadata-identical, source-only warm-cache
rebuild regression now detect/prevent that failure. Its failed gate and original
reviewer evidence remain recorded.

The final two rounds assessed an unchanged candidate. Sudo, Apache, their
reference group and the authored HTTP/2–3 application each achieved median
realism **90** twice, with passing correctness/telemetry and no unresolved
verified P0/P1 findings. Every role covered every advertised service/version.
All four reviewers detected the separate deliberate version contradiction in
each round; it is excluded from quality scoring. The run ended `quality_success`.
Scores describe bounded reviewer observations, not measured fidelity percentages.

The native authoring exercise froze criteria before behavior and demonstrated
genuine red runs. Its final profile passes 9/9 cases on HTTP/2 and 9/9 on HTTP/3
after repairs to shared cookie handling. The HTTP/3 driver also reconnects closed
idle transports while preserving private cookie state, without replaying
uncertain requests. Focused regressions and the full suite pass.

Current evidence and the visually inspected dashboard are under ignored
`results/stabilization-20261102/`. Its five assessment containers are stopped and
retained. Remote ARM64 CI is deferred until the human is ready for a PR. The 2026-11-03 Bedrock check
below completes the separate native live-provider integration gate; it does not
refresh historical native realism-panel scores after source changes.

## Live Bedrock SSH integration — 2026-11-03

A local deployment YAML reused existing configurable `aws_profile`, `region`,
`model`, temperature, token-limit and deadline fields. It selected the active US
Sonnet 4.6 inference profile via `us-east-1`; credentials remained in the AWS
credential chain. The listener bound only `127.0.0.1` on an ephemeral port.

The first run exposed rejection of empty Converse history turns after a silent
command. Failed mocked regressions preceded the metadata-only serialization
repair, which preserves original transcript content and role order. Summary
regressions also preceded support for final bold judgement labels, with unknown
or non-final labels still producing UNKNOWN. The full deterministic suite passes.

The repeated explicit live run passed 17 checks with eight model calls across
three SSH sessions, reporting 3,121 input and 318 output tokens. It covered
interactive/non-interactive behavior, stable identity, private generative
history, working-directory facts, summaries, base64 logs and cleanup. See the
[detailed stabilization addendum](stabilization.md#live-bedrock-ssh-addendum--2026-11-03).
The local runner trims surrounding whitespace for generated-text assertions;
raw output and its omitted final newlines remain recorded as fidelity work.
These bounded observations establish integration, not general realism or exact
terminal byte fidelity. Local evidence is under ignored
`results/bedrock-ssh-20261103/`; no persistent listener remains.

## Unified operator interface — 2026-11-03

The catalog, named Docker deployment lifecycle and versioned JSON results reuse
the existing CLI/configuration, runtime validation, profiles, evaluator and
assessment helpers. The repository-local `deceive` umbrella skill routes natural
language to these operations and the existing authoring/assessment workflows.
Its metadata validates and it remains repository-local. A fresh operator-agent
acceptance pass and four independent active reviewers are recorded below.

The public managed CLI passes real SSH and HTTPS/1.1–3 probes, including HTTP/2–3
multiplexing, combined YAML/CLI selection, complete base/relative prompt/binary
asset snapshots, explicit TCP/UDP discovery, stable restart bindings and data,
and ownership-scoped teardown. Shared external assertions pass the reference
CVEs' base-deployment cases; protected variants remain separate and are still
covered by full installed-wheel/container acceptance checks. Mocked lifecycle
regressions cover foreign ownership, changed options/configuration, readiness
failure, failure before container creation, data retention and AWS configuration
without live calls.

The real snapshot test exposed CLI-added members disappearing when a resolved
listener was materialized without its original `deceptions`. A failing resolver
regression preceded the shared repair. Container snapshots now retain that exact
resolved selection. The updated wheel check exercises catalog discovery and
JSON results outside the checkout; container CI now includes the managed CLI
smoke. No additional runtime package, CVE or runtime model call was introduced.

### Fresh operator acceptance

A fresh-context agent used the umbrella skill to discover/inspect the catalog,
validate and deploy metrics plus diagnostics, and verify actual H2/H3 responses
before/after stop/restart. Container/image/volume IDs, member fingerprints,
bindings and generated TLS identity remained stable. It then authored a local
fictional Harbor Queue 1.2 profile after freezing seven cases for each protocol.
Genuine missing-behavior red runs preceded implementation, and the unchanged
suites passed 7/7 on actual HTTP/2 and 7/7 on HTTP/3. Setup/socket-permission
failures were recorded separately and were not counted as behavior failures.

Exactly one fixed assessment loop used four fresh-context native reviewers with
20 actions each, covering both protocol versions. Correctness and telemetry
passed; every reviewer reported realism 90 with no profile findings. The run
ended `count_complete`. Its two-round confirmation policy remained unchanged,
so final qualification was false and finish returned 1. This completed the
workflow test without claiming quality success or a measured fidelity percentage.
The inspected SVG, original reports, frozen hashes, command history and evidence
export remain under ignored `results/operator-acceptance-20261103/`.

The protocol reviewer preserved repeat H3 HEAD failures as client/transport
uncertainty. After the frozen panel completed, three real-wire regressions
reproduced those failures. The locked aioquic client's length-validation path
was treating HEAD metadata as a missing body, contrary to
[HTTP HEAD semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.2).
A narrow client connection wrapper now tracks HEAD streams and preserves their
headers while requiring zero response content. Normal GET length validation is
unchanged; tracking is cleaned on completion/reset/connection termination.
The normal and FIN clients share the wrapper, with regression guards for invalid
lengths, actual HEAD content and method case. Its aioquic framing-hook dependency
is exercised against the lockfile and installed artifacts; the existing aioquic
package now has an explicit `>=1.7,<2` floor/range, with no additional packages.

A separate parent-owned diagnostic replayed HEAD against the unchanged Harbor
profile and original server image: H2, H3 and standalone FIN all returned empty
405 responses with the original length metadata; subsequent GET on the same
H3 connection passed. This verifies the client repair without altering the
historical panel scores or claiming a fresh panel for the changed client.
All exercise/diagnostic resources were removed, preserving the nine unrelated
stopped assessment containers. No live runtime provider or AWS credentials were
used. No new CVE or public deployment was added.

Current local evidence is under ignored `results/unified-interface-20261103/`.
No PR, merge or publication was performed; ARM64 remote CI remains deferred.

## SSH stream and exit-status fidelity — 2026-11-03

The built-in `linux-ssh` profile is now version 2 and requests structured model
replies. Existing custom/INI-migrated profiles retain text mode. Neither frozen
CVE suite nor its agreement record changed. Real SSH tests verify exact stdout
and stderr bytes, missing/extra trailing newlines, binary content, strict schema
validation, status queries, shell exit, private status and one-summary ownership.
The assessment/evaluation clients share byte-preserving prompt handling; source
tests also cover response-format inheritance and configured evaluation limits.

Initial red runs captured 12 missing-contract failures, two client-capture
failures and a blank-line status failure. A later regression reproduced the
assessment client's open connection after shell exit; the driver now closes it.
Evidence is retained under ignored `results/ssh-fidelity-20261103/`.

A separately authorized live Bedrock check used configurable AWS profile, region,
model and limits from local deployment YAML. No credentials are in the repository.
The five-case criteria were frozen before execution. The first run passed 3/5:
exec output worked, but interactive replies sometimes included JSON fences and
were rejected. One diagnostic call confirmed the wrapper. The decoder now
tolerates only a single JSON fence, still validating types/fields and preserving
raw model output. Explanatory text and malformed objects remain rejected.

The unchanged live suite then passed **5/5**, covering newline/unterminated exec
output, separate stderr with status 7, interactive variable history, status
queries and inherited shell exit, followed by a fresh baseline. The fresh-baseline
case starts a new runtime; it does not independently prove concurrent-session
isolation. Deterministic integration tests cover private concurrent state.
The two suite executions and diagnostic used **17 generation calls**, reporting
10,454 input and 368 output tokens; analysis was disabled. These are reported
token counts, not a dollar estimate or a general realism assessment.

The final wheel and ARM64 image exercise the new path with fake providers and
real SSH channels, including binary output, separate stderr/status, interactive
status and fresh-connection status. The same scripts retain frozen CVE acceptance,
real HTTP/2–3 and composition checks. A two-loop Docker assessment smoke uses fake
review reports and validates SSH/HTTP drivers, telemetry, compatible container
reuse and teardown; it is not an independent expert panel.

Structured history improves transport fidelity without implementing a complete
shell. Generative state remains bounded history; PTY line discipline, arbitrary
stdout/stderr interleaving and output indistinguishable from the shell prompt
remain documented limitations. No new runtime dependencies were introduced.

## Container measurements

Docker Engine 29.9.2 runs Linux/aarch64 on this workstation. ARM64 is the only
current build and CI target, including wheel and ordinary pytest jobs. AMD64 is
an optional future enhancement. Measurements are local observations, not
performance promises.

| Artifact | Docker-reported stored bytes after unpacking | Ready time | Packages |
| --- | ---: | ---: | ---: |
| `deceive:interface-arm64` (native) | 384,095,894 | 1.579 s | 50 |
| `deceive:ssh-fidelity-arm64` (native) | 384,143,198 | 1.568 s | 50 |

Ready time measures container creation/start through the local health probe with
an existing image and a new data volume. It excludes image pulling. Stored image
size is measured after first unpacking, so lazy-unpacked foreign images are not
incorrectly compared using compressed content alone; it is not a download size.
The latest standard image verifies installed source/assets against 50 expected
files (49 before the SSH reply module). A separate warm-cache rebuild changes only copied Python source while
retaining identical build metadata, then verifies the changed installed bytes.

Container smoke tests removed their disposable containers and volumes. Built
images remain available locally under the tags above. The GitHub workflow builds
ARM64 on a native runner and produces an image archive, but has not been
triggered or published as part of this work.

## Native measurements

| Measurement | Result |
| --- | ---: |
| Wheel, excluding dependencies | 113,901 bytes |
| Installed packages without provider extras | 29 |
| Installation using available cached dependencies | 0.063 s |
| Fresh process startup to readiness | 0.223 s |

The source lockfile has **57 packages**, including all optional provider SDKs and
test dependencies, versus 131 before this change. PyTorch, Transformers,
LangChain and tokenizer downloads are no longer required. Container builds use
`uv.lock`; the wheel verification also checks compatible dependency versions
resolved by a fresh native installation.
The latest wheel check selected aioquic 1.7.2; source and standard-container
dependencies remain frozen by `uv.lock`. Capability probe observations above
refer to the locked source environment, not every allowed future dependency.

The verification scripts write machine-readable measurements for subsequent
release runs. Use `scripts/verify_wheel.py` and `scripts/container_smoke.py` to
reproduce checks; `scripts/assessment_smoke.py` exercises the Docker assessment lifecycle.
Container architecture/emulation is included in measurement reports. Installed-wheel
checks also verify the assessment CLI and render a cancelled partial dashboard.

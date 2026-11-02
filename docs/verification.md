# Verification

Implementation is on `codex/deception-profiles`, based on updated `dev` at
`cce98f3`. Local `main` and `dev` were fast-forwarded before implementation.
`codex/protocol-registry` remains at `2647132` as reference. This document records
local verification before branch review. No registry publication, merge, or
persistent deployment was performed.

## Tests and acceptance

- Original SSH baseline: 26 tests passed. Assessment baseline: **105 tests passed**.
- Final deterministic suite: **132 tests passed** in 35.85 seconds on Darwin arm64,
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
- Both reference CVEs were approved on 2026-11-01 before implementation. All
  **17 acceptance cases** pass: 9 sudo cases and 8 Apache cases, including all
  held-out variations. Their suite fingerprints are frozen in
  `deceive/acceptance/reference-approval.json` and checked by tests and artifacts.
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

## Active assessment pilot

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
suite requires that exact wording. It remains unresolved pending a separately
agreed criteria amendment. No profile behavior or frozen criterion was changed.
The median changes reflect reviewer variance, not a claimed realism repair.

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

## Container measurements

Docker Engine 29.9.2 runs Linux/aarch64 on this workstation. ARM64 is the only
current build and CI target, including wheel and ordinary pytest jobs. AMD64 is
an optional future enhancement. Measurements are local observations, not
performance promises.

| Artifact | Docker-reported stored bytes after unpacking | Ready time | Packages |
| --- | ---: | ---: | ---: |
| `deceive:assessment-arm64` (native) | 383,877,984 | 1.559 s | 50 |

Ready time measures container creation/start through the local health probe with
an existing image and a new data volume. It excludes image pulling. Stored image
size is measured after first unpacking, so lazy-unpacked foreign images are not
incorrectly compared using compressed content alone; it is not a download size.
The standard-image and assessment-lifecycle checks ran concurrently on this workstation.

Container smoke tests removed their disposable containers and volumes. Built
images remain available locally under the tags above. The GitHub workflow builds
ARM64 on a native runner and produces an image archive, but has not been
triggered or published as part of this work.

## Native measurements

| Measurement | Result |
| --- | ---: |
| Wheel, excluding dependencies | 91,316 bytes |
| Installed packages without provider extras | 29 |
| Installation using available cached dependencies | 0.243 s |
| Fresh process startup to readiness | 0.212 s |

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

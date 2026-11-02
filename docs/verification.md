# Verification

Implementation is on `codex/deception-profiles`, based on updated `dev` at
`cce98f3`. Local `main` and `dev` were fast-forwarded before implementation.
`codex/protocol-registry` remains at `2647132` as reference. This document records
local verification before branch review. No registry publication, merge, or
persistent deployment was performed.

## Tests and acceptance

- Baseline before implementation: 26 tests passed.
- Final deterministic suite: **80 tests passed** in 18.03 seconds on Darwin arm64,
  Python 3.11.15. This includes actual SSH, HTTP/1.1, HTTP/2 multiplexing, HTTP/3,
  binary content, authentication modes, isolated state, key reuse, migration,
  resource/deadline handling, startup rollback, observer failures, and offline
  initialization of all five provider SDK adapters.
- Composition tests cover additive YAML/CLI selections (including settings-only
  YAML), deduplication, conflicting definitions and explicit/default inheritance,
  base/version/capability/routing/binding conflicts, read-only preflight and
  startup revalidation, relative assets, private rule state, stable listener
  names, profile attribution, and real HTTP/2 and HTTP/3 multiplexing.
- Both reference CVEs were approved on 2026-11-01 before implementation. All
  **17 acceptance cases** pass: 9 sudo cases and 8 Apache cases, including all
  held-out variations. Their suite fingerprints are frozen in
  `deceive/acceptance/reference-approval.json` and checked by tests and artifacts.
- The model-free combined reference deployment was tested with concurrent SSH
  and HTTP clients and one summary per independently identified session.
- Both standard container images built and passed the full smoke script. Tests
  cover UID 10001 operation, stdout JSONL, SSH and HTTP/1.1–3, health/readiness,
  graceful shutdown, persisted SSH keys/TLS certificates across container reuse,
  installed SDKs and exclusion of local ML frameworks.
- Both containers also passed the packaged CVE suites with external networking
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

No test or acceptance run called a live LLM or ran vulnerable software.

## Container measurements

Docker Engine 29.9.2 runs Linux/aarch64 on this workstation. **amd64 was tested
under emulation**, not on a native amd64 machine; CI retains a native runner for
that architecture. Measurements are local observations, not performance promises.

| Artifact | Docker-reported stored bytes after unpacking | Ready time | Packages |
| --- | ---: | ---: | ---: |
| `deceive:arm64` (native) | 383,361,386 | 1.536 s | 50 |
| `deceive:amd64` (emulated) | 357,977,679 | 3.576 s | 50 |

Ready time measures container creation/start through the local health probe with
an existing image and a new data volume. It excludes image pulling. Stored image
size is measured after first unpacking, so lazy-unpacked foreign images are not
incorrectly compared using compressed content alone; it is not a download size.
The latest architecture smoke checks ran concurrently on the same workstation.

Container smoke tests removed their disposable containers and volumes. Built
images remain available locally under the tags above. The GitHub workflow builds
both architectures on native runners and produces image archives, but has not been
triggered or published as part of this work.

## Native measurements

| Measurement | Result |
| --- | ---: |
| Wheel, excluding dependencies | 55,125 bytes |
| Installed packages without provider extras | 29 |
| Installation using available cached dependencies | 0.058 s |
| Fresh process startup to readiness | 0.179 s |

The source lockfile has **57 packages**, including all optional provider SDKs and
test dependencies, versus 131 before this change. PyTorch, Transformers,
LangChain and tokenizer downloads are no longer required. Container builds use
`uv.lock`; the wheel verification also checks compatible dependency versions
resolved by a fresh native installation.

The verification scripts write machine-readable measurements for subsequent
release runs. Use `scripts/verify_wheel.py` and `scripts/container_smoke.py` to
reproduce checks; container architecture/emulation is included in the reports.

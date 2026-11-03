# Stabilization before the unified interface

This pass exercises the existing deceptions and development workflows before
adding the common operator interface. ARM64 remains the only build/test target.
No new CVE or production deployment is introduced.

## Versioned sudo amendment

On 2026-11-02 the human selected stock-sudo-style refusal wording. Sudo profile
and suite version 2 retain the existing UID behavior, controls, private state and
execution restrictions. The suite has 12 cases, including unsupported option and
missing-command controls. The frozen fingerprint is
`e2470cdd29f98f47eb63a7754f7dd3d93f764ae73d9771c476966b28cd3b39d9`.

The original v1 profile, suite and exact approval record are retained under
`deceive/acceptance/history/`. The active v2 agreement is
`deceive/acceptance/sudo-2019-14287-v2-approval.json`. The
[behavior contract](reference-acceptance-proposal.md) describes the precise
amendment and its fidelity limits. Apache criteria remain unchanged.

## Native authoring exercise

A fresh native author used the repository authoring skill to create a fictional
BuildArchive 1.4.2 application under ignored
`results/authoring-stabilization-20261102/`. Required, negative, sequence,
concurrent, isolation and variation criteria were written and frozen before
behavior. Genuine red runs passed only 1/9 cases on both HTTP/2 and HTTP/3.

The authored candidate initially passed HTTP/2 9/9 but HTTP/3 only 5/9. The shared
HTTP/3 client was not retaining cookies, so later requests observed new private
sessions. The parent workstream added protocol regressions and repaired the
shared client using HTTPX's cookie jar, including cookie scope, expiry, explicit
overrides and lowercase HTTP/3 field names. The unchanged authored profile and
frozen criteria then passed 9/9 on both protocols. The author's 12-invocation
budget, commands, setup failures and actual red/final reports are preserved.

## Installed source and warm-cache builds

The first active Docker round failed the sudo acceptance gate despite passing
host tests. Independent reviewers reproduced the old disclosure. Installed
module hashes proved that the rebuilt image contained an old project wheel:
the host/candidate module hash began `886ef169`, while the installed module
began `6fd56280`.

This matches uv's documented [local-project caching heuristic](https://docs.astral.sh/uv/concepts/cache/).
The Docker build now explicitly reinstalls DECEIVE while retaining cached
dependencies. Built assessment images compare installed runtime source hashes
before launch; standard-image verification also checks packaged clients/assets.
The warm-cache regression holds pyproject, lockfile, Dockerfile, README and
license unchanged, edits only a module in an isolated build context, and checks
the installed bytes in the rebuilt image. No working-tree source is altered by
that regression. It passes, and its temporary image is removed.

## Assessment consistency

The versioned `evidence-v2` rubric separates observed tells from coverage
uncertainty. Reviewers cite substantive captured interactions for their score
band and explain coverage limits separately from verdict confidence. Midpoint
anchors reduce arbitrary within-band variation; they do not force a pass.
Reports with mismatched bands or unknown score evidence are rejected.

Each reviewer must probe every service and advertised HTTP version. Repeated
unchanged-candidate assessments export median/reviewer ranges in
`repeatability.json`. Changed candidates or rubric revisions are not pooled.
Idle HTTP/3 transport reuse now reconnects with the same private cookie jar;
uncertain requests are never silently replayed.

## Verification and remaining gates

The deterministic suite passes **146 tests**. The standard ARM64 image passes
installed-source checks for 46 packaged files, all 20 current CVE acceptance
cases, real HTTP/2–3, composition, non-root operation, persistent keys and clean
shutdown. The installed wheel passes outside the checkout.

Active rounds, decisions, exact repair replays, source verification and the final
dashboard are preserved under ignored `results/stabilization-20261102/`.
The first failed round remains evidence and cannot count toward confirmation.
Three rounds produced 60 validated independent reviewer reports. Rounds 2 and 3
assessed the same candidate and comparison fingerprint. Sudo, Apache, their
reference deployment group and the authored application each had a realism
median of 90 in both rounds, with passing correctness and telemetry gates and
no unresolved verified P0/P1 findings. All four reviewers detected the deliberate
version contradiction in each round; that calibration target remains excluded
from quality scoring and automatic repair.

The run ended with `quality_success`. The repeatability report records panel
median ranges of 90–90 for those four unchanged targets. These are descriptive
results from bounded native reviews, not a measured 90% fidelity guarantee or a
statistical independence claim. The inspected standalone dashboard preserves
the failed first round, repair annotations, coverage and calibration findings.
All five assessment containers were stopped and retained without teardown errors.
The final disposable lifecycle check passes two loops over real SSH and
HTTP/1.1–3, reuses compatible containers after a profile-only update and removes
its own containers, network and volumes.

Remote ARM64 CI is deferred until the human is ready for a PR; no PR to `dev`
is part of the current work. The Python matrix invocation explicitly selects its intended
version. The live-provider SSH gate was completed with a configured Bedrock
profile on 2026-11-03; see the addendum below. Mock SDK tests remain separate from
that explicit live run.

The subsequent interface milestone is a shared catalog, managed deployment
lifecycle/status and structured operation results, followed by an umbrella skill.

## Live Bedrock SSH addendum — 2026-11-03

The existing deployment provider schema supplies the AWS profile, region, model,
temperature and output limit. No deployment-specific AWS setting was added to
runtime code. A local ignored YAML selected a named AWS profile, `us-east-1`,
`us.anthropic.claude-sonnet-4-6`, null temperature and a 512-token output limit.
Its SSH listener used `127.0.0.1:0`, configured request deadlines and optional
intent analysis. A separate local runner capped each run at ten model calls.

The first run reached the model but exposed Converse rejecting a blank assistant
turn after a command with no output. An independent bounded request confirmed
the validation error. Three mocked regressions failed before the adapter repair:
empty, spaces/tabs and newline-only turns. The adapter now serializes these turns
as explicit metadata with a system explanation, preserving role order and the
original runtime transcript. A second regression exposed a final bold judgement
label parsing as UNKNOWN; final bold labels are now accepted, while trailing
unstructured commentary and unknown labels still yield UNKNOWN. Summaries request
concise plain text to reduce formatting and truncation failures.

The second live run passed all 17 checks over three real SSH sessions in 8.139
seconds, with eight completed model calls reporting 3,121 input and 318 output
tokens. It covered non-interactive output without a server banner/prompt,
interactive stable identity, private generative history, deterministic working
directory facts supplied to generated answers, private directory state, exit,
base64 telemetry, one successful intent summary per session and cleanup.
No persistent listener remains. Credentials were resolved through the configured
AWS profile and were not copied into DECEIVE configuration or evidence.

The local generated-text assertions trim surrounding whitespace; they do not
establish exact terminal byte fidelity or qualify general SSH realism. Raw model
output is preserved, including omitted final newlines. Exact generative line
endings and exit statuses remain tracked fidelity work. Historical native panel
scores above describe their original candidates, before these provider/summary
repairs, and are not fresh assessments of this changed candidate.

Red/final reports, local deployment YAML and telemetry remain under ignored
`results/bedrock-ssh-20261103/`. These explicit live checks are outside pytest;
ordinary automated tests continue using mocked providers only.

After the repairs, the full deterministic suite passes 153 tests in 45.70
seconds. The rebuilt native ARM64 image passes installed-source verification,
all 20 current CVE cases, SSH/HTTP1.1–3, composition, persistent keys and cleanup.
The current wheel passes installation/evaluation outside the checkout. These
artifact checks are model-free and remain separate from the explicit live run.

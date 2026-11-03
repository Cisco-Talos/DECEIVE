# Active assessment and repair

DECEIVE includes deterministic assessment helpers and a repository
[deceive-assess skill](../skills/deceive-assess/SKILL.md). The skill coordinates
native independent reviewers and code repair; the CLI manages test instances,
evidence and outcomes. It does not launch coding agents by itself. This remains
proof-of-concept tooling, not a production deployment or formal blind study.

Use the host's native agents through the skill with requests such as:

- Run 20 loops on the reference CVE profiles.
- Run until the default realism/correctness criteria are met, at most 20 loops.
- Assess all catalog profiles independently and these deployment groups.

The skill works on the current branch, preserving existing edits. It records
patches/checkpoints but never commits, pushes, resets or discards changes by itself.

## Prepare and start

Run on macOS/Linux (including WSL) from a Git checkout with Docker 28+ available.
Default native-agent limits are four concurrent probe actions, 30 actions per
role/target and ten minutes from that role's first probe of the target. Existing
sessions are scoped to role/target/service; do not share runtime data directories.

```sh
uv run deceive assess prepare --spec examples/assessment.yaml --results-dir results/assessment
uv run deceive assess begin-loop --run results/assessment
uv run deceive assess status --run results/assessment
```

`--root` on prepare selects the source checkout (default current directory).
The versioned spec is separate from deployment YAML. `targets` contain a `name`
and either `profiles` or `deployment`. Optional `protocol`/`versions` override a
single listener, and `suite` selects a custom acceptance suite. Profiles resolve
their complete bases/assets without introducing explicit defaults in place of
inheritance. Paths belong to their owning YAML. `all_profiles: true` adds catalog
profiles as individual targets; it never merges an incompatible inventory.

The example selects sudo, Apache and their reference multi-service deployment.
A calibration target may use `calibration: server_version` with an HTTP profile;
the controller inserts a deliberately contradictory root-page server header.
Keep the target's claims ordinary so reviewers do not know which target is the
control. Calibration is never a production repair target or part of the quality
median, but detection must be verified before the overall assessment can pass.

`docker.build: true` builds/cache-selects an image from an immutable source
snapshot; otherwise specify `docker.image`. The manifest records the actual
digest. Use `build: true` for repair loops: server/installed dependency changes
then rebuild images. With `build: false`, the explicitly supplied image is the
target; rebuild that image yourself before assessing server repairs. Assessment-driver
changes and mounted profile edits reuse server images; binding/mount changes
recreate containers. `docker.retain` defaults true. Targets use dedicated Docker
networks with explicit loopback TCP/UDP mappings. The controller verifies those
mappings. This dedicated bridge is not an outbound-network sandbox. Model-backed targets additionally require configured `providers`, a
target `provider`, and explicit `docker.provider_network: true`; no fake runtime
provider is silently substituted for realism assessment.

Bedrock targets reuse deployment `aws_profile`, `region` and `model` settings.
Set `docker.aws_dir` to an explicit AWS shared-config/credentials directory
(relative paths belong to the assessment YAML). The harness mounts it read-only
and sets the container's shared-config paths; it does not copy secrets into the
candidate or image. Files must be readable by the container's non-root user.
Use a private parent directory for any temporary credential staging and remove it
after final shutdown. Named AWS profiles require this explicit mount. Without a
named profile, standard AWS credential environment variables can be forwarded by
name; values are not written into the specification or reports. Provider network
access still requires `docker.provider_network: true`.

Built target images are checked against the installed runtime source fingerprints
before deployment; a newly tagged image with a stale cached wheel is rejected.
The standard-image check additionally verifies packaged clients and assets.
Source-only rebuild regression testing keeps project metadata unchanged and
checks that the installed module bytes actually change. This addresses uv's
[local-project cache heuristic](https://docs.astral.sh/uv/concepts/cache/) while
retaining dependency caching. Explicit `build: false` images retain their own
recorded digest and require operator-controlled rebuilds as described above.

## Active probes

Only the controller receives private manifests and logs. Give native reviewers
the public JSON from begin-loop/status, their briefing and the following tools:

```sh
uv run deceive assess probe --run results/assessment --role product --target target-01 \
  --action '{"operation":"exec","session":"first","parameters":{"command":"sudo -V"}}'
uv run deceive assess probe --run results/assessment --role protocol --target target-02 \
  --action '{"operation":"request","parameters":{"method":"GET","path":"/"}}'
```

An action can also be supplied as `--action @probe.json`. Select `endpoint` using
the public service handle when a target has several listeners. A named `session`
retains the actual SSH channel or HTTP client/cookies across CLI calls. Omitting
it uses a fresh client; `operation: close` closes the named session. The broker
uses a private Unix socket and is outside the honeypot process.

SSH supports `exec`/`commands` with `command` or `commands`, and optional username,
password and interactive flag. A multi-command or named-session action uses an
interactive channel. Responses preserve raw/banner/prompt bytes separately from
command output. Commands only reach the honeypot simulation, not a host shell.

HTTP supports `request` with method, target-relative path, version, header pairs
and body/body_base64. Redirects are not followed. Real negotiation is mandatory.
`h2_method`, `h2_resets` (maximum eight streams), and `h3_fin` expose bounded wire
probes; they characterize existing library behavior, not unimplemented CVEs.
Returned body/header bytes are base64 with structured status/event facts.
HTTP/3 clients retain cookie scope/expiry rules. A named client reconnects a closed
QUIC transport with its existing cookie jar; the observation marks
`transport_reconnected`. A request with uncertain completion is never silently replayed.

Installed assessment drivers use the explicit spec `drivers` allowlist and the
`deceive.assessment_drivers` entrypoint group. API version 1 instances declare
`protocols`, declare TCP/UDP `bindings(listener)`, implement async
`execute(endpoint, action, key)` and `close()`, and
return structured observations. Built-ins cannot be replaced. The framework does
not impose URLs/authentication/sessions on other protocols or implement new base
protocols through generated text.

## Reports, repairs and continuation

Run native protocol, product, attacker and consistency reviewers in fresh contexts.
The full report/decision schemas and role briefings are in the skill references.
Each report must match candidate/role/target and cite captured interaction IDs.
New runs default to the frozen `review_rubric: evidence-v2`. A `score_basis`
records the evidence band, observed facts, interaction IDs, and coverage limits.
The controller rejects band/score mismatches and unknown score evidence. Observed
tells require findings; limited coverage belongs in verdict confidence and the
coverage explanation. Band midpoints anchor judgments without forcing a pass.
Every required reviewer must capture evidence from every service and advertised
HTTP version; an unprobed version is a coverage gap. `repeatability.json` reports
panel-median and reviewer-score ranges only for complete assessments of the same
candidate and comparison/rubric revision. These descriptive ranges do not prove
improvement or replace the two-round success predicate.
Historical reports remain readable using their recorded `legacy-v1` rubric;
they are not reinterpreted or mixed into v2 confirmation comparisons.
Reports without active evidence, unknown evidence or stale candidate IDs are rejected.
Verified unresolved findings carry forward when a later reviewer misses them;
only an evidenced controller decision resolves or rejects them. Review scores
and original reports remain unchanged.

```sh
uv run deceive assess record-review --run results/assessment --file reviewer.json
uv run deceive assess end-loop --run results/assessment --decisions decisions.json
uv run deceive assess begin-loop --run results/assessment
```

A failed technical check becomes a finding; intermediate commands do not stop
orchestrating the run just because a candidate is unqualified. Diagnose and
repair at the owning layer, with a failing regression before the fix and sibling
coverage. Existing human-agreed acceptance hashes stay frozen. Correctness is
checked on the external managed endpoint; protected/override cases also exercise
fresh loopback listeners inside the same image and staged candidate. Reports
label these backends rather than pretending the base target was protected.
Generic external state assertions need a network-visible probe; SSH cwd/user/uid
checks use the live channel. Unsupported state assertions fail explicitly.

Code/profile changes during an active attempt invalidate its reviews. Use
`begin-loop --retry` to stop/re-stage/review a new attempt, or repair between
completed loops. State captures working-tree content, not only Git HEAD. Resume
with `assess resume --run ...`; surviving broker sessions remain live. If the
broker must restart, the public state marks session reset, and clients must
reestablish session-dependent observations. Do not mix old reviews with new tests.
To extend a finished run while reusing its retained resources, use
`assess resume --run ... --additional-loops 5`. This records the policy extension;
it does not turn a prior unsuccessful run into a quality pass.

## Scoring and finalization

Realism equals 100 minus synthetic confidence. Verdict confidence is separate.
Until mode defaults to max 20 loops, median realism 85 per required target/group,
two unchanged passing candidates, no unresolved P0/P1, and all correctness/telemetry
checks passing. Missing roles/coverage and unexplained material disagreement
prevent success. Fixed mode honors the requested count instead of early success.

A plateau needs a baseline plus three complete comparable cycles without the
configured gain (default 3 points) or substantive verified progress. Diagnose
variance/deeper issues before `end-loop --confirm-plateau`; plateau is needs-work,
not passed. The system does not invent native-agent token/dollar telemetry.

```sh
uv run deceive assess finish --run results/assessment
uv run deceive assess render --run results/assessment
uv run deceive assess cleanup --run results/assessment --remove
```

Finish stops owned containers and generates `dashboard.svg` and a history copy,
including on partial/cancelled runs. Use `--reason cancelled` or an evidenced
`--reason blocked --note ...` when ending early. By default compatible stopped
containers/images remain reusable. Remove mode deletes only ownership-verified
containers and their dedicated volumes/network, after evidence export. No global
Docker pruning occurs. Run directories are ignored and contain sensitive
authentication/session observations; do not publish them indiscriminately.

The final SVG shows reviewer scores, medians/rolling medians, threshold, deltas,
disagreement, profile/group heatmaps, technical gates, findings and revisions.
Missing/stale results stay gaps. Structured state and per-loop reports reproduce
the chart without model calls. Finalization returns 0 for qualified results,
1 for unmet quality, and 2 for configuration/tool errors; intermediate failed
gates remain actionable results rather than implicit run termination.

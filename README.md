# DECEIVE

DECEIVE is a profile-driven network honeypot. It provides real SSH and
HTTP/HTTPS 1.1, 2, and 3 listeners while simulating application behavior through
YAML rules, virtual baseline content, optional LLM responses, or a combination.
Attacker input never reaches a real shell or host filesystem.

**DECEIVE is a proof of concept, not production-quality infrastructure. Be
cautious about deploying it in a production environment.** Authentication
telemetry intentionally records attempted usernames and passwords.

## Quick start

The standard container includes every built-in protocol and all provider adapters.
The default HTTP profile requires no API key or configuration editing:

```sh
docker build -t deceive:local .
docker run --rm --name deceive -p 8080:8080 -v deceive-data:/data deceive:local
curl http://localhost:8080/
```

The artifact workflow produces an ARM64 image archive and a Python
wheel. After loading an image archive with `docker load`, use its image tag in
place of `deceive:local`. Images are not automatically published to a registry.

JSONL telemetry goes to stdout. `/data` holds generated keys, certificates, and
local readiness status. The container runs as UID/GID 10001. Bind-mounted data
directories must be writable by that account; named volumes work out of the box.

For HTTPS, HTTP/2, and HTTP/3 together:

```sh
docker run --rm -p 8443:8443/tcp -p 8443:8443/udp -v deceive-data:/data \
  deceive:local serve --profile demo-http --https --http-versions 1.1 2 3
curl -k https://localhost:8443/api/status
```

HTTP/3 requires the UDP mapping and firewall access. A demonstration certificate
is generated once and retained in the volume. Supply your own certificate for a
trusted HTTPS identity. Set `advertised_port` in deployment YAML (or
`--advertised-port`) when the external UDP port differs from the internal port.

## Native installation and SSH

Use Python 3.11 or newer on macOS or Linux (including WSL), managed through `uv`:

```sh
uv sync
uv run deceive serve --profile demo-http
```

For generative SSH, install the selected provider extra and choose a model:

```sh
uv sync --extra openai
export OPENAI_API_KEY=YOUR_KEY
uv run deceive serve --profile linux-ssh --provider openai --model YOUR_MODEL
ssh guest@localhost -p 8022
```

The SSH host key is generated on first start and retained under `.deceive/keys`.
Use `--data-dir` or `DECEIVE_DATA_DIR` to choose persistent storage. Add `--analyze`
to enable LLM intent summaries. Without it, summaries use judgement `UNKNOWN`.
A profile using generative fallback must have a provider; deterministic profiles
can run entirely without one.

Deployments and assessment specs can share an ignored `providers.local.yaml` catalog
with a global default and explicit listener overrides. Copy
[`examples/providers.yaml`](examples/providers.yaml), add
`provider_config: providers.local.yaml` to your YAML, and put API keys in its `.env`
file using `DECEIVE_API_KEY=...`. Process environment values take precedence.
Bedrock can continue using a named AWS profile without copying AWS keys into `.env`.
The CLI sends only selected providers' referenced variables to managed containers;
it does not mount the `.env` or provider catalog. See
[shared configuration](docs/configuration.md#shared-provider-settings-and-secrets).

Whole-device SSH packs are available without model credentials:

```sh
uv run deceive serve --profile linux-device
# Also: macos-device, freebsd-device, ios-device
```

They provide private channel state, nested interpreters or device CLI modes,
ordinary commands and bounded terminal applications. Unix packs include a pager,
process monitor, editor and configuration menu fixture. Application changes stay
coherent with command discovery. Supported keys include editor insertion undo and
literal search, and bounded monitor refresh controls. The shared terminal engine
supports editing, history recall, cancellation and resize. Pager search cancellation
retains its application; IOS uses inline paging and configurable terminal length.
Monitor resource figures and IOS interface views share authoritative virtual facts.
Editor saves use normal LF text-file termination; long-file pager movement changes
the viewport, and virtual CPU totals accumulate across refreshes. See
[whole-device sessions](docs/device-sessions.md) for supported behavior and limits.
Transient SSH model failures return an ordinary error while retaining the private
channel state. `Model attempt failed` records identify the provider/model, request,
attempt and sanitized exception class; a correlated deterministic final response
records the delivered failure bytes. IOS interface and installed-route views agree
when a virtual interface is shut down. FreeBSD uses its native `amd64` machine label.
Copy `examples/testing.yaml` to ignored `testing.local.yaml` for explicit online
model checks; automated CI remains offline. Model smoke never implies independent
realism qualification.

The bundled `linux-ssh` version 5 requests structured model replies so stdout,
stderr and command exit status remain separate. Output bytes retain their trailing
newlines, including commands that emit none. Interactive terminals display both
streams before the server-owned prompt; `echo $?` and bare `exit` use the previous
command status. Existing custom and migrated profiles keep text replies unless
they select `ssh_response_format: json`. See the [SSH reply contract](docs/profiles.md#ssh-model-replies).
Its opt-in `virtual_files` behavior uses one bounded private view for basic file
reads, listings and supported mutations, so generated commands receive the same
current file facts. It does not implement a complete shell or filesystem.
The profile also guides the model to preserve ordinary stdout when a failing command
emits diagnostics on stderr; this remains generative behavior rather than a full
command implementation.
Single-file `wc -c`/`wc --bytes` uses the current virtual bytes deterministically,
including private writes and UTF-8 content, so byte counts agree with file reads.
Literal-only `printf` (one format argument without escapes/expansion, including
`%%`) preserves output bytes and reports an unfinished `%` with partial stdout,
stderr and status 1. Richer formats remain on fallback. Bare interactive `history`
lists only the session's bounded input transcript; fresh non-interactive commands
have empty history. History options and host history files are outside this support.

Bedrock uses the same deployment YAML provider configuration. Install the native
extra with `uv sync --extra bedrock`, then select the provider from your SSH
listener and run `deceive serve --config deployment.yaml`:

```yaml
providers:
  default:
    kind: bedrock
    aws_profile: YOUR_AWS_PROFILE
    region: us-east-1
    model: YOUR_MODEL_OR_INFERENCE_PROFILE_ID
    max_output_tokens: 2048
    temperature: null
```

These are operator-selected settings. Omit `aws_profile` to use the default AWS
credential chain, including an AWS workload role. The SSH listener example in
`examples/deployment.yaml` selects the named provider with `provider: default`.
Container deployments must make their AWS credentials/role available inside the
container; a host-only profile is not automatically available there.

The same SSH command can run in the standard container by passing
`-e OPENAI_API_KEY` and mapping port 8022. Keys and API credentials are never built
into the image.

The sudo and Apache reference CVE profiles run without a model or API key:

```sh
uv run deceive serve --profile sudo-2019-14287
uv run deceive serve --profile apache-2021-41773
```

The sudo profile exposes the agreed CLI probes and simulated UID bypass over SSH
on port 8022. The Apache profile exposes single-encoded traversal to declared
virtual files over HTTP/1.1 on port 8080. They do not run vulnerable software or
execute payloads. See their [approved criteria](docs/reference-acceptance-proposal.md).
Interactive SSH accepts Enter, requested echo, cursor editing, history recall,
completion and cancellation. Nested exit returns to the parent interpreter.
Complete PTY discipline and shell compatibility remain outside the bounded emulation.
The sudo and sshhole profiles now include virtual home content and basic navigation.
Their declared CVE interactions stay deterministic without credentials. With an
explicitly configured provider, unfamiliar commands use bounded model fallback
guided by the same virtual identity and files; model-free mode retains a limited
fallback. Neither mode executes commands on the host.
The sudo profile also exposes profile-owned `/bin` and `/usr/bin` inventories.
`python` and `python3` open a bounded virtual Python 3.7 prompt with simple
expressions, printing, virtual directory listings and virtual file reads. This is
not a general Python interpreter; unsupported code cannot execute on the host.
The inventory is an initial device fact, not an allowlist for model-backed
interaction. With a provider selected, unfamiliar commands and Python statements
can receive model replies. Validated model proposals can add private virtual
executables and files; later listings and discovery use that same private state.
Without a provider, unsupported interactions return the declared fallback.
For CLI-only startup, select a shared local provider catalog without another
deployment file:

```sh
uv run deceive serve --profile sudo-2019-14287 \
  --provider-config providers.local.yaml --preflight
```

The catalog's global default chooses the provider; the public profile contains
no model or credential choice.
Sudo profile/suite version 2 uses the human-approved stock-style denial wording;
the original version 1 criteria and agreement remain in packaged history.
The model-free `sshhole-2026-123158` profile emulates the Alpine/OpenSSH musl
password-authentication bypass with real SSH authentication. `deploy` and
`backup` have `*` shadow markers; `admin` supplies the separate password-hash
prerequisite. Root password login stays prohibited by default, while the
acceptance suite tests an explicitly enabled root variant. For example, a
300-byte ASCII password succeeds for `deploy` where a 256-byte one fails:

```sh
uv run deceive serve --profile sshhole-2026-123158
ssh deploy@localhost -p 8022
```

See its [approved behavior and limits](docs/sshhole-acceptance-proposal.md).
This emulates the authentication outcome and virtual Alpine facts; it does not
run a vulnerable OpenSSH build or execute commands on the host.
Creating a deception now includes an active, research-backed realism assessment
after deterministic acceptance. The authoring skill hands the new profile to
the separate assessment skill for bounded reviewer, repair and confirmation
loops, with a dashboard even when quality remains unmet. Research-only or draft
requests do not start a run. See [active assessment](docs/assessment.md).
To run both in one process, use
`uv run deceive serve --config examples/reference-deployment.yaml`.

For an installed command outside a checkout, build a wheel with `uv build --wheel`
and install it using `uv tool install dist/deceive-0.1.0-py3-none-any.whl`. Provider
extras are `openai` (also Azure), `ollama`, `bedrock`, `gemini`, and `all-providers`.

## Deployment and profiles

Schema version 2 profiles can define required HTTP/command contracts, typed
customization parameters with usable defaults, and optional organization values.
The fictional `workbench-http-linux`, `workbench-http-cmd`, `workbench-http-ps51`
and `workbench-http-ps7` examples run without a model and exercise the shared
virtual command service over HTTPS 1.1, 2 and 3:

```sh
uv run deceive profile show workbench-http-linux
uv run deceive config validate --config examples/contracts-deployment.yaml
uv run deceive serve --profile workbench-http-linux
```

Use `--organization FILE` to supply shared values. Deployment YAML supports
distinct instance IDs and per-instance organization/parameter overrides. Required
interactions can use deterministic responses or checked model replies with one
bounded repair and optional deterministic fallback. Version 1 profiles and
approved CVE suites retain their existing semantics. See the
[contract and customization guide](docs/behavior-contracts.md) for authoring,
state/command limits, inspection and evaluation of bound instances.

Install the operator, authoring and assessment skills into your agent's user
directory from the host CLI:

```sh
deceive install-skills                  # Both agents (default)
deceive install-skills --agent claude
deceive install-skills --agent chatgpt
deceive help
deceive help profile evaluate
```

Use `uv run deceive` instead of `deceive` in a checkout. Claude Code skills go to
`~/.claude/skills`; the local ChatGPT/Codex agent uses `~/.agents/skills`.
Rerunning synchronizes managed skills: updates existing files, adds new skills
and removes obsolete managed skills/references. Unrelated files are preserved.
Local edits cause an actionable conflict before installation; `--force` explicitly
replaces conflicting files. The wheel bundles the skills and reading assets,
so no checkout or download is needed for installation. Start a new agent session
if skills are not yet visible. Every command also accepts `-h` and `--help`.
See [installation and updates](docs/operations.md#install-and-update-agent-skills).

Discover and inspect profiles with `deceive profile list` and `deceive profile
show ID`. Add `--directory DIR` for an authored catalog and `--json` for a
versioned operation result. Named background deployments use the standard image:

```sh
uv run deceive deployment start demo --profile demo-http --image deceive:local
uv run deceive deployment status demo --json
uv run deceive deployment stop demo
uv run deceive deployment start demo
```

Managed deployments run provider preflight inside the container before opening
listeners. Explicit `--skip-preflight` is available when creating a new deployment;
static checks always run. Already-ready deployments do not repeat billable checks.
Managed deployments publish on localhost by default, retain one data volume,
and reuse stopped containers. They use a local image without pulling/building
at startup. See [operator commands](docs/operations.md) for composition, port
mapping, provider credentials, replacement and ownership-scoped removal.
The repository [deceive umbrella skill](skills/deceive/SKILL.md) connects discovery,
running, validation, profile creation and active assessment through chat.

For several listeners or custom settings, copy `examples/deployment.yaml`, edit
it, and run:

```sh
uv run deceive serve --config deployment.yaml
```

Select several deceptions on the CLI by repeating `--deception` (`--profile` is
an alias). Selections add to those in a configuration file; identical profiles
are selected once. Profiles declaring the same compatible base can share a
listener. Validate the complete selection before running it:

```sh
uv run deceive config validate --config examples/composition-deployment.yaml \
  --deception examples/profiles/diagnostics.yaml
uv run deceive serve --config examples/composition-deployment.yaml \
  --deception examples/profiles/diagnostics.yaml
```

This example combines two independently authored profiles on one HTTPS listener
supporting HTTP/2 and HTTP/3. Validation prints the resolved listener plan and, by default, checks selected model
providers with bounded live requests. Use `--offline` for static checks without
credentials or provider calls. Neither mode opens listeners or creates runtime files. `serve`
always repeats compatibility validation before opening any listener. Conflicts
fail with a nonzero exit code; profile order never silently resolves a conflict.
Existing standalone profiles continue to work and use separate listeners unless
explicitly authored for composition.

Mount the YAML and its profile assets read-only into a container and pass
`serve --config /config/deployment.yaml`. Set `data_dir: /data` in that file.
File paths resolve relative to the YAML that owns them. Credentials use named
environment variables or mounted files; AWS uses its standard credential chain.

Profiles specify fixed system identity and baseline virtual content. Connections
see the same baseline but receive private, temporary session state. There is no
shared mutable filesystem or persistence of attacker changes.

See [configuration](docs/configuration.md), [profiles and extension interfaces](docs/profiles.md),
and [evaluation and authoring](docs/evaluation.md). The repository authoring skill
is [deceive-author](skills/deceive-author/SKILL.md).

Authoring and refinement include source-linked [research dossiers](docs/deception-research.md)
beside the bundled deceptions. Research-backed assessment uses these independent
product/platform comparisons in addition to functional contracts; unassessed
realism remains a gap rather than a default passing score.

## Migrating the SSH-only version

The old entrypoint prints migration guidance. Convert your INI explicitly:

```sh
uv run deceive config migrate SSH/config.ini --output-dir migrated
uv run deceive serve --config migrated/deployment.yaml
```

Original files are unchanged. Review `migration-report.txt`, credential settings,
identity facts, and old prompt formatting before running. Existing SSH account
semantics are retained: empty passwords disable password authentication for that
account, `*` accepts any password, and unknown users accept any password.

## Logging and evaluation

Session events retain UTC millisecond timestamps, endpoint addresses, `task_name`
IDs, sensor fields, and base64 input/output details. Deterministic output is a
`Deception response`; actual model output is an `LLM response`. One `Session
summary` is emitted per connection, covering its private channels. Intent analysis is optional and failures produce
`UNKNOWN`. HTTP records also preserve binary body content and structured request
metadata; these are not raw packet captures.
SSH responses add base64 `ssh_stdout`/`ssh_stderr` and numeric `ssh_exit_status`.
For structured model replies, `LLM response.details` retains the raw model JSON
rather than just the terminal text. Consumers comparing wire output should use
the stream fields.
Canonical decimal status strings from text-only models are normalized before
strict validation; other malformed replies remain failures. Assessment audits
keep interactive and exec output separate and require a distinct captured request
for each SSH observation.
Rejected structured SSH replies are recorded as `response_stage: attempt` with
their raw model text. The delivered `Session unavailable` failure is a separate
deterministic final response with the same request ID, exact stream bytes and
exit status 1; the session closes without another model call.

```sh
uv run deceive profile validate demo-http
uv run deceive profile evaluate demo-http \
  --suite deceive/acceptance/demo-http.yaml --report-dir /tmp/deceive-evaluation
```

The corresponding reference suites are
`deceive/acceptance/sudo-2019-14287.yaml` and
`deceive/acceptance/apache-2021-41773.yaml`. Substitute the profile and suite names
in the evaluation command. Packaged approval metadata freezes their fingerprints.

Evaluation starts real local listeners, writes transcripts/results/fingerprints,
and exits unsuccessfully if required assertions fail. Generative evaluation
requires explicit `--live-model --config ...`; ordinary tests never call a live
provider.

New vulnerability behavior requires [automated tests first](docs/vulnerability-testing.md),
including a recorded failing run and agreed, frozen acceptance criteria.
Bundled CVE suites are discovered automatically in local and artifact checks.
See the [HTTP/2–3 capability findings](docs/protocol-capability-findings.md) and
the [active assessment contract](docs/agentic-assessment.md).

The [active assessment tooling](docs/assessment.md) provides `deceive assess`
lifecycle/probe/report helpers and a repository
[deceive-assess skill](skills/deceive-assess/SKILL.md) for native independent
reviewers and repeated repairs. Docker targets are exposed only on localhost;
the skill preserves current edits and does not commit or push automatically.
Start with [the research-backed assessment example](examples/assessment-research.yaml).
Correctness, realism and telemetry remain separate; every finalized run produces
an SVG dashboard. New runs use `research-v4`: independent source-linked comparisons,
evidence-backed criterion ratings, frozen workflow coverage and major/subtle
known-defect controls for every reviewer/protocol family. Missing evidence or failed calibration means
`insufficiently_assessed`, never a passing default. Legacy scores remain readable
but cannot confirm modern realism quality. The separate assessment skill owns
this workflow; the umbrella skill routes to it. New assessments default to schema 2 and require
`assess plan` before reviewer probes and `assess audit` before loop closure.
Dashboard gap labels distinguish review, harness, infrastructure and target issues.

## Development and verification

```sh
uv sync --all-extras
uv run --all-extras pytest
uv build --wheel
uv run python scripts/verify_wheel.py dist/deceive-0.1.0-py3-none-any.whl
uv run --all-extras python scripts/container_smoke.py deceive:local
```

CI requires actual HTTP/3 tests. Container CI builds and exercises the ARM64
image, retaining measurement reports and an image archive. AMD64 is a deferred
optional enhancement. Publication,
merging, and deployment remain separate actions.

Container checks compare installed package files with the candidate source and
exercise a source-only rebuild with warm Docker/uv caches. The project wheel is
explicitly reinstalled during image builds; dependency layers remain cached.
HTTP/3 acceptance clients preserve HEAD response metadata without expecting body
bytes; source and installed-artifact checks cover that behavior and ordinary
content-length validation.

## License

MIT. See [LICENSE](LICENSE).

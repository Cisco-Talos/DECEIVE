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

The bundled `linux-ssh` version 3 requests structured model replies so stdout,
stderr and command exit status remain separate. Output bytes retain their trailing
newlines, including commands that emit none. Interactive terminals display both
streams before the server-owned prompt; `echo $?` and bare `exit` use the previous
command status. Existing custom and migrated profiles keep text replies unless
they select `ssh_response_format: json`. See the [SSH reply contract](docs/profiles.md#ssh-model-replies).
Its opt-in `virtual_files` behavior uses one bounded private view for basic file
reads, listings and supported mutations, so generated commands receive the same
current file facts. It does not implement a complete shell or filesystem.

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

Two reference CVE profiles also run without a model or API key:

```sh
uv run deceive serve --profile sudo-2019-14287
uv run deceive serve --profile apache-2021-41773
```

The sudo profile exposes the agreed CLI probes and simulated UID bypass over SSH
on port 8022. The Apache profile exposes single-encoded traversal to declared
virtual files over HTTP/1.1 on port 8080. They do not run vulnerable software or
execute payloads. See their [approved criteria](docs/reference-acceptance-proposal.md).
Sudo profile/suite version 2 uses the human-approved stock-style denial wording;
the original version 1 criteria and agreement remain in packaged history.
To run both in one process, use
`uv run deceive serve --config examples/reference-deployment.yaml`.

For an installed command outside a checkout, build a wheel with `uv build --wheel`
and install it using `uv tool install dist/deceive-0.1.0-py3-none-any.whl`. Provider
extras are `openai` (also Azure), `ollama`, `bedrock`, `gemini`, and `all-providers`.

## Deployment and profiles

Discover and inspect profiles with `deceive profile list` and `deceive profile
show ID`. Add `--directory DIR` for an authored catalog and `--json` for a
versioned operation result. Named background deployments use the standard image:

```sh
uv run deceive deployment start demo --profile demo-http --image deceive:local
uv run deceive deployment status demo --json
uv run deceive deployment stop demo
uv run deceive deployment start demo
```

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
supporting HTTP/2 and HTTP/3. Validation prints the resolved listener plan without
opening sockets, creating data files, or contacting model providers. `serve`
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
summary` is emitted per session. Intent analysis is optional and failures produce
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
Start with `examples/assessment.yaml`. Correctness, realism and telemetry results
remain separate, and every finalized run produces a graphical SVG dashboard.
New runs use the versioned `evidence-v2` scoring rubric, require cited score
evidence and coverage of each advertised HTTP version, and export repeatability
ranges for repeated reviews of an unchanged candidate.

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

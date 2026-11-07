# Deployment configuration

Deployment and profile YAML use `schema_version: 1`. Unknown fields, duplicate
mapping keys, executable YAML tags, unsupported capabilities, mismatched protocol
versions, and missing providers are rejected before listening. YAML files are
limited to 4 MiB. The operator-controlled YAML and installed extensions are trusted;
attacker input is not configuration.

Start one or more profiles with repeatable `--deception NAME` / `--profile NAME`,
or use `serve --config deployment.yaml`. CLI selections are additive with YAML
`deceptions` and explicit listener profiles. Identical ID/version/content selections
are deduplicated; different definitions of the same ID are rejected. CLI profile
paths resolve from the working directory; YAML paths resolve from their owning file.
The YAML can contain only operational settings when all deceptions are supplied
on the CLI; validation applies to the combined configuration.
Listener/provider overrides cannot be combined with `--config`; `--data-dir` can.

`deceive config validate` accepts the same selection flags as `serve`. By default,
it validates the resolved runtime configuration and makes one bounded synthetic
request per distinct selected provider configuration. This verifies credential loading,
model access and acceptance of the configured inference parameters through the real
adapter. It does not open listeners or create runtime data/log/key files. Network
connections and billable model calls are expected when providers are selected.

Use `deceive config validate --offline` for CI, editing and credential-free checks.
This performs static compatibility checks without initializing provider SDKs or
making provider requests, including requests to a local Ollama server. It does not
require credential variables or secret files to exist. Enabled trusted extension
factories/validators are still loaded. Unused providers never receive live checks.

JSON and text output distinguish `offline-valid`, `live-verified`, `not-required`
(no selected providers), and `failed`. Provider checks report aliases, kind, configured
model, elapsed time and numeric token usage; errors identify the initialization or
request stage without SDK exception text, secrets, or response content. Known settings
are statically validated; live success establishes that the tested request worked,
not that a remote backend honored every setting or that deception realism is qualified.
The request uses the configured model, temperature and token limits; inference time is
bounded by the smaller request/provider deadline and concurrency by `llm_concurrency`.

Exit status is 0 for success and 2 for validation/preflight failure. Invalid static
configuration is rejected before any SDK initialization. Port availability and TLS/key
parsing remain startup checks. No validation result is cached to bypass later checks.

Managed `deceive deployment start` enables `serve --preflight` inside the actual
container before any protocol listener opens. Every real restart repeats the check
using that container's retained image, environment, mounts and network. Starting an
already-ready container is idempotent and makes no additional model calls. For a new
managed deployment, `--skip-preflight` explicitly disables live checking; static
validation still runs. This policy is retained with the container; changing it requires
replacing the stopped container. Older retained containers without a recorded
preflight policy must also be replaced before restart. Increase deployment `--timeout` to accommodate slow
models or multiple waves of checks. Native `serve --preflight` provides the same
optional startup gate; plain `serve` retains its existing behavior.

## Automatic selection and composition

```yaml
schema_version: 1
data_dir: ./data
deception_defaults:
  host: 0.0.0.0
  # provider: default
  # analyze: true
deceptions:
  - profile: profiles/metrics.yaml
  - profile: profiles/diagnostics.yaml
```

Profiles declare transport, allowed HTTP versions, preferred/required internal
ports, exact base dependencies, engine capabilities, incompatibilities and state
scope under `requirements` (see [profiles](profiles.md)). Automatic grouping uses
the base content, transport and chosen port; the enabled HTTP versions are the
intersection supported by the base and all members. Empty intersections fail.
The example `examples/composition-deployment.yaml` plus its CLI-selected diagnostics
profile resolves to one HTTPS listener on TCP/UDP 8443 supporting HTTP/2 and HTTP/3.

Automatically named listeners retain their names when compatible deceptions are
added or removed, provided the base, transport and port remain the same. The
existing single-listener CLI retains the name `main` and its key filenames.
Use explicit listener names to retain identity when changing deployment styles.

For certificates, keys, accounts, provider assignment, or explicit port/IP
placement, use `listeners` with either `profile: NAME` or `profiles: [A, B]`.
Each member of a composed listener declares the same base and exact base version.
An additive CLI selection joins a matching explicit base listener; if more than
one listener matches, validation requires explicit placement in `listener.profiles`.
Otherwise it receives an automatically planned listener. Standalone profiles
without a base dependency are not automatically merged with other standalone
profiles. Binding conflicts fail; DECEIVE does not silently choose a different port.

Validation rejects incompatible base versions, identity/files/prompts/fallbacks,
unsupported capabilities/versions, declared incompatibilities, uncertain routing
overlaps, and duplicate TCP/UDP binds (including wildcard addresses). It does not
use DNS during validation; unresolved hostnames sharing a port are conservatively
considered conflicting. Different virtual hosts on the same listener are not yet
an alternative to disjoint application routes. Connection-scoped deceptions
currently require an exclusive listener. Raw protocol hooks remain unsupported;
declaring one as a required capability produces an error.

```yaml
schema_version: 1
data_dir: /data
sensor_name: edge-honeypot
# Optional; omitted means JSONL to stdout.
# log_file: logs/activity.jsonl
providers:
  default:
    kind: openai
    model: YOUR_MODEL
    api_key_env: OPENAI_API_KEY
    temperature: null
listeners:
  - name: ssh
    protocol: ssh
    profile: linux-ssh
    host: 0.0.0.0
    port: 8022
    provider: default
    analyze: true
    accounts: {guest: "", user1: secret, root: "*"}
  - name: web
    protocol: https
    profile: demo-http
    host: 0.0.0.0
    port: 8443
    quic_port: 8443
    advertised_port: 443
    versions: ["1.1", "2", "3"]
```

## Paths, storage and identity

`data_dir`, `log_file`, explicit key/certificate paths, provider secret files, and
profile paths resolve relative to the deployment YAML. Prompt and response assets
resolve relative to the profile YAML. Built-in profiles can be selected by name.
The Python wheel contains their YAML and the demonstration acceptance suite.

One process owns a data directory through an exclusive lease. Generated private
keys use mode 0600. Existing keys/certificates are reused; a missing explicit path
or incomplete generated TLS pair is an error, never a reason to replace a key.
Provide listener `host_key` for SSH or both `cert_file` and `key_file` for HTTPS to
use existing material. Generated certificates are demonstration certificates,
not automatically trusted public certificates.

Fixed facts live in the profile; editing them intentionally changes the baseline
on restart. There are no model-generated persistent identity facts. Separate data
directories are required for independent simultaneous DECEIVE processes.

## Listeners

Names must be unique and contain letters, digits, `_` or `-`. Listeners are enabled
by default; set `enabled: false` to omit one. `host` defaults to `0.0.0.0`. Ports
are required operational choices in deployment files (`port: 0` is supported for
local testing). The CLI defaults to SSH 8022, HTTP 8080, or HTTPS 8443.

HTTP `versions` default to `["1.1"]` and must be allowed by the profile.
HTTP/3 requires HTTPS and UDP. A missing `quic_port` uses `port`; `quic_port: 0`
allocates an independent ephemeral UDP port. `advertised_port` controls HTTP/3
discovery when an external port mapping differs. HTTP/2 over TLS negotiates `h2`;
the application/evaluator records the actual negotiated version.

SSH accepts one process/channel per connection. A connection owns its session
and authentication telemetry. Empty configured passwords allow passwordless
login; fixed values require an exact match; `*` and unknown users accept any
password, including empty. This deceptive behavior is intentional.
SSH output format is owned by the profile (`ssh_response_format: text` or `json`),
not the listener/provider. See [SSH model replies](profiles.md#ssh-model-replies).

Stateless HTTP creates one session per request. Stateful profiles issue opaque
server-generated cookies; unknown client-selected IDs never create chosen session
IDs. Concurrent requests sharing a session serialize behavior transitions.
HTTP/2 or HTTP/3 streams and source IPs are not treated as client identities.

## Providers

Provider `kind` is `openai`, `azure`, `ollama`, `bedrock`, or `gemini`. Configure
`model` explicitly. Native extras install only the desired SDK; the standard
container includes every SDK. No provider is initialized for model-free profiles
unless a listener selects one.

- OpenAI: optional `endpoint`; default credentials use `OPENAI_API_KEY`.
- Azure: `endpoint`, `api_version`, and `model` as deployment name; default
  credentials use `AZURE_OPENAI_API_KEY`.
- Ollama: optional `endpoint` (otherwise the SDK's local default); an optional key
  is passed as a bearer authorization header.
- Gemini: optional `endpoint`; the SDK supports its normal Google/Gemini key
  environment variables.
- Bedrock: optional `region`, `aws_profile`, and `endpoint`; use the AWS standard
  credential chain, including mounted `AWS_SHARED_CREDENTIALS_FILE` or workload
  credentials. `api_key_env`/`api_key_file` are not AWS credential configuration.
  Select an appropriate model or inference-profile ID through `model`.
  An explicit `aws_profile` selects the SDK's named-profile credential chain;
  its saved keys can differ from access keys in another application's environment.
  Compare credential sources before assuming a failed named-profile request means
  every locally configured AWS credential is invalid.
  Blank conversation turns are represented as metadata only in the outgoing Converse
  request, because Bedrock rejects empty text blocks; stored transcripts and
  logged output retain their original content.

For non-AWS providers, `api_key_env` selects a named environment variable and
`api_key_file` selects a mounted UTF-8 secret file. Secret-file content takes
precedence over an environment reference. A literal `api_key` is also accepted in
private YAML, exclusively of the other references, and is excluded from configuration
dumps. Do not put literal API keys in profiles or committed YAML.

Common controls: `temperature` (default 0.2; `null` omits it),
`max_output_tokens` (2048), `context_tokens` (16384), and `tls_verify` (true).
SDK retries are disabled; runtime deadlines and concurrency bound calls. Bedrock
uses bounded thread slots and explicit SDK connect/read deadlines so cancellation
does not create an unbounded backlog of synchronous calls.

History has turn and byte limits, plus a conservative UTF-8-byte token estimate
that reserves output tokens. It may trim more than a model-specific tokenizer.
It does not download local tokenizers. Large prompts that cannot fit fail
explicitly. Provider-specific context sizes must be configured accurately.

`analyze: true` enables LLM summaries and requires a provider. Without analysis,
or when analysis fails, the session still gets one summary with `UNKNOWN`.

### Shared provider settings and secrets

Copy [`examples/providers.yaml`](../examples/providers.yaml) to ignored
`providers.local.yaml` beside your deployment. Add this to each deployment or
assessment specification:

```yaml
provider_config: providers.local.yaml
```

The catalog contains `schema_version: 1`, `providers`, optional `default_provider`,
and optional `env_file: .env`. Inline deployment `providers` may replace individual
catalog aliases; each replacement is a complete definition. A deployment-level
`default_provider` overrides the catalog default. The default fills only omitted
listener providers and `deception_defaults.provider`; explicit aliases override it
and explicit `null` disables it. Set `default_provider: null` to keep an existing
model-free deployment model-free. A composed listener uses one provider; use separate
listeners/deployments for different model selections. Direct-profile assessment
targets inherit the catalog default, while targets naming deployment files use
those files' settings.
When selecting profiles directly on the CLI, use `--provider-config FILE` with
`serve`, `config validate` or `deployment start`. It applies the same global
default without a separate deployment YAML. The catalog is explicit; simply
placing `providers.local.yaml` in a directory does not activate a provider.

In the catalog, `api_key: ${env:DECEIVE_API_KEY}` is a named credential reference,
equivalent to `api_key_env: DECEIVE_API_KEY`. Put `DECEIVE_API_KEY=...` in `.env`.
Other string provider settings, such as `model` or `region`, may use
`${env:NAME}` too; these are resolved after YAML parsing, so values cannot inject
YAML structure. Interpolation is confined to provider settings, never profile or
attacker content. Credential references stay unresolved during offline validation;
missing non-secret setting variables fail validation immediately.

Environment files support comments, single/double quoted single-line values and
optional `export`. Quote values containing whitespace or `#`. Shell commands,
variable expansion and multiline values are not evaluated. Duplicates and malformed
lines fail with line numbers without exposing values. Process environment wins over
the selected file. A provider's own `env_file` overrides a deployment-level
`env_file`, which overrides the catalog's file. Relative paths resolve against the
YAML that declares them. A missing environment file is allowed when the process
environment or AWS credential chain supplies credentials. Files are never loaded
into the host process environment.

`deceive config validate --config deployment.local.yaml` checks selected models live
by default; `--offline` checks structure and compatibility without credentials or
SDK calls. `deceive deployment start NAME --config deployment.local.yaml` resolves
the catalog on the host and injects only selected providers' credential names and
values. Unrelated `.env` entries and unused providers are excluded. Neither the
catalog nor `.env` is mounted. Literal keys become generated environment references
in container snapshots. Direct-profile assessment literals are stored in separate
mode-0600 secret files, outside source checkpoints and serialized configuration.

For Bedrock, continue using `aws_profile` and the AWS chain, with
`--aws-dir ~/.aws` for managed containers or `docker.aws_dir` in assessments.
The explicitly mounted directory remains readable in that container; it is not a
per-profile credential projection. A named profile does not also forward unrelated
AWS access keys. Without a profile, standard AWS key/session/region variables may
come from the selected `.env`, or a workload credential source may supply them.
Updating local configuration does not replace an existing container or change its
retained environment. Stop/remove and recreate it to apply changed credentials.

## Limits

All limits are deployment settings under `limits`:

| Key | Default |
| --- | ---: |
| `input_bytes` (SSH line / HTTP header bytes) | 16384 |
| `body_bytes` | 1048576 |
| `output_bytes` | 1048576 |
| `sessions` | 100 |
| `requests` (active runtime behavior calls) | 32 |
| `idle_seconds` | 300 |
| `total_seconds` | 1800 |
| `request_seconds` | 30 |
| `llm_seconds` | 25 |
| `llm_concurrency` | 4 |
| `history_turns` | 32 |
| `history_bytes` | 65536 |
| `history_tokens` | 12000 |
| `observer_queue` | 128 |

Limits must be positive and bounded where appropriate. Connections, application
sessions and active requests are distinct; protocol libraries also retain their
own handshake/framing state. These controls do not make the proof of concept a
production traffic firewall. Oversized HTTP bodies/headers return 413/431;
capacity, deadline, and response failures return 503/504/502. SSH limit failures
end the simulated session. Mutable session state and history are cleaned up.

## Unified telemetry

Every event has `timestamp` (UTC, millisecond precision), `level`, `task_name`,
source/destination IP and port, `sensor_name`, `sensor_protocol`, `protocol_instance`,
and `message`. Session events add `profile_id`, `profile_version`, and a resolved
profile fingerprint. Input/output events include `request_id`, `behavior` where
applicable, and `interactive`.
`deception_profiles` lists selected profile IDs, versions and fingerprints on
session records; response records add `deception_profile_id` and
`deception_profile_version` for the handler that answered. A composed
`profile_id` identifies the effective composition rather than hiding its members.

`User input` and response `details` are base64. SSH input preserves received bytes;
HTTP input details encode a JSON representation whose raw path, query, headers and
body are themselves base64, so binary content survives. `http_body` also contains
the original body in base64. This representation is not a packet capture or the
original HTTP framing. HTTP response events include status and version.

Actual model output is `LLM response`; deterministic output is `Deception response`.
SSH response records add base64 `ssh_stdout`, base64 `ssh_stderr`, and integer
`ssh_exit_status`. For structured replies, `details` preserves the raw model JSON
(including any surrounding fence), while stream fields describe parsed output.
Interactive clients see stdout followed by stderr; exec clients see separate
channels. Invalid structured replies are logged as `LLM response` with
`ssh_response_error: invalid_format`, without parsed stream fields, then produce
a sanitized session failure. The rejected model text is never sent to the client.
`Session summary.details` remains plain text, with judgement `BENIGN`, `SUSPICIOUS`,
`MALICIOUS`, or `UNKNOWN`. At most one summary is emitted per session. Authentication
events intentionally include attempted usernames/passwords. Provider errors are
sanitized; credentials, configuration contents, and SDK tracebacks are not logged.

`deceive healthcheck --data-dir ...` checks local readiness/PID/heartbeat. It adds
no public route. Status is removed on clean shutdown and stale status fails health.

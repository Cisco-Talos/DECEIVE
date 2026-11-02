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

`deceive config validate` accepts the same selection flags as `serve`. It validates
the resolved runtime configuration, prints listeners/base profiles/deceptions,
and exits 0 for success or 2 for configuration errors. It opens no sockets,
creates no data/log/key files, initializes no provider clients, and calls no
models. Explicitly enabled trusted extension factories/validators are loaded.
Port availability, provider connectivity/credentials, and TLS/key parsing remain
startup checks. `serve` independently reloads the files and performs the same
compatibility validation before any listener binds; a prior validation result is
never used as permission to skip checking.

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

For non-AWS providers, `api_key_env` selects a named environment variable and
`api_key_file` selects a mounted UTF-8 secret file. Secret-file content takes
precedence. Do not put literal API keys in profiles or committed YAML.

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
`Session summary.details` remains plain text, with judgement `BENIGN`, `SUSPICIOUS`,
`MALICIOUS`, or `UNKNOWN`. At most one summary is emitted per session. Authentication
events intentionally include attempted usernames/passwords. Provider errors are
sanitized; credentials, configuration contents, and SDK tracebacks are not logged.

`deceive healthcheck --data-dir ...` checks local readiness/PID/heartbeat. It adds
no public route. Status is removed on clean shutdown and stale status fails health.

# Profiles and extension interfaces

A profile is a versioned YAML document. Deterministic, generative and hybrid
profiles use the same protocol engines. See the packaged `demo-http` and
`linux-ssh` examples. The JSON schema can also be inspected through
`deceive.models.Profile.model_json_schema()`.

```yaml
schema_version: 1
id: small-api
version: "1"
protocol: http
http_versions: ["1.1", "2", "3"]
identity: {hostname: api.build.example}
stateful: true
cookie_name: session
behaviors:
  - id: authenticate
    match: {path: /login, method: POST, body_contains: demo-password}
    transition: {authenticated: "yes"}
    reply: {status: 200, body: "Welcome\n"}
  - id: private
    match: {path: /private, state: {authenticated: "yes"}}
    reply: {status: 200, body: "Internal dashboard\n"}
fallback: reject
fallback_reply: {status: 404, body: "Not found\n"}
limitations: [This profile models only the declared routes.]
```

Rules run in declared order. A matching handler returns a response and optional
state transition; otherwise dispatch continues. `fallback: reject` returns the
declared fallback response. `fallback: llm` requires a listener provider. All
sessions have transcripts, including deterministic responses, so later model
calls and intent summaries receive the applicable bounded context.

## Independently authored deceptions

A deception can declare its own requirements and depend on a standalone base:

```yaml
schema_version: 1
id: diagnostics
version: "1"
requirements:
  protocol: https
  http_versions: ["2", "3"]
  base_profile: demo-http
  base_version: "1"
  preferred_port: 8443
  capabilities: [http.requests, 'behavior:rule']
  scope: request
behaviors:
  - id: diagnostics
    match: {path: /api/diagnostics, method: GET}
    reply: {body: '{"workers":4}'}
```

`protocol` and `http_versions` at the top level are derived from requirements
when omitted; contradictory duplicates are rejected. HTTPS uses the HTTP behavior
engine. `base_profile` resolves relative to this profile (or by built-in name);
`base_version` is an exact version, not a range. Nested base dependencies are
currently rejected. Standalone profiles may also declare requirements without a
base, as the reference CVE profiles do.

`preferred_port` is a default; `required_port` is an internal listener constraint
and takes precedence. External container mappings are operator-owned. Requirements
can also declare `incompatible_with: [profile-id]` and `scope: request`, `session`,
or `connection`. Connection-scoped profiles cannot currently share a listener
with another deception. Built-in capabilities are `ssh.commands`, `http.requests`,
`http.raw_path`, `http.binary_body`, `http.duplicate_headers`, `http.sessions`, and
`behavior:NAME` for enabled handlers. Unknown capabilities fail validation, including
raw frame/QPACK/QUIC event hooks that the engine does not yet implement.

The base owns identity, ordinary behavior and final fallback. Deceptions can add
virtual files; conflicting content or explicit identity facts fail validation.
Explicit fallback/cookie settings must agree with the base. One common prompt
may be supplied; differing prompts are rejected rather than concatenated.
Setting `stateful: true` enables the common application's cookie session, while
each deception's rule state/transition keys are namespaced. Shared mutable state
between deceptions remains deferred.

Every composed behavior needs an explicit routing match, including custom
handlers. The runtime gates the handler on that match. Across different
deceptions, disjoint exact paths, methods or commands prove separation; ambiguous
regular expressions, body/header predicates or catch-all rules fail conservatively.
Duplicate headers can contain both values, so differing header values alone do
not prove separation. Within one authored profile, its declared rule order still
applies. Deception routes run before ordinary base routes; the base then supplies
the fallback. Selection order does not resolve cross-profile conflicts.

Keep acceptance suites per deception and also exercise intended combinations.
Static compatibility checks do not prove arbitrary extension code or model
responses are semantically consistent. The CLI examples in
`examples/composition-deployment.yaml` demonstrate composition without adding CVEs.

## Rules and assets

Each behavior has a unique `id`, `kind` (default `rule`), optional `match`, `reply`,
`transition`, and handler-specific `options`. Built-in ordinary rules and identity
handling do not accept `options`. Matches support exact `command`, full-match
`command_regex`, exact `path`/`method`, required `headers`, `body_contains`, and
required session `state`. Runtime pattern matching and evaluation assertions use
the `regex` library with a 50 ms timeout, so pathological backtracking cannot
occupy the event loop indefinitely. Patterns remain trusted profile content.

Replies support one of UTF-8 `body`, `body_base64`, or profile-relative `body_file`,
plus `status`, header pairs, `exit_status`, and `close`. Header pairs retain
duplicates. HTTP framing/hop-by-hop headers are owned by the adapter. Profile
assets are loaded at startup; no request-selected path can become an asset path.

State transitions contain string keys/values and have bounded size. Session state
cannot change deployment identity. `cwd`, `user`, and `uid` are reserved SSH facts;
other state keys can represent an application's authentication or workflow state.
Mutable state is per session and temporary. A baseline file is a virtual string
fixture, never a reference to a host file.

`prompt` can be embedded, or `prompt_file` can reference a UTF-8 asset. Prompts and
responses can mix with deterministic rules. Runtime system instructions supply
fixed identity and baseline virtual files, require only the current response,
and give the model no tools. SSH banners and shell prompts are server-owned.
HTTP model responses must satisfy the structured reply schema and cannot select
host files. Prompt instructions are not a security boundary for real execution:
the runtime provides no execution capability at all.

## Stable identity and virtual SSH content

`identity` contains hostname, OS, kernel, architecture, username/UID baseline,
SSH version, and banner. `files` maps absolute virtual paths to fixed content.
The `identity` handler supports `hostname`, selected `uname`/`id` forms, `whoami`,
`pwd`, reading declared files, basic directory changes/listing, and shell exit.
It does not implement a real filesystem, shell grammar, binaries, or subprocesses.

SSH profiles can keep arbitrary other commands generative. A CVE profile must
declare its supported command family and fidelity explicitly. A narrow HTTP
deception need not model an operating system at all. Cross-service shared mutable
state and persistent attacker changes are future capabilities.

## Reference vulnerability behaviors

The approved built-ins are `sudo-2019-14287` (SSH) and `apache-2021-41773`
(HTTP/1.1). Their packaged profiles and acceptance suites have the same names.
Protocol/version mismatches are rejected during validation.

Sudo options are `patched` (default false) and `runas_all` (default true).
The profile identity's username is the permitted account. Version/list probes and
`id` with no flag, `-u`, or `-un` are supported, including the documented special
UIDs. Bypass responses do not change the login identity. Other binaries are denied.
`patched: true` advertises the fixed 1.8.28 version and rejects the bypass;
`runas_all: false` represents an unaffected sudoers policy. If changing the policy,
update any virtual sudoers file fixture to agree with it. GID/group fields are
declared simulation fixtures, not a claim of exact sudo/PAM implementation behavior.

Apache options are `protected` (default false), `alias_prefix` (`/cgi-bin/`), and
`alias_root` (`/usr/local/apache2/cgi-bin`, a virtual directory). GET/HEAD traverse
the documented `.%2e` segments using the preserved raw path and a single decoding
pass. Responses come only from `profile.files`; undeclared files return 404.
`protected: true` denies traversal with 403. Double-encoded follow-on variants and
CGI execution are excluded. The reference profile advertises Apache 2.4.49 but does
not reproduce its transport or complete parsing behavior.

## Installed extensions

The extension API version is `deceive.interaction.API_VERSION` (currently 1).
Entrypoint groups are `deceive.protocols`, `deceive.behaviors`, and
`deceive.observers`. Deployment YAML explicitly enables names:

```yaml
extensions:
  observers: [example]
```

Each entry point loads a zero-argument factory/class whose instance has
`api_version = 1`. Installed extensions are trusted executable Python and run in
the process; this is not a sandbox. Profiles cannot import code. Built-in names
cannot be replaced. Disabled/unlisted extensions are never loaded.

- Protocol adapters implement `async start(runtime, listener)` returning a handle
  with `endpoints` and `async close()`; profile protocol names must match their
  listener. The built-in HTTPS alias uses HTTP profile behavior.
- Behavior handlers implement `validate(behavior)` and asynchronous
  `respond(profile, behavior, interaction, session)` returning a typed `Response`
  or `None`. Responses carry explicit origin/behavior, output, and state changes.
- Observers implement `async observe(event)` and receive independent event copies
  through bounded queues. Exceptions/timeouts are logged without exception text;
  overflow drops only optional observer copies, not primary telemetry.

Protocol libraries are infrastructure, not AI-generated profile content. Missing
capabilities must be reported, not disguised with plausible text. The HTTP
adapter's version-constrained Hypercorn integration owns sockets/tasks for
ephemeral ports, admission, readiness, and shutdown; protocol parsing remains in
Hypercorn/aioquic. Raw framing exploits and exact host fingerprints are excluded.

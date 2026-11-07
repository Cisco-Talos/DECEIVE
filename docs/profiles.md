# Profiles and extension interfaces

For schema version 2 parameters, organization/instance bindings, required HTTP
and command contracts, and virtual Linux/Windows command environments, see the
[behavior contract guide](behavior-contracts.md). Existing version 1 profiles
keep the behavior documented below.

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
with another deception. Built-in capabilities are `ssh.commands`, `ssh.structured_responses`, `http.requests`,
`http.raw_path`, `http.binary_body`, `http.duplicate_headers`, `http.sessions`, and
`behavior:NAME` for enabled handlers. Unknown capabilities fail validation, including
raw frame/QPACK/QUIC event hooks that the engine does not yet implement.

The base owns identity, ordinary behavior and final fallback. Deceptions can add
virtual files; conflicting content or explicit identity facts fail validation.
Explicit fallback/cookie/SSH response-format settings must agree with the base. One common prompt
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
SSH replies additionally support UTF-8 `stderr` or binary `stderr_base64`.
The output limit applies to stdout and stderr together.

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
`echo $?` and `echo "$?"` report the previous command status; a successful query
then sets status 0. Blank input preserves status. Bare `exit`/`logout` inherits
the previous status, and `exit N` supports explicit statuses 0–255. Status and
history belong to the connection and are cleared at session end.

SSH profiles can keep arbitrary other commands generative. A CVE profile must
declare its supported command family and fidelity explicitly. A narrow HTTP
deception need not model an operating system at all. Cross-service shared mutable
state and persistent attacker changes are future capabilities.

### Profile-scoped SSH authentication

Schema version 2 SSH profiles may declare `ssh_auth` for a typed, deterministic
authentication policy. The initial supported `kind` is `musl-star-bypass`, used
by the bundled `sshhole-2026-123158` profile. Each account declares a virtual
shadow marker (`*`, `!`, `$5$`, or `$6$`), numeric UID, absolute virtual shell,
and a fixture password only for hash-bearing accounts. The policy also declares
`password_authentication`, `use_pam`, `patched`, and `permit_root_login`.
For an unpatched, no-PAM profile with password authentication enabled and at
least one password-bearing account, a `*` account with a usable shell accepts
257–1024 UTF-8 password bytes. `!`, unknown users, and `nologin`/`false`
shells reject. Root accepts passwords only when `permit_root_login: yes`.
The runtime never reads a real shadow database or passes a password to a model.

The policy is selected per profile and does not change legacy SSH listener
`accounts` behavior for other profiles. For an SSH listener using this profile,
`ssh_auth` supplies its account behavior; listener `accounts` do not override it.
The policy is held fixed for the deployment lifetime. A composed profile must
share its base's auth policy exactly; incompatible policies fail validation.
The public fixture password in a bundled deception is a simulated credential,
not an operator secret. Provider credentials still belong in deployment settings.

## SSH model replies

The profile setting `ssh_response_format` defaults to `text` for compatibility.
Text output is preserved as returned and has exit status 0; the legacy standalone
`YYY-END-OF-SESSION-YYY` sentinel still ends the session. Text that happens to look
like JSON remains literal output. INI migration explicitly retains this mode.

The bundled `linux-ssh` version 3 selects `ssh_response_format: json` and declares
`ssh.structured_responses`. The model returns one object, for example:

```json
{"stdout":"partial","stderr":"permission denied\n","exit_status":1,"close":false}
```

`exit_status` is required and must be an integer 0–255. `stdout` and `stderr`
default to empty strings; `close` defaults to false and ends the login shell when
true. For non-UTF-8 output use `stdout_base64` or `stderr_base64` instead of the
corresponding text. Values must have the declared types; duplicate/unknown fields,
invalid base64, tool requests, file references and state-transition fields fail
validation. A single surrounding JSON Markdown fence is tolerated; explanatory
text outside the object is rejected. Raw model text stays in telemetry.
One narrow formatting normalization accepts a canonical ASCII decimal status
string such as `"1"` and validates it as integer 1. Signs, leading zeros, whitespace,
floating-point spellings, non-ASCII digits and out-of-range statuses remain
invalid. No other fields are coerced and this adds no model retries.

The runtime supplies the same bounded, structured history for deterministic and
generated interactions, including streams and status. Model adapters remain
text-only and expose no tools. This schema improves output transport and status
fidelity; it does not turn generative responses into a complete shell emulator.
Only history represents generative effects such as an exported variable, so
trimming that history can lose those effects.

Exec channels expose stdout and stderr independently. Interactive channels display
stdout followed by stderr before the prompt; arbitrary interleaving of the two
streams is not represented. A requested PTY applies CRLF output translation,
terminal echo and basic Enter/Backspace handling; full PTY line discipline is not
represented. Unsupported/malformed replies end the session with a sanitized
failure. Existing deterministic CVE response wording and stream placement are
unchanged.

## Private virtual file commands

The opt-in `virtual_files` behavior runs before `identity` in bundled Linux SSH
profiles. The `directories` option lists normalized absolute virtual directories,
such as `/tmp` and `/var/tmp`. Baseline files still come from `profile.files`.
An optional `listing_time` supplies one stable ls-style display date for the
profile's virtual listings; it does not implement per-file timestamps.
An optional `executables` list declares virtual paths under `/bin`, `/usr/bin`
or `/usr/sbin`. Listings show them as executable files with fixed small binary
fixtures; they never read or run the container's executables. Installed-command
discovery and supported interpreter entry points use the same declared paths.
The sudo reference profile declares `python` and `python3`, which provide a
bounded Python 3.7 prompt for simple expressions and virtual reads. Arbitrary
Python programs, imports and system calls are outside this interpreter. When a
provider is configured, unfamiliar safe statements use the model in the current
Python context. Forbidden host-execution primitives remain blocked. The initial
executable list is not a complete whitelist for model-backed sessions: validated
model effects can add private virtual programs, visible to `ls` and `which` on
the same channel. Deterministic vulnerability commands retain their priority.
Reads, listings, current directory and supported writes share one connection's
private view; another connection starts from the unchanged baseline. Generative
fallback receives that current view too.

Supported forms are basic `cat` operands, `ls` with a single optional path and
`-l`, `-a`, `-A`, `-1`, `-d`, `-h` flag combinations, `cd`, unflagged `touch`,
`mkdir`, `rm`, and literal `echo`/`echo -n` with spaced `>` or `>>` redirection.
There is no shell expansion, pipeline, symlink or real path access. Other forms
use the profile fallback. Listing names and byte sizes come from virtual content;
ownership/modes and dates are display fixtures, not full permission or timestamp
emulation. Missing-file/directory diagnostics use stderr.

Each session permits at most 128 overlay/deletion/directory entries and 64 KiB of
overlay content. Capacity failures leave the previous view intact. End-of-session
cleanup discards the view. The sudo and sshhole profiles include it for surrounding
host exploration; their agreed vulnerability handlers still take precedence.

`fallback: llm_if_available` keeps deterministic startup when no provider is
configured and uses checked model replies for otherwise unhandled commands when
the listener explicitly selects a provider. The fallback does not promise full
shell or device emulation. Real OpenSSH terminal journeys in
`tests/fixtures/ssh_journeys.yaml` exercise every bundled SSH profile using each
profile's own authentication, prompt and command expectations.

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

## Whole-device SSH packs

The optional `device` declaration selects platform, interpreter, virtual home,
full-screen applications and validated model effects. See the
[device session guide](device-sessions.md) for schemas, state ownership, terminal
support, model actions, telemetry and offline/online acceptance boundaries.
`ssh.device` and `ssh.fullscreen` are additional engine capabilities.

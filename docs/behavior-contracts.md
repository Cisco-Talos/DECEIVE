# Behavior contracts and customization

Schema version 2 adds optional parameters, required interaction contracts and a
shared virtual command service. Version 1 profiles keep their existing behavior.
DECEIVE remains a proof of concept. No command reaches a real shell or filesystem.

## Start with defaults

```sh
deceive profile show workbench-http-linux
deceive profile validate workbench-http-linux
deceive config validate --deception workbench-http-linux
deceive serve --deception workbench-http-linux
```

The four fictional Workbench examples are `workbench-http-linux`,
`workbench-http-cmd`, `workbench-http-ps51`, and `workbench-http-ps7`. They select
HTTPS, default port 8443, and support HTTP/1.1, 2 and 3. Map both TCP and UDP for
HTTP/3. Each profile runs without a provider and supplies organization, tenant
and hostname defaults. Workbench is a fictional administration application,
not a claim of a newly emulated CVE. Its command API is intentionally explicit.

```sh
curl -k https://localhost:8443/api/demo/status
curl -k https://localhost:8443/api/demo/command -X POST \
  -H 'Content-Type: application/json' -d '{"command":"workbench status"}'
```

Use a cookie jar (`curl -c cookies -b cookies`) to retain private application files.
The returned JSON includes stdout/stderr, their base64 encodings, and exit_status.
A command's exit ends only that invocation. Every invocation starts from the
configured home/environment/status; files persist only in its cookie session.

## Defaults, organizations and instances

An authored profile declares parameters, each with a valid default:

```yaml
schema_version: 2
id: example-api
protocol: http
parameters:
  organization_name: {type: string, default: Example Industries}
  tenant_id: {type: string, default: demo, pattern: '[a-z][a-z0-9_-]{0,31}'}
identity:
  banner: Welcome to ${organization_name}
contracts:
  - id: status
    http: {method: GET, path: '/api/${tenant_id}/status'}
    reply:
      body_json: {organization: '${organization_name}', ready: true}
```

Parameter types are string, integer, number and boolean. Constraints include
enum, minimum/maximum, pattern and max_length. Boolean values do not count as
integers. Types are preserved when a whole structured value is a placeholder.
Base parameters are inherited; incompatible redeclarations fail.

An optional organization file contains shared public facts:

```yaml
schema_version: 1
id: acme
version: '1'
values:
  organization_name: Acme Research
  tenant_id: acme
```

Resolution is profile defaults, selected organization values, then instance
parameters. Extra organization keys are allowed for reuse by other profiles;
unknown instance override names fail. Each instance may select a different
organization, replacing the deployment default:

```yaml
schema_version: 2
organization: ./organization.yaml
listeners:
  - name: linux
    protocol: https
    port: 8443
    versions: ['1.1', '2', '3']
    profile:
      profile: workbench-http-linux
      id: operations-linux
      parameters: {hostname: ops-node-01}
```

The same selection object works in `deceptions` and `listener.profiles`.
Existing string listener selections and `{profile: NAME}` deception selections
remain supported. Distinct bound copies require distinct instance IDs.
Composition validates the resolved routes and facts; a different instance ID
does not waive an identity, port or route conflict. The current engine does not
provide virtual-host routing for incompatible copies on one listener.

`--organization FILE` selects the default for `serve`, `config validate` and
`deployment start`, including additive YAML/CLI selections. Explicit instance
organizations win. `profile show` and `profile validate` accept the same flag.
`profile evaluate PROFILE --config FILE --instance ID --suite SUITE --report-dir DIR`
selects a bound instance. Include `--live-model` only for intentional model use.

`config validate --json` reports effective values, origins, instance IDs and
fingerprints without opening listeners. Startup repeats validation. Managed
containers and assessment snapshots embed resolved content, complete bases and
assets; retained deployments keep their original binding until replaced.

## Substitution and assets

`${name}` substitutes a declared parameter once; `$${name}` emits literal text.
Runtime placeholders use `request.*`, `command.*` or `session.*`. Replacement
values are never evaluated recursively. There are no expressions, loops,
environment expansion or model tools.
A rendered value tree is capped at 8 MiB while substitutions are built; normal
configured response/file limits still apply afterward. Windows command baselines
must use normalized absolute paths and cannot declare conflicting file names
that differ only by case.

Templates apply only to content: identity, prompts/banners, virtual paths/files,
request matches, replies, guidance and declared effects. JSON is serialized as
structured data, Location captures are URL-escaped, and response headers are
validated. Parameter insertions in regex fields are literal-escaped.

Use inline prompt/body content, `prompt_file`, or `body_template_file` in a
contract/behavior reply for a UTF-8 text template. Paths resolve from their owning
YAML. `body_file`, body_base64 and stderr_base64 are binary and are not templated.
Substitution cannot select host assets, protocols, extensions or providers.

## Required HTTP behavior

Each contract owns one method/path operation. Path segments such as `{job_id}`
capture values available as `${request.path.job_id}`. Query/header/cookie and
JSON-field requirements are exact constraints; nested JSON fields use dot paths.
Single query values are available as `${request.query.key}`, headers as
`${request.headers.name}`, cookies as `${request.cookies.name}`, and scalar JSON
fields as `${request.json.key}`. Duplicate query values do not select one value.

```yaml
contracts:
  - id: job
    http: {method: GET, path: '/jobs/{job_id}', query: {key: public}}
    requires: {ready: 'yes'}
    reply:
      body_json: {id: '${request.path.job_id}', status: queued}
      headers:
        - [content-type, application/json]
    error: {status: 400, body: 'Invalid request\n'}
    checks:
      json_types: {id: string}
      json_fields: {status: queued}
    effects:
      state: {last_job: '${request.path.job_id}'}
```

Matched operations reject unmet input/state requirements through their error
reply. Other paths/methods can use ordinary profile fallback. Ambiguous contract
paths fail validation. Keep routes from separate deceptions disjoint.
JSON command endpoints, JSON field requirements and JSON capture references
reject duplicate object keys by default, including nested duplicates. Set
`http.json_duplicates: last` explicitly when the application should select the
last value. Malformed or ambiguous JSON uses the contract's declared error reply
and commits no effects. Version 1 behavior is unchanged.

Checks include exact text/body_base64, contains (list), bounded full-match pattern,
status, headers, stderr, exit_status, json_fields and json_types. Supported JSON
types are string, integer, number, boolean, object, array and null. Dot paths
address nested fields and numeric array positions. These are local typed
assertions, not arbitrary code or remotely fetched schemas.

`mode: model` uses contract guidance, fixed identity/current virtual facts, and
checks. Invalid output gets one bounded repair within the original model/request
deadline. An optional `fallback` reply must satisfy the same checks. Exhausted
validation without fallback produces a service/command failure. Provider errors,
cancellation and timeouts do not trigger model-repair retries.

Effects support bounded string state, virtual file writes and removals. They
commit once after validation; invalid attempts and failures commit nothing.
They cannot alter deployment identity. Models cannot supply effects or assets.
Telemetry preserves actual model output in `LLM response`; failed attempts carry
`response_stage: attempt`. Exactly one delivered result carries stage `final`,
with `response_body_base64`, correlation and profile/instance attribution.

## Virtual commands

Select `command_environment.dialect`: linux, cmd, powershell-5.1 or powershell-7.
Set username, optional home, directories, environment and a programs catalog.
Programs have name, virtual path, optional aliases, help and version output.
Profiles sharing a base can add disjoint program catalogs, directories and
environment entries. Conflicting globals, aliases, definitions or argument cases
fail composition validation. Workflow state and its `session.*` captures are
namespaced per deception; the composed listener shares its private virtual files.
Command contracts match a program plus an argument list. `{name}` captures one
literal argument for `${command.name}`; `${command.args.0}` addresses a position.
Unsupported arguments for a declared program use its contract error reply.

| Dialect | Supported bounded forms |
| --- | --- |
| Linux | Existing identity, status, exit, virtual cat/ls/cd/touch/mkdir/rm, single-file wc -c/--bytes and literal echo redirection; literal-only printf (one format, no escapes/expansion; %% and incomplete %); bare bounded interactive history (empty in non-interactive HTTP/SSH invocations); echo, export NAME=VALUE, which NAME; declared program cases |
| cmd.exe | hostname, whoami, ver, where NAME, cd [PATH], dir [PATH], type PATH, echo, literal echo > or >>, mkdir PATH, del PATH, set [NAME or NAME=VALUE], echo %ERRORLEVEL%, exit [0..255] |
| PowerShell | hostname/whoami, Get-Command NAME, Get/Set-Location, Get-ChildItem [PATH], Get-Content PATH, Set/Add-Content PATH VALUE (or -Path PATH -Value VALUE), New-Item -ItemType File/Directory -Path PATH, Remove-Item PATH, Write-Output, literal redirection, environment/status/exit |

Command support is intentionally bounded. cmd directory and PowerShell object
formatting are simplified. General scripts, expressions, pipelines, registry,
remote providers and arbitrary shell syntax remain outside fidelity claims.
Document a needed exact output through a contract rather than relying on this
subset for a complete operating-system impersonation.

Single-command wrappers support `cmd [/d] /c COMMAND` and
`powershell.exe|pwsh [-NoProfile] [-NonInteractive] -Command COMMAND` on virtual
Windows. No host interpreter is invoked. Windows paths are case-insensitive;
UNC and drive-relative paths are rejected. Windows text output uses CRLF.
PowerShell 5.1 literal output redirection uses UTF-16LE with BOM, Set/Add-Content
uses `command_environment.ansi_encoding` (cp1252 by default, optionally utf-8); PowerShell 7 uses
UTF-8 without BOM. These distinctions follow [Microsoft's encoding documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_character_encoding?view=powershell-5.1).
`shell_version` can supply the version returned by the bounded version query.
`Get-Content` detects Unicode BOMs, and `Add-Content` preserves an existing
file's detected encoding. Without a BOM, appends use the dialect's configured
default; appending does not insert a second BOM. Output redirection retains its
own dialect default, matching the documented distinction from `Add-Content`.
Full formatting and encoding/culture choices beyond the matrix are limitations.

PowerShell `type PATH` uses the same logical text decoding as `Get-Content PATH`;
use `cmd /d /c type PATH` to inspect raw file bytes. Interpreter wrappers preserve
quoted paths, apostrophes and empty literal arguments. Windows literal `>`/`>>`
can be adjacent to text or filenames; quoted operators remain data. Only one
trailing literal redirection is supported; descriptor redirection and pipelines
remain excluded. `Get-Command type` identifies the PowerShell text alias.
These conventions are documented in the
profile research dossiers rather than inferred solely from passing contracts.

Workbench profile version 2 explicitly declares HEAD companions for its read-only
landing, status and job routes. They return GET-equivalent status/metadata without
response content. This is profile configuration, not an implicit rewrite of every
GET contract. POST command endpoints are unchanged.

HTTP command endpoints set `endpoint: {source: query|form|json, field: command,
response: json|text}` on a deterministic HTTP contract. Extraction is explicit;
other request text never becomes a command. SSH interactive process state
persists within that shell. HTTP process cwd/environment/status reset per request;
only configured cookie application/files state can persist. No cross-service
mutable state is introduced.

## Author and assess

Use `deceive-author` to gather required interactions, defaults, expected outputs,
state effects and fidelity limits, then create independent acceptance tests.
Contract checks are not the sole test oracle. New CVEs still require research,
human agreement, a frozen suite and a meaningful failing test before behavior.
Use `deceive-assess` for requested active realism/repair loops on the exact bound
instances. Keep telemetry/correctness gates separate from realism scores.

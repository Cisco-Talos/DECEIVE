# DECEIVE operator interface

The `deceive` CLI supplies deterministic operations; the repository
[deceive skill](../skills/deceive/SKILL.md) connects them through natural-language
requests. Authoring and reviewer/repair loops remain in their existing skills.
No agent service, new dependency, public management endpoint or mandatory model
is introduced. `serve` remains the foreground/native execution path.

## Find and validate profiles

```sh
deceive profile list
deceive profile list --vulnerabilities --json
deceive profile list --directory ./profiles --protocol https
deceive profile show sudo-2019-14287 --json
deceive profile show custom-id --directory ./profiles --json
deceive profile validate ./profiles/custom.yaml --json
deceive config validate --config deployment.yaml --deception demo-http --json
```

The catalog discovers packaged profiles and top-level `.yaml`/`.yml` files in
each explicitly supplied directory (repeatable). It resolves bases and relative
assets without starting listeners or contacting providers. Identical definitions
are deduplicated; conflicting definitions of an ID fail. It does not register or
copy local profiles globally. Author custom base dependencies as relative paths
or built-in references, using the existing profile format.

`show --json` includes the authored definition with omitted defaults preserved,
its fingerprint, resolved identity/files, transport, base requirements, behavior
kinds, references and fidelity limits. Discovery/validation does not establish
that network ports or provider credentials will work at startup.

## Named Docker deployments

Load or build the standard image first. Starts use only local image contents;
there is no automatic pull, build or dependency installation.

```sh
deceive deployment start demo --profile demo-http --image deceive:local
deceive deployment list --json
deceive deployment status demo --json
deceive deployment stop demo
deceive deployment start demo
deceive deployment stop demo
deceive deployment remove demo
```

Names begin with a lowercase letter and contain lowercase letters, digits,
underscores or hyphens, at most 64 characters. Each deployment owns one container,
a dedicated bridge network and one persistent data volume. It can contain many
listeners/profiles. YAML and repeatable CLI `--deception` selections are additive
exactly as with `serve`, and the full selection is validated before resources
are created. The container repeats validation at startup.

The manager records an immutable local image ID and materializes a snapshot of
complete profiles, bases, embedded prompts and binary assets. The snapshot is
mounted read-only; editing an authored file does not change a running container.
Installed extensions must already be present in the selected image and explicitly
allowlisted in deployment YAML.

Publishing defaults to host `127.0.0.1`, independently of listener addresses in
YAML. Container listeners bind `0.0.0.0` so Docker can forward to them. Use
`--publish-host IPV4` for a deliberate different host binding. For CLI-only
selection `--host` is also accepted for that binding; with `--config`, use
`--publish-host`. Original listener ports become host/internal ports; keep
internal ports at least 1024. `--publish LISTENER=PORT` overrides external ports
without changing protocol requirements. Unknown/duplicate listener overrides
fail. Port zero allocates an ephemeral host port and a high internal port.

```sh
deceive deployment start reference --config examples/reference-deployment.yaml \
  --image deceive:local --json
deceive deployment start web --profile demo-http --https --http-versions 1.1 2 3 \
  --port 0 --publish main=0 --image deceive:local --json
```

HTTPS/3 publishes both TCP and UDP. The manager sets `advertised_port` to the
published UDP port, including when ports are allocated dynamically. It verifies
Docker's actual mappings and the private healthcheck before reporting a ready
deployment. Use the reported ports for clients. A port race, failed bind,
unavailable image, invalid mount or startup deadline fails the command; partial
resources remain owned and discoverable for diagnosis/cleanup. No automatic
replacement is performed on failure.

Data always lives in the named Docker volume at `/data`; a YAML `data_dir` is
translated for this backend. CLI `--data-dir` is reserved for `serve`. Omitted
`log_file` retains JSONL on Docker stdout. A configured file destination is
translated to `/data/telemetry.jsonl`, reported in result notes. Docker log files
are bounded to three 10 MiB files. Explicit SSH/TLS keys/certificates are mounted
read-only; generated material stays in the data volume. The container runs with
the image's non-root user, a read-only root filesystem and a bounded `/tmp`.

Stop retains container, snapshot, network and data. `start NAME` reuses them,
including stable keys, certificates, mappings and original environment; it opens
fresh runtime sessions. Starting an already ready unchanged deployment is
idempotent. Changed configuration/image/options are rejected. To change mounted
material, profile content, environment values or configuration, stop/remove the
container and start a replacement; its named data volume is reused by default.
This also makes credential rotation explicit instead of silently retaining old
container environment values.

`remove` requires a stopped container, removes its container/network/record and
retains the data volume and private snapshot history. `remove --remove-data`
also deletes that deployment's data volume. It never deletes authored files or
another deployment's resources. Retain evidence before removing resources.
Missing externally deleted containers are reported as `missing`; they are never
treated as ready. Remove the record before creating a replacement.

Lifecycle commands use `.deceive/managed` by default. Set `DECEIVE_STATE_DIR` or
pass the same `--state-dir DIR` to each command when operating elsewhere. Moving
or losing the registry loses automatic discovery; keep it alongside retained
volumes. Read-only empty listings do not create a registry. Ownership labels,
immutable container IDs and per-deployment locks prevent commands from silently
adopting or stopping unrelated containers. Assessment uses separate ownership
and continues to use `assess cleanup`.

## Providers and credentials

Use existing named provider settings in deployment YAML: model, AWS region/profile,
endpoint, token/context limits and temperature. Active providers' referenced
`api_key_env` variables are forwarded by name, as are present standard provider
credential variables. `api_key_file` and explicit key/certificate paths are
mounted read-only; their contents are never copied into snapshots or results.
`--env NAME` forwards an additional existing environment variable; values in this
flag are rejected. Unused providers are not initialized or forwarded.

For a named Bedrock AWS profile, provide `--aws-dir /path/to/.aws`, mounted
read-only at the image user's `.aws` directory. Configure the AWS profile, region
and model in YAML; authenticate locally before starting. Secrets and credential
files must be readable by UID 10001 in the container; the manager never changes
source permissions. Docker mount source paths containing commas are currently
rejected. A host-only credential process or SSO refresh flow may require a
container-compatible credential arrangement; native `serve` remains available.

## Structured operation results

Add `--json` before or after subcommands for a single versioned result:

```json
{
  "schema_version": 1,
  "operation": "profile.list",
  "ok": true,
  "status": "succeeded",
  "exit_code": 0,
  "data": {"profiles": []},
  "artifacts": [],
  "error": null
}
```

Failures carry an error code/message and a nonzero exit code. Exit 0 means the
operation succeeded, 1 means a completed check/finalization did not qualify,
and 2 means arguments/configuration or execution failed. Assessments can
successfully record a failed gate; inspect their correctness/telemetry/realism,
completeness and qualification fields in `data`. Missing model credentials or
failed readiness are never turned into successful deployment results.

Default human output remains for ordinary commands; existing `assess` raw JSON
is preserved unless `--json` requests the common envelope. `serve` streams session
JSONL and rejects this envelope flag to keep telemetry separate. Use
`deployment start --json` to start a background container with a command result.

Creation uses [deceive-author](../skills/deceive-author/SKILL.md), acceptance uses
`profile evaluate`, and active loops use
[deceive-assess](../skills/deceive-assess/SKILL.md). The umbrella skill routes these
operations; it does not implement a second authoring or assessment engine. Skills
remain repository-local unless separately installed. No PR, merge, publication
or automatic source commit is part of these operations.

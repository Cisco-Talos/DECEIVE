# Defaults and organization binding

Use profile/deployment schema version 2 for parameters and contracts. Every
parameter needs a typed, valid default. A deception must work without an
organization file. Refer to the installed CLI's profile validation and the
[contract guide](../../../docs/behavior-contracts.md) for supported fields.

Ask which public simulated facts should be reusable: organization, hostnames,
tenant names, banners, and baseline content. Keep provider credentials in the
existing deployment configuration. Produce an organization file only if useful.

An organization is schema_version 1, with id, optional version, and values.
Resolution is profile defaults, then the selected organization, then per-instance
parameters. An instance organization replaces the deployment default. Extra
organization keys can serve other profiles; unknown instance overrides fail.

Use `${name}` for configuration values, `$${name}` for literal text. Runtime
captures use separate request.*, command.*, session.* names. There is no template
language, recursive evaluation, environment expansion, or executable code.

Validate both default-only and customized instances. Use distinct instance IDs
for differently bound copies, and check their resolved identities, content,
routes and composition. Keep source profile IDs stable. Exercise the exact
bindings in acceptance and assessment; reports and evidence must identify the
instance and fingerprint, not only its reusable source profile.

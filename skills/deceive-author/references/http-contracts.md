# Required HTTP interactions

Read the [contract guide](../../../docs/behavior-contracts.md). Establish methods,
paths/captures, query/header/cookie/body requirements, prerequisites, success and
error responses, structured fields, bytes, headers and simulated effects.
Distinguish required guarantees from broader fallback behavior.

Method matches are explicit. Decide HEAD policy for readable resources: a HEAD
companion can use the same response definition as GET, with wire content
suppressed by the adapter. Test status, media type and length on actual protocols.
Do not copy command endpoints or mutating effects into HEAD. Distinguish a chosen
resource-specific method policy from a transport defect; GET does not implicitly
add a HEAD contract.

Response headers are a list of pairs, for example
`reply: {body_json: {ready: true}, headers: [[content-type, application/json]]}`.
Acceptance step headers use lists of pairs too: `headers: [[Content-Type, application/json]]`.
The `http.headers` mapping belongs to the profile's match, not its acceptance suite.
JSON command endpoints and JSON
constraints reject duplicate keys by default; choose `http.json_duplicates: last`
only when that is the intended application behavior, and test both controls.

Choose deterministic output for fixed facts. Choose model mode only when useful,
with local guidance and meaningful checks. A model contract gets one bounded
repair; an optional deterministic fallback must satisfy the same checks.
Examples and generated contract checks do not replace independently authored
acceptance tests. Freeze agreed CVE suites before refinement.

For command endpoints, explicitly choose query/form/JSON extraction, field,
response envelope, command environment and account. Web invocations start fresh
processes. Choose stateless requests or cookie-isolated application files/state;
do not infer sessions from IP addresses or HTTP streams. An invocation's exit
cannot end the whole application session.

Cover malformed/duplicate inputs, unmet prerequisites, negative/control cases,
captures, binary output, headers, state sequences, isolation, and intended
composition. Use actual negotiated protocol versions. Report missing engine
capabilities instead of describing a packet exploit as an application response.

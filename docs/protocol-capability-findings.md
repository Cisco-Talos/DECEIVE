# HTTP/2 and HTTP/3 capability findings

These are bounded tests of DECEIVE's current engine, run on loopback on
2026-11-02. They do not implement or certify either proposed CVE. They use no
live model, vulnerable product, real proxy backend or public target.
The source test environment uses Hypercorn 0.18.0, h2 4.4.1 and aioquic 1.7.0
from the lockfile. Re-run these probes when protocol dependencies change; native
wheel installation can select newer compatible dependencies.

Run with:

```sh
uv run pytest tests/test_protocol_capabilities.py -v
```

The test client can send selected malformed fields; the server libraries retain
their existing validation. All connections use real TLS/HTTP negotiation and
ephemeral ports. Tests inspect wire outcomes, ASGI entry and DECEIVE telemetry.

| Probe | Observed behavior | Implication |
| --- | --- | --- |
| HTTP/2 method containing CR/LF/NUL | Connection closes with HTTP/2 `PROTOCOL_ERROR`, before ASGI/profile input | These specific inputs are unavailable to ordinary profiles |
| HTTP/2 method with embedded spaces/request-line text | Reaches the profile as a method string, uppercased by Hypercorn | Whitespace injection is already visible; exact original case is lost |
| Four unfinished HTTP/2 streams reset, followed by a normal request | Normal request succeeds; reset streams produce no profile interaction; admission counters recover | This bounds cleanup behavior, not Rapid Reset attack resistance or emulation |
| HTTP/3 standalone empty QUIC FIN with zero/matching body length | Normal response reaches the client and a profile interaction is logged | The valid FIN path works |
| HTTP/3 standalone empty QUIC FIN with absent/short body versus declared length | aioquic closes the connection with `H3_MESSAGE_ERROR`; no completed request reaches profile dispatch | A profile cannot select different vulnerable/protected behavior at this layer |

The HTTP/3 probes send HEADERS first and await server ASGI entry; for partial
body cases they await body delivery before sending an empty QUIC STREAM FIN.
This distinguishes a standalone FIN from an HTTP/3 DATA frame carrying FIN.
Requests are tiny and bounded; cleanup is asserted after closing the runtime.

## Apache CVE-2021-33193

The [original PortSwigger disclosure](https://portswigger.net/research/http2)
describes whitespace in the method enabling request-line injection during
HTTP/2-to-HTTP/1 proxy translation. The
[Apache advisory](https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-33193)
identifies the affected proxy behavior. Sources reviewed 2026-11-02.

The whitespace mechanism reaches today's ASGI interface. A blanket assumption
that this CVE needs raw frame interception was too broad. The next acceptance
specification must address Hypercorn's method uppercasing (including injected
path case), the chosen virtual proxy/backend parser behavior and observable
follow-up effects. We have not established full CVE fidelity by returning an
ordinary page to the crafted method. Lower-level method preservation may be
needed for exact case-sensitive request-line semantics; broader raw framing is
not established as a prerequisite by these tests.

## HAProxy CVE-2026-33555

The [vendor fix](https://github.com/haproxy/haproxy/commit/05a295441c621089ffa4318daf0dbca2dd756a84)
adds body-length validation on the standalone-FIN path; the
[researcher's disclosure](https://r3verii.github.io/cve/2026/04/14/haproxy-h3-standalone-fin-smuggling.html)
explains how incomplete bodies affect a reused backend connection. Sources
reviewed 2026-11-02.

Our existing library checks this input before a profile can choose to emulate
the vulnerable case. Its connection-close outcome also differs from the vendor
fix's documented stream reset; they are not claimed to be packet-equivalent.
The required extension is bounded observation/handling before that validation,
followed by isolated virtual backend-connection semantics. Do not disable library
validation globally, forward traffic to a real backend, or introduce shared
attacker state across unrelated sessions to imitate the defect.

Any new hook needs its own tests first: raw event/bytes preservation, stable
connection/stream identifiers, vulnerable versus protected decisions, normal
traffic and sibling-stream behavior, admission limits and cleanup. A virtual
backend transaction may span multiple streams within a test-scoped connection;
that is distinct from globally shared mutable systems.

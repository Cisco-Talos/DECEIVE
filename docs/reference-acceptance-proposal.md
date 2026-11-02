# Reference deception acceptance proposal

Status: approved by the human on 2026-11-01, before CVE behavior implementation.

These profiles emulate the interactions below. They do not run vulnerable software,
execute commands, or read the host filesystem. All asserted outputs use declared
virtual identity and file fixtures. Required assertions must all pass; held-out
variations are reported separately, without a universal similarity percentage.

## sudo CVE-2019-14287 (SSH)

Source: the sudo maintainer's announcement,
https://seclists.org/oss-sec/2019/q4/18 and the linked vendor advisory.

Baseline: a non-root account on a Linux host with a vulnerable sudo version and a
simulated sudoers rule permitting `/usr/bin/id` as `(ALL, !root)` with no password.

Required cases:

1. Identity, sudo version, and `sudo -l` consistently expose the configured facts.
2. `sudo -u#-1 id` and `sudo -u#4294967295 /usr/bin/id` report simulated root IDs.
3. Explicitly requesting root through the normal policy is denied.
4. Ordinary `id` still reports the login account after the elevated command.
5. A protected/patched profile variant rejects the special-ID bypass.
6. Variations in whitespace and supported option spelling retain the same outcome.
7. Independent sessions expose the same baseline and do not share mutable state.

Limitations: only the declared command family is emulated. Arbitrary binaries,
compiled payloads, a general sudo implementation, and a persistent root shell are
not promised. Unsupported commands follow the profile's explicit fallback.

## Apache CVE-2021-41773 (HTTP/1.1)

Source: https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-41773.

Baseline: Apache 2.4.49 identity, an Alias-like `/cgi-bin/` mapping, and virtual
files outside its document root. The vulnerable variant permits the declared
traversal; a protected variant enforces access denial.

Required cases:

1. Normal pages and unknown routes return their declared status, headers, and body.
2. Published single-encoded traversal forms retrieve the exact virtual fixture.
3. The protected variant denies the same request.
4. Requests for undeclared virtual files disclose no host data.
5. Double-encoded forms belonging to the subsequent incomplete-fix vulnerability
   are not claimed as supported exploitation of this CVE.
6. Raw encoded paths reach the behavior without application routing normalization.
7. Repeated and concurrent requests produce consistent identity and fixture data.

Limitations: HTTP/1.1 application behavior only; no CGI execution, arbitrary RCE,
request smuggling, memory corruption, or exact Apache transport fingerprint.
HTTP/2 and HTTP/3 engine support is proven with a separate generic application.

## Evaluation evidence

Run clients against actual loopback listeners on ephemeral ports. Keep required
positive/negative and sequence assertions separate from held-out variations.
Record transcripts, source references, profile and suite fingerprints, and
machine-readable results. Ordinary tests use deterministic providers only.

## Agreement and artifacts

The human approved both CVEs in this chat on 2026-11-01, before implementation.
Primary sources above were reviewed on the same date. The maintained profiles
and suites are packaged under `deceive/profiles/` and `deceive/acceptance/`, using
the names `sudo-2019-14287` and `apache-2021-41773`. The frozen suite fingerprints
are recorded in `deceive/acceptance/reference-approval.json` and checked by tests.
Required and held-out cases are both exercised, with held-out results reported
separately. Changes to the agreed fidelity or criteria require a new agreement.

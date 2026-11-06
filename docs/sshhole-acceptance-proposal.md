# sshhole (CVE-2026-123158) deception proposal

Status: **approved in the 2026-11-05 authoring chat**, with realistic account
names and additional root/service-account coverage requested by the human.
Research reviewed 2026-11-05. Profile ID: `sshhole-2026-123158`, version `1`.

## Research basis and target

The published issue is a password-authentication bypass in portable OpenSSH on
musl Linux when PAM is not used. A target account with exactly `*` as its shadow
password, at least one other account with a `$5$` or `$6$` password hash, and
enabled password authentication are the relevant prerequisites. musl returns `*`
for a crypt failure on passwords longer than 256 bytes; affected sshd can compare
that error marker equal to the target's stored `*`. OpenSSH 10.6p2 and Alpine's
stable-branch patched packages address the issue. The CVE Program published
CVE-2026-123158 on 2026-11-05, after Alpine's advisory said no CVE had yet been
assigned.

Primary sources:

- https://sshhole.com/
- https://github.com/oz9un/sshole (researcher's reproduction and checker; read as
  text, never executed)
- https://www.alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/
- https://www.openssh.org/releasenotes.html#10.6p2
- https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/123xxx/CVE-2026-123158.json

Use a **generic Alpine Linux 3.24.3 host**, following the researcher's minimal
two-account reproduction but with plausible local account names. Advertise
`OpenSSH_10.3p1` and virtual Alpine package `openssh-10.3_p1-r1` for the
vulnerable variant. `deploy` and `backup` have `*` and usable `/bin/ash` login
shells, `admin` has a `$6$` password hash, and `root` has `*` but retains
`PermitRootLogin prohibit-password`. `PasswordAuthentication yes`/`UsePAM no`
are configured. The chosen hostname, account names/IDs and `admin` fixture
password are authored facts, not documented facts about a real host. A service
account with `!`, an invalid shell, or an sshd access restriction must not be
represented as automatically exploitable.

This is a generic test host, **not** the official Alpine tiny-cloud image. The
cloud image's `alpine` account and passwordless `doas` privilege path are outside
version 1's claim. No real OpenSSH or musl code runs in DECEIVE.

## Approved required acceptance

Run an actual SSH client against a loopback listener on an ephemeral port.
Use ASCII credentials for exact byte-length boundary tests.

1. **Ordinary auth:** `deploy` and `backup` reject empty, short wrong, and
   exactly 256-byte passwords; `admin` accepts its configured fixture password
   and rejects wrong passwords. Unknown users reject. `root` rejects password
   login, including the long trigger, under the declared default root policy.
2. **Positive bypass:** `deploy` and `backup` accept arbitrary 257-, 300-, and
   1024-byte passwords with one SSH password-auth attempt. Successful
   authentication opens an interactive or exec channel as that user; `whoami`,
   `id`, `pwd`, and
   `/etc/os-release` expose one consistent virtual Alpine identity.
3. **Outside range and protected:** a 1025-byte attempt does not authenticate.
   A patched variant, advertising Alpine's `openssh-10.3_p1-r2`, rejects the same
   257/300/1024-byte attempts while retaining normal `admin` authentication.
4. **Prerequisites:** disabling password authentication, enabling PAM, removing
   the other `$6$` hash, or changing a target's shadow marker to `!` prevents
   bypass. With `PermitRootLogin yes`, `root:*` also accepts the long-password
   trigger; with the default `prohibit-password`, it does not. These variants
   remain explicit test fixtures, not selections by attacker input.
5. **State and telemetry:** independent sessions keep the same identity but have
   private mutable virtual state. Auth failures/successes, attempted usernames
   and passwords, profile/instance attribution, and at most one summary per
   session retain existing telemetry contracts. No attempted command accesses
   host processes or host files.
6. **Composition:** validate an intended SSH listener deployment against the
   profile's declared requirements. An incompatible SSH identity/auth policy must
   fail validation instead of silently overriding either deception.

The byte-length boundary is asserted with ASCII to avoid client-specific Unicode
encoding. Exact OpenSSH error wording, packet fingerprints, complete shell/PAM
behavior, real privilege escalation, and command execution are outside scope.
Rejection must be observed at SSH authentication, not simulated after login.
Public-key login and account key provisioning are excluded from version 1; the
`*` marker is modeled as the account's shadow field, without claiming that
DECEIVE accepts a real authorized key for that account.

## Implementation and evidence

The profile-scoped typed SSH auth policy keeps legacy listener account semantics
for other profiles, including unknown-user wildcard behavior. The new decision
is at the SSH authentication boundary and does not call an LLM. The profile
supplies virtual Alpine identity and deterministic core commands. The packaged
suite has a frozen fingerprint and this chat's actual agreement record. A
separate active realism assessment can probe the finished profile against the
source-linked research dossier.

## Test-first evidence

On 2026-11-05, before adding the authentication policy, the command
`uv run pytest -q tests/test_sshhole.py --maxfail=1 --tb=short` exited 1 at
`test_real_ssh_boundary_and_realistic_accounts`: `Profile.model_validate`
rejected `ssh_auth` as an extra field. This is the missing typed engine
capability, not a fixture or provider error. The pre-existing SSH integration
suite passed 12/12 before the new behavior work.
The acceptance assertion for rejected authentication was also written and run
before the evaluator extension; it failed because `authenticated` was not yet
an allowed assertion field. The packaged YAML suite was generated after the
Python red tests and implementation from the approved criteria; this ordering
is recorded explicitly because the repository's preferred sequence calls for
freezing the packaged suite before implementation.

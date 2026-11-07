# Whole-device SSH sessions

DECEIVE remains a proof of concept. All device activity is simulated in memory;
no attacker-selected path, command, application or network destination reaches the host.

## Reference devices

Run `uv run deceive serve --profile linux-device` and connect to port 8022.
The model-free public reference packs are `linux-device` (Ubuntu 22.04/Bash),
`macos-device` (macOS 14/Zsh), `freebsd-device` (FreeBSD 14/sh), and
`ios-device` (IOS XE 17.9 style CLI). A configured provider enables optional fallback.
Names, process inventories, file contents and the configuration menu are fictional
fixtures, not captures of reference equipment. Packaged source-linked research dossiers
identify independent platform evidence and remaining realism gaps.

The first three packs provide bounded ordinary commands and full-screen `less`,
`top`, `vi`, and `device-menu` applications. IOS provides EXEC/configuration/interface
modes, contextual `?`, unique command abbreviations, an enable password question,
interface description/shutdown controls and private running/startup configuration.
The reference enable password is the public fixture `fixture-enable`; override
`device.enable_password` in an authored pack. It is not an operator credential.

```yaml
device:
  platform: macos        # linux, macos, freebsd, ios
  interpreter: zsh      # bash, zsh, sh, ios
  home: /Users/{user}
  applications: [less, top, vi, device-menu]
  model_effects: true
```

Platform and interpreter are separate choices except that IOS requires its own
interpreter. Pack declarations require SSH and participate in composition conflict
validation. Identity, contracts, files and behavior rules remain profile-owned.
Existing SSH profiles receive the shared terminal/session engine; their accepted
rules retain precedence. HTTP command endpoints keep their existing interface.

## Interaction and state

Each SSH session channel owns a private overlay. Independent channels on the same
connection have separate files, working directories, effective identity and applications.
Nested shells share virtual device objects but restore the parent's environment and
working directory on exit. Reconnecting restores the baseline. Runtime identity and
telemetry attribution never change; explicit hostname edits change only the channel's
effective hostname and virtual `/etc/hostname`.

The interpreter supports quoting, environment/tilde expansion, command lists,
`&&`/`||`, pipes and one trailing input/output/append redirection per command.
Unsupported grammar such as command substitution and background jobs fails before
execution. This is not complete Bash/Zsh/sh compatibility. Common discovery, files,
text filtering, byte/line counting, environment, process, metadata and permission
operations use private objects. Additional existing profile handlers retain their
accepted semantics. Utility flags and permissions are bounded subsets; they are
not complete GNU/BSD utility implementations. External network activity is never real.

The terminal decoder handles fragmented UTF-8/escape input, arrows, history recall,
Home/End, deletion, completion, interrupts, EOF and bracketed paste. Pasted newlines
become spaces so paste does not independently submit commands. PTY echo and newline
modes are respected. `xterm`, `xterm-256color` and `vt100` support full-screen output;
`dumb` can run ordinary commands and receives an explicit limitation for applications.

`less` supports movement, pages, forward search and quit. Ctrl-C cancels a search
and retains the pager. Movement changes the viewport of longer files; a file's final
newline is not an extra displayed line. IOS output instead uses an inline `--More--` dialogue:
Space advances a page, Enter advances a line, and q/Ctrl-C returns to the CLI.
`terminal length 0..512` selects a private page length; zero disables paging.
The default follows terminal height. It does not enter a Unix alternate screen.
`show interfaces` and `show ip interface brief` share the complete virtual interface
inventory and effective configuration; unfamiliar model views receive that inventory.
The same installed-route inventory drives `show ip route` and model context.
Connected/local routes withdraw on shutdown and return on no shutdown. Reference
interface addresses also appear in running/startup configuration.

`top` refreshes virtual
process state once a second by default. `s`/`d` requests a bounded 0.1–60 second
refresh interval; `N` selects PID order, `R` reverses it, and `k` requests bounded
virtual process removal. The editor supports normal/insert/command modes, basic
movement, insertion/deletion, insertion-group undo with cursor restoration,
literal forward search (including same-line matches and wrapping), `:w`, `:wq`,
`:x`, `:q`, and `:q!`. It reports unsupported editor commands.
Editor text saves terminate nonempty logical lines with LF, preserve explicit blank
lines and empty files, and remain stable across repeated saves. Ctrl-C leaves insert
or command/search mode while retaining the buffer and unsaved-change protection.
The menu fixture supports selection, forms, confirmation, apply/cancel and quit.
The monitor renders platform-specific CPU, memory and process summaries from the
same bounded resource inventory exposed to model fallback and `ps aux`; Linux also
supports `free -m`. Virtual sampling accumulates CPU time and elapsed counters without
reading host processes, memory or network interfaces. An unchanged process's total
CPU time cannot decrease. These are representative
displays, not complete native top option or column compatibility.
Applications preserve state across resize and restore parent interaction on exit.
They do not launch real binaries, editor shell escapes, plugins or subprocesses.

Limits include 128 virtual file nodes, 64 KiB of private file bytes, 64 KiB editor
buffers, bounded undo, `application_depth` (default 8), `channel_limit` (16),
`screen_columns` (240), and `screen_rows` (100), plus existing request/input/output,
idle/total lifetime and provider concurrency/deadline controls. Full shell job control,
SFTP/SCP, forwarding and reconnect persistence remain excluded.

## Model actions

Provider request failures/timeouts preserve channel state and return a bounded
ordinary error, with one correlated final response and sanitized failed-attempt
telemetry. Rejected unsafe model proposals retain their explicit failure policy.
FreeBSD reference identity/journeys use native `amd64`, rather than Linux's label.

With `device.model_effects: true` and JSON replies, models may add:

```json
{
  "stdout": "Created the note.\n",
  "exit_status": 0,
  "effects": {
    "write_files": {"/tmp/note": "private text\n"},
    "remove_files": [],
    "add_executables": ["/usr/bin/example-tool"],
    "remove_executables": [],
    "configuration": {"hostname": "private-node"},
    "cwd": "/tmp"
  },
  "dialogue": {"prompt": "Continue? ", "echo": true}
}
```

Effects are typed proposals, validated on a staged overlay. Invalid effects and
invalid replies commit nothing. Allowed configuration keys are hostname and description;
file writes/removals require permitted virtual destinations. Model dialogue requests
one subsequent input; hidden input uses `echo: false`. Models receive effective device
facts, current files, recent interaction and context. They do not receive host tools.
Executable effects change only the private virtual inventory under `/bin`, `/usr/bin`
or `/usr/sbin`; baseline entries cannot be removed. Successful unfamiliar commands
may establish a bounded virtual executable fact, and successful `which` claims must
name a matching validated virtual path. These facts never run host executables.
A generation check prevents cancelled or late replies from committing effects.
Immediate application key handling and screen rendering never call a provider.
Structural validation does not prove that arbitrary model prose is realistic.

Telemetry preserves core fields, exact noninteractive streams/status, actual raw
model replies, and base64 input/output. All channels share the connection's stable
`task_name` and add `channel_id`. Command replies add `state_revision`, application
context and optional ordered `terminal_chunks`. `Terminal input`, `Terminal output`
and `Terminal event` records capture byte/event activity; output sequences permit
independent client-capture correlation. One summary is generated when the connection
ends, rather than when the first channel exits.

## Offline tests and installed artifacts

`uv run pytest` never selects a live provider. OpenSSH must be installed; missing
clients fail device acceptance instead of skipping it. Thirteen packaged OpenSSH
journeys exercise at least 20 meaningful actions each: three for each reference
device pack and one for the sudo device session. Screen tests use real SSH
channels and the independent pyte emulator; provider tests inject scripted, invalid,
delayed and failing replies. Existing CVE suites and approval fingerprints stay frozen.

```sh
uv run python scripts/check_device_sessions.py --report results/devices/offline.json
uv run python scripts/check_device_applications.py
```

Wheel verification runs installed journeys and screen/state checks outside the
checkout. Container verification runs native OpenSSH clients against localhost-only
ARM64 device containers and runs application checks with external networking disabled.

The first capability regression run against revision `43464bf` was:
`UV_CACHE_DIR=/tmp/deceive-uv-cache uv run --no-sync pytest tests/test_device_sessions.py -q`.
All three cases failed because compound commands returned fallback, a second channel
was rejected and nested exit closed the channel. The earlier sandbox-denied socket run
was an infrastructure failure and is not counted as capability evidence. No new
vulnerability behavior is introduced by this work.

## Local online configuration and independent review

Copy `examples/testing.yaml` to ignored `testing.local.yaml`. Select your provider,
model, region and optional local AWS profile there. Credentials remain in environment
variables, mounted secret files or the AWS credential chain. Do not put keys in YAML.
No test loads this file automatically and CI uses no personal provider configuration.

```sh
uv run --all-extras python scripts/check_device_sessions.py \
  --live-model --config testing.local.yaml --provider evaluation \
  --report results/devices/online.json
```

Use repeated `--profile` for public or custom references and `--journeys FILE` for
custom journey definitions. Without explicit profiles, local config listener selections
choose online targets; offline defaults discover public packs by capability.
The runner requires an explicit provider alias and verifies actual model calls.
It records model metadata and timing but always labels realism **unassessed**.
A successful smoke test is not independent realism qualification.

For qualification, copy `examples/assessment-device.yaml` to ignored
`assessment.local.yaml`, configure its provider/targets, expand frozen coverage to the
selected pack and application surface, and run the existing `deceive-assess` skill.
The skill owns native independent reviewers, calibration, repair budgets and repeated
confirmation. `require_live_model: true` requires explicit target providers and provider
networking; missing credentials are an assessment gap, never an offline pass.
The raw `terminal` driver supports bounded send/resize/wait events and captures raw
bytes, screen, cursor, source port and timing. Telemetry auditing rejects reused screen
captures. Its client emulator handles xterm's 1049 alternate buffer, preserving the
primary screen/cursor across application exits and resize. Runtime control/status,
model smoke, contract correctness and independent
research-backed realism remain separate results. A template with incomplete workflow
coverage cannot qualify a target.

# AGENTS.md - DECEIVE

This document gives AI coding agents the project-specific context needed to make
consistent, idiomatic changes to DECEIVE.

## Project Overview

DECEIVE is a profile-driven proof-of-concept honeypot supporting real SSH and
HTTP/HTTPS 1.1, 2, and 3 listeners. YAML profiles select deterministic, generative,
or hybrid behavior over virtual data. Attacker input never reaches a real shell
or host filesystem. Identity and baseline content stay consistent across
connections; session state is private and temporary.

Primary implementation lives in `deceive/`: `models.py`/`config.py` define YAML,
`runtime.py` owns sessions and transcripts, `providers.py` contains optional SDK
adapters, and `protocols/` owns protocol libraries. `SSH/ssh_server.py` is now
migration guidance. Built-in profiles and acceptance suites ship in the wheel.

## Start-Of-Work Checklist

For any non-trivial change:

1. Read `README.md`, `pyproject.toml`, and `TODO.txt` before editing.
2. Check `git status --short`; preserve user changes already in the tree.
3. Inspect the relevant tests before changing behavior.
4. Update `TODO.txt` only when the change completes, changes, or adds a tracked
   backlog item.
5. Update `README.md` and `examples/deployment.yaml` when setup, config keys,
   runtime behavior, or log fields change.

## Tech Stack

- Python 3.11, pinned by `.python-version` and `requires-python` in
  `pyproject.toml`.
- `uv` for dependency management and command execution.
- `asyncssh` for the SSH server and integration test clients.
- Direct optional SDK adapters for OpenAI/Azure, Ollama, Bedrock, and Gemini.
- Hypercorn/aioquic for HTTP/1.1–3; PyYAML/Pydantic for safe typed configuration.
- `pytest` and `pytest-asyncio` for automated tests.
- Standard library `argparse`, `configparser`, `logging`, `json`, `asyncio`, and
  path utilities. The current CLI is argparse-based; do not switch frameworks
  unless explicitly requested.

## Dependency Management

Use `uv`; do not add `requirements.txt` or install dependencies with bare `pip`.

Common commands:

```bash
uv sync
uv run pytest
uv run pytest tests/test_ssh_server_unit.py
uv run pytest tests/test_ssh_integration.py
uv run deceive serve --profile demo-http
```

When adding or removing dependencies, update `pyproject.toml` and `uv.lock`
together. This project is an installed Python package with a console command and bundled
profile assets. Verify wheels outside the checkout when packaging changes.

## Code Style

- Prefer clear, direct Python over clever abstractions.
- Add type hints for new or significantly changed functions. Existing code is
  still being modernized, so avoid broad type-only churn.
- Use specific exceptions and actionable error messages at runtime boundaries.
- Avoid bare `except Exception` in new code unless it is at `main()` or another
  intentional process boundary.
- Prefer `pathlib.Path` for new path-heavy code, but match nearby code when a
  small change in `SSH/ssh_server.py` would otherwise create needless churn.
- Keep lines readable, around 100 characters where practical.
- Use comments sparingly for non-obvious async, logging, or security behavior.
- Do not add linting or formatting tool mandates unless the project config is
  updated to support them.

## Runtime Architecture

### Protocol Lifecycle

`Runtime.start()` validates profiles/providers and starts configured adapters.
Use `host: 127.0.0.1`, `port: 0`, and ephemeral data directories in tests. Preserve
real HTTP/2 and HTTP/3 negotiation tests; do not replace them with fallback HTTP.
The runtime owns summaries and cleanup; SSH connection instances own authentication.
Keep protocol code independent of deterministic/generative profile decisions.

### Authentication Semantics

The honeypot intentionally supports deceptive login modes:

- `username =` accepts login without a password.
- `username = secret` requires the exact password.
- `username = *` accepts any password, including empty passwords.
- Unknown usernames currently authenticate like wildcard accounts.

Do not "fix" the unknown-user behavior unless implementing an explicit auth
policy option. Tests should cover all four modes.

### LLM Simulation

Provider adapters implement a text-only async interface. The runtime supplies
fixed identity, virtual file facts, and bounded per-session history. Deterministic
interactions also enter the transcript. Do not introduce local model/tokenizer
downloads, model tools, or actual command execution.

Interactive SSH receives a server-owned banner and prompt. Non-interactive output
contains neither. The model answers only the current input. The legacy
`YYY-END-OF-SESSION-YYY` sentinel remains accepted as a session-ending decision.

## Logging Contracts

DECEIVE writes JSON Lines to stdout by default or deployment `log_file`. Relative
paths resolve from the deployment YAML directory. Preserve core telemetry fields;
add new profile/request metadata rather than repurposing existing fields.

Preserve these fields for session telemetry:

- `timestamp` - UTC ISO 8601 with millisecond precision.
- `level`
- `task_name` - the stable `session-...` id for the SSH session.
- `src_ip`, `src_port`, `dst_ip`, `dst_port`
- `message`
- `sensor_name`
- `sensor_protocol` - SSH, HTTP, HTTPS, or an explicitly enabled adapter

Important message types:

- `SSH connection received`
- `User attempting to authenticate`
- `Authentication success`
- `Authentication failed`
- `User input`
- `LLM response` (actual model output)
- `Deception response` (deterministic output)
- `Session summary`
- `SSH connection closed`

`User input` and `LLM response` records store full content in `details` as
base64-encoded UTF-8. Keep that encoding contract stable so arbitrary terminal
bytes do not break JSON logs. Include the `interactive` boolean for command and
response records where it applies.

`Session summary` records include `details` with the LLM summary and `judgement`
as one of `BENIGN`, `SUSPICIOUS`, `MALICIOUS`, or `UNKNOWN`. Generate at most one
summary per session.

This is a honeypot: authentication logs intentionally include attempted
usernames and passwords. Do not remove that behavior casually, but also do not
log provider API keys, environment variables, local config contents, or stack
traces containing secrets.

## Configuration And Local Artifacts

Tracked: deployment examples, packaged profiles/acceptance suites, legacy INI
migration template, docs and skills. Keep generated data under an ignored data
directory. Do not commit credentials, keys, generated logs, evaluation reports, or
local deployment artifacts. Provider credentials use environment variables or
mounted secret files; AWS uses its credential chain.

Update typed models, examples, docs, and tests together when adding settings.
Assets resolve relative to their owning YAML, not the current working directory.
Profiles cannot execute Python or choose real file paths from attacker input.
Installed extensions are trusted code and must be explicitly allowlisted.

## Testing Requirements

All tests must be deterministic and must not call a live LLM provider. Use injected fake providers and mocked SDK clients.

Testing conventions:

- Use `tmp_path` for config files, host keys, logs, and any file I/O.
- Bind integration servers to `127.0.0.1` and `port = 0`.
- Use `known_hosts=None` for ephemeral local AsyncSSH clients in tests.
- Flush and close log handlers in fixtures to avoid leaking global state.
- Close runtimes, sockets, provider clients, observer tasks, and temporary data
  directories after tests. Avoid module-global runtime state.
- Assert log shape, base64 encoding, session id consistency, and one summary per
  session when touching session flow.

Run at least the focused test file for the code you changed. Run the full suite
before commits or behavior-heavy changes:

```bash
uv run pytest
```

## Security And Safety

DECEIVE is a proof of concept, not production-ready infrastructure. Keep that
warning intact in user-facing docs unless the security posture materially
changes.

Prioritize bounded resource controls for public-facing behavior:

- Maximum input line length.
- Session idle and total timeouts.
- Connection and request limits.
- LLM call throttling.
- Cleanup for per-session message history.

Never route attacker input to a real shell or filesystem. The LLM should simulate
output only. If adding tools, retrieval, file access, or command execution, gate
them behind explicit design review and tests that prove attacker input cannot
escape the simulation boundary.

## Documentation Checklist

Update docs when behavior changes:

- `README.md` for setup, running, operator behavior, log schema, or warnings.
- `examples/deployment.yaml` and configuration docs for new settings; the legacy
  INI template should continue explaining migration.
- `SSH/prompt.txt` only for default emulation behavior.
- `TODO.txt` for backlog changes or completed tracked priorities.
- Tests for every observable auth, session, config, prompt, or logging contract.

## Versioning And Commits

The project version currently lives in `pyproject.toml` only. If asked to bump
the version, update `pyproject.toml`, run `uv sync` so `uv.lock` stays
consistent, and document the reason in the commit.

Prefer Conventional Commit prefixes such as `feat:`, `fix:`, `docs:`, `test:`,
`refactor:`, and `chore:` when committing.

## Known Design Decisions

- Honeypot authentication intentionally records attempted usernames/passwords.
- Unknown SSH users authenticate successfully.
- Runtime models are optional; deterministic deployments need no credentials.
- Session summaries use UNKNOWN when analysis is disabled or unavailable.
- Shared persistent attacker state and cross-service system state are deferred.
- Container publication/deployment are separate from building/testing artifacts.

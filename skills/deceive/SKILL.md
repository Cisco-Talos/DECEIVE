---
name: deceive
description: >-
  Operate DECEIVE through chat: discover and inspect deception profiles, validate
  combinations, manage deployments, evaluate behavior, and route profile creation
  or active assessment loops to the repository workflows. Use for DECEIVE operator
  requests, not unrelated honeypot products.
---

# Work with DECEIVE

Use the installed `deceive` command, or `uv run deceive` from this repository.
Discover the actual command surface with `--help`; the CLI and its versioned
results are authoritative. Keep the user's selected profile IDs, deployment
names, provider settings and requested assessment scope throughout the task.

Read [operator commands](../../docs/operations.md) when managing deployments or
interpreting structured results. Request `--json` for machine-readable output;
`ok` means the command completed successfully, while assessment qualification,
realism, correctness and telemetry remain separate values in `data`.

## Choose the operation

Profile creation/refinement routes to deceive-author, including its research
dossier and default active assessment handoff. The separate deceive-assess skill
owns that review/repair loop and standalone realism requests; it consumes frozen
independent research as well as functional contracts.

| User intent | Interface |
| --- | --- |
| Available deceptions or CVEs | `profile list`, optionally `--vulnerabilities`, `--protocol`, `--directory DIR` |
| Requirements, identity or limitations | `profile show ID_OR_FILE` |
| Validate one authored profile | `profile validate FILE` |
| Validate a complete selection | `config validate --config FILE --deception ID` (repeatable, additive) |
| Run named deceptions | `deployment start NAME` with selection/config and existing `--image` |
| Run in foreground or natively | `serve` with the same selection/config flags |
| Find or inspect deployments | `deployment list` / `deployment status NAME` |
| Stop or restart a deployment | `deployment stop NAME` / `deployment start NAME` |
| Remove a stopped container | `deployment remove NAME`; data remains unless `--remove-data` was requested |
| Automated acceptance | `profile evaluate PROFILE --suite FILE --report-dir DIR` |
| Create/refine a deception | Read and apply [deceive-author](../deceive-author/SKILL.md) |
| Active reviewer and repair loops | Read and apply [deceive-assess](../deceive-assess/SKILL.md) |

Do not reproduce the authoring or assessment algorithms here. Those workflows
own research, human acceptance agreement, tests first, frozen criteria, reviewer
orchestration, repair budgets, confirmation/plateau and final dashboards. The
CLI helpers do not themselves run autonomous coding agents. "All profiles" in
assessment means individual targets unless the user selects deployment groups.

## Operate consistently

Discover profiles and inspect unfamiliar requirements before choosing a
combination. Resolve an ambiguous requested ID through the catalog or available
local directories before asking the user. Never silently rename a conflicting
profile or hide a composition error. Preserve explicit provider/model/region and
credential references; examples are not defaults to hardcode.

Validate the exact combined YAML/CLI selection before launching. `start` and
`serve` repeat runtime validation. Reuse the user's configuration rather than
copying provider details into profile YAML. Model-free deceptions need no model.
Acceptance tests and ordinary pytest remain deterministic; live provider use
requires the user's selected scope and configuration.

Managed deployments use a locally installed standard image and publish only on
localhost by default. Do not pull, build, publish, expose publicly or change a
provider merely because a requested start fails. A local image build can be part
of an authorized deployment task; explain when it is needed and preserve runtime
configuration. Retained starts reuse the existing image, bindings and data.
Changing configuration, environment or mounts requires explicitly stopping and
replacing the container; preserve its data unless deletion is authorized.

Use the same `--state-dir` (or `DECEIVE_STATE_DIR`) for related lifecycle commands.
Do not control a container by guessing its name or PID. The manager verifies
ownership. Its resources are separate from assessment containers; use the owning
workflow for cleanup. Readiness failure is a failure, with retained state for
diagnosis, never a successful deployment. Capture safe results and artifact
paths; do not print credentials or full Docker environment inspection.

Return the concrete deployment/operation outcome, profile IDs, endpoints, report
or dashboard links, and unresolved limitations. Preserve existing edits. Do not
commit, push, open PRs, merge or publish automatically; honor the user's actual
authorization. The current feature branch remains independent of `dev` review.

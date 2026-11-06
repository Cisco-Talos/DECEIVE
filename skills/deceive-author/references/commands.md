# Required commands and virtual platforms

Read the [supported command matrix](../../../docs/behavior-contracts.md#virtual-commands).
Select linux, cmd, powershell-5.1, or powershell-7. Establish fixed identity,
account, home, environment, directories, files, and claimed version details.

For Windows literal output, `>`/`>>` need not have surrounding spaces. Quoted
operators remain data; wrappers preserve empty arguments and quoted paths. Only
one trailing literal redirection is implemented; descriptor redirection and
pipelines remain outside the supported grammar. Test these boundaries and
discovery of any aliases you claim.

For each required program, define its canonical name, virtual path, aliases,
discovery, help/version where claimed, argument cases, errors, stdout/stderr,
exit status, prerequisites and virtual effects. Use `{name}` for one argument
capture and `${command.name}` in its response. Arbitrary argument patterns,
scripts, pipelines and host operations are not supported by this bounded engine.

Do not claim complete shell compatibility. Test only the documented argument
forms and declare limitations. Use profile contracts or raise an engine gap for
additional requirements. Verify Windows case-insensitive paths and native
newlines; distinguish PowerShell 5.1 file encodings from PowerShell 7. Identity,
listings, reads, writes and model facts must describe the same virtual view.

Interactive SSH keeps process state. Web command invocations reset cwd,
environment and previous status, while cookie-scoped files/application state may
persist. Test new-session isolation and ensure failed validation commits nothing.
Attacker inputs never select actual host paths or run an interpreter.

"""Real SSH authentication checks for the approved sshhole deception."""
from __future__ import annotations

import asyncio
import base64
import json

import asyncssh
import pytest

from deceive.config import load_profile
from deceive.assessment.drivers import SSHDriver
from deceive.assessment.models import ProbeAction
from deceive.cli import main
from deceive.clients import ShellClient
from deceive.evaluate import Expected
from deceive.models import Profile


def target_profile() -> Profile:
    data = load_profile("linux-ssh").model_dump(mode="python")
    data.update(schema_version=2, id="sshhole-2026-123158", version="1",
                fallback="reject", behaviors=[{"id": "identity", "kind": "identity"}],
                ssh_auth={
                    "kind": "musl-star-bypass",
                    "password_authentication": True,
                    "use_pam": False,
                    "patched": False,
                    "permit_root_login": "prohibit-password",
                    "accounts": {
                        "root": {"shadow": "*", "uid": 0, "shell": "/bin/ash"},
                        "deploy": {"shadow": "*", "uid": 1001, "shell": "/bin/ash"},
                        "backup": {"shadow": "*", "uid": 1002, "shell": "/bin/ash"},
                        "admin": {"shadow": "$6$", "password": "fixture-admin-secret",
                                  "uid": 1000, "shell": "/bin/ash"},
                        "daemon": {"shadow": "*", "uid": 2, "shell": "/sbin/nologin"},
                    },
                })
    return Profile.model_validate(data)


def test_acceptance_can_assert_authentication_rejection():
    assert Expected.model_validate({"authenticated": False}).authenticated is False


def test_ssh_auth_configuration_must_match_virtual_sshd_config():
    data = load_profile("sshhole-2026-123158").model_dump(mode="python")
    data["files"]["/etc/ssh/sshd_config"] = "PasswordAuthentication no\nPermitRootLogin yes\n"
    with pytest.raises(ValueError, match="ssh_auth.*sshd_config"):
        Profile.model_validate(data)


def test_sshhole_and_other_ssh_profile_need_distinct_listeners(capsys, tmp_path):
    result = main(["config", "validate", "--deception", "sshhole-2026-123158",
                   "--deception", "sudo-2019-14287", "--data-dir", str(tmp_path / "data")])
    assert result == 2
    assert "Listener conflict" in capsys.readouterr().err
    assert not (tmp_path / "data").exists()


def endpoint(runtime) -> int:
    return next(iter(runtime.servers.values())).endpoints[0]["port"]


async def login(port: int, username: str, password: str):
    return await asyncssh.connect("127.0.0.1", port=port, username=username,
                                  password=password, preferred_auth="password",
                                  client_keys=[], known_hosts=None)


@pytest.mark.asyncio
async def test_real_ssh_boundary_and_realistic_accounts(runtime_factory):
    runtime = await runtime_factory("ssh", profile=target_profile())
    port = endpoint(runtime)
    for username in ("deploy", "backup"):
        for password in ("", "wrong", "A" * 256, "A" * 1025):
            with pytest.raises(asyncssh.PermissionDenied):
                await login(port, username, password)
        for length in (257, 300, 1024):
            async with await login(port, username, "A" * length) as connection:
                assert (await connection.run("whoami")).stdout == username + "\n"
    for username in ("root", "daemon", "not-a-user"):
        with pytest.raises(asyncssh.PermissionDenied):
            await login(port, username, "A" * 300)
    with pytest.raises(asyncssh.PermissionDenied):
        await login(port, "admin", "wrong")
    async with await login(port, "admin", "fixture-admin-secret") as connection:
        assert (await connection.run("id -u")).stdout == "1000\n"


@pytest.mark.asyncio
async def test_bundled_sshhole_uses_model_only_for_unhandled_session_input(runtime_factory):
    profile = load_profile("sshhole-2026-123158")
    assert profile.fallback == "llm_if_available"
    runtime = await runtime_factory("ssh", profile=profile, model=True)
    async with await asyncssh.connect("127.0.0.1", port=endpoint(runtime),
                                     username="deploy", password="A" * 300,
                                     preferred_auth="password", client_keys=[],
                                     known_hosts=None, encoding=None) as connection:
        shell = await ShellClient.open(connection, 2)
        assert (await shell.run("whoami", 2)).body == b"deploy\n"
        assert not runtime.test_provider.calls
        assert (await shell.run("unfamiliar-command", 2)).body == b"simulated output\n"
        assert len(runtime.test_provider.calls) == 1
        await shell.run("exit", 2)


@pytest.mark.asyncio
async def test_protected_variants_and_explicit_root_policy(runtime_factory):
    variants = [
        (lambda p: setattr(p.ssh_auth, "patched", True), "deploy", False),
        (lambda p: setattr(p.ssh_auth, "use_pam", True), "deploy", False),
        (lambda p: setattr(p.ssh_auth, "password_authentication", False), "deploy", False),
        (lambda p: p.ssh_auth.accounts.pop("admin"), "deploy", False),
        (lambda p: setattr(p.ssh_auth.accounts["backup"], "shadow", "!"), "backup", False),
        (lambda p: setattr(p.ssh_auth, "permit_root_login", "yes"), "root", True),
    ]
    for change, username, expected in variants:
        profile = target_profile()
        change(profile)
        runtime = await runtime_factory("ssh", profile=profile)
        if expected:
            async with await login(endpoint(runtime), username, "A" * 300) as connection:
                assert (await connection.run("whoami")).stdout == "root\n"
        else:
            with pytest.raises(asyncssh.PermissionDenied):
                await login(endpoint(runtime), username, "A" * 300)


@pytest.mark.asyncio
async def test_sshhole_identity_is_private_and_attempts_are_attributed(runtime_factory):
    profile = target_profile()
    profile.identity.hostname = "edge-build-07"
    profile.identity.os = "Alpine Linux v3.24"
    profile.identity.uid = 1001
    profile.identity.username = "deploy"
    profile.identity.ssh_version = "OpenSSH_10.3p1"
    profile.files = {"/etc/hostname": "edge-build-07\n",
                     "/etc/os-release": 'NAME="Alpine Linux"\nVERSION_ID=3.24.3\nID=alpine\n',
                     "/etc/passwd": "root:x:0:0:root:/root:/bin/ash\n"
                                    "admin:x:1000:1000:admin:/home/admin:/bin/ash\n"
                                    "deploy:x:1001:1001:deploy:/home/deploy:/bin/ash\n"
                                    "backup:x:1002:1002:backup:/home/backup:/bin/ash\n"}
    runtime = await runtime_factory("ssh", profile=profile)
    port = endpoint(runtime)
    async with await login(port, "deploy", "A" * 300) as first:
        assert (await first.run("id")).stdout.startswith("uid=1001(deploy)")
    async with await login(port, "backup", "B" * 300) as second:
        assert (await second.run("id")).stdout.startswith("uid=1002(backup)")
    await asyncio.sleep(0.02)
    records = [json.loads(line) for line in runtime.test_stream.getvalue().splitlines()]
    assert any(r["message"] == "Authentication success" and r.get("username") == "deploy"
               and r.get("password") == "A" * 300 for r in records)
    assert any(r["message"] == "Authentication success" and r.get("username") == "backup"
               and r.get("password") == "B" * 300 for r in records)
    assert all(r.get("profile_id") == profile.id for r in records
               if r["message"] == "Authentication success")
    summaries = [r for r in records if r["message"] == "Session summary"]
    assert len({r["task_name"] for r in summaries}) == len(summaries)


@pytest.mark.asyncio
async def test_packaged_profile_and_assessment_driver_auth(runtime_factory, tmp_path):
    runtime = await runtime_factory("ssh", profile=load_profile("sshhole-2026-123158"))
    port = endpoint(runtime)
    driver = SSHDriver()
    target = {"ports": {"tcp": {"host": port}}}
    for password, expected in (("A" * 256, False), ("A" * 257, True)):
        action = ProbeAction(operation="authenticate", parameters={
            "username": "deploy", "password": password})
        observed = await driver.execute(target, action, ("sshhole", password[:1]))
        assert observed["version"] == "ssh"
        assert observed["facts"]["authenticated"] is expected
    commands = [("cat /etc/hostname", "edge-build-07\n", 0),
                ("apk info -v openssh", "openssh-10.3_p1-r1\n", 0),
                ("cat /etc/shadow", "Permission denied", 1)]
    secret = tmp_path / "host-secret"
    secret.write_text("host-only")
    commands.append(("cat " + str(secret), "host-only", 1))
    for command, expected, status in commands:
        async with await login(port, "backup", "B" * 300) as connection:
            result = await connection.run(command)
            assert result.exit_status == status
            if command == "cat " + str(secret):
                assert expected not in result.stdout
            elif command == "cat /etc/shadow":
                assert expected in result.stderr and result.stdout == ""
            else:
                assert expected in result.stdout
    await driver.close()


@pytest.mark.asyncio
async def test_alpine_shell_facts_and_error_streams(runtime_factory):
    runtime = await runtime_factory("ssh", profile=load_profile("sshhole-2026-123158"))
    target = {"ports": {"tcp": {"host": endpoint(runtime)}}}
    driver = SSHDriver()

    async def run(command: str, session: str | None = None, client: str = "one"):
        action = ProbeAction(operation="exec", session=session, parameters={
            "username": "deploy", "password": "A" * 300, "command": command})
        return await driver.execute(target, action, ("alpine-shell", client))

    try:
        release = await run("cat /etc/alpine-release")
        assert base64.b64decode(release["body_base64"]) == b"3.24.3\n"
        missing = await run("cat /tmp/no-such-file")
        assert base64.b64decode(missing["body_base64"]) == b""
        assert b"No such file" in base64.b64decode(missing["facts"]["outputs"][0]["stderr_base64"])
        assert missing["facts"]["outputs"][0]["exit_status"] == 1
        unknown = await run("not-a-real-command")
        assert base64.b64decode(unknown["body_base64"]) == b""
        assert b"not found" in base64.b64decode(unknown["facts"]["outputs"][0]["stderr_base64"])
        assert unknown["facts"]["outputs"][0]["exit_status"] == 127
        protected = await run("cat /etc/shadow")
        assert base64.b64decode(protected["body_base64"]) == b""
        assert b"Permission denied" in base64.b64decode(
            protected["facts"]["outputs"][0]["stderr_base64"])
        bad_cd = await run("cd /not-a-directory", "bad")
        assert base64.b64decode(bad_cd["body_base64"]).startswith(b"ash: cd:")
        await run("cd /tmp", "visit")
        changed = await run("pwd", "visit")
        assert base64.b64decode(changed["body_base64"]) == b"/tmp\n"
        fresh = await run("pwd", "other", "two")
        assert base64.b64decode(fresh["body_base64"]) == b"/home/deploy\n"
    finally:
        await driver.close()

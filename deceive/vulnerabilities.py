"""Narrow, deterministic CVE simulations over virtual data, never real execution."""
from __future__ import annotations

import posixpath
import re
import shlex
from urllib.parse import unquote

from pydantic import Field, model_validator

from deceive.interaction import Interaction, Response, Session
from deceive.models import Behavior, Model, Profile


class SudoOptions(Model):
    patched: bool = False
    runas_all: bool = True


class ApacheOptions(Model):
    protected: bool = False
    alias_prefix: str = "/cgi-bin/"
    alias_root: str = "/usr/local/apache2/cgi-bin"

    @model_validator(mode="after")
    def valid_alias(self) -> ApacheOptions:
        if (not self.alias_prefix.startswith("/") or not self.alias_prefix.endswith("/")
            or ".." in self.alias_prefix or "\x00" in self.alias_prefix):
            raise ValueError("alias_prefix must be an absolute directory URL")
        if not self.alias_root.startswith("/") or posixpath.normpath(self.alias_root) != self.alias_root:
            raise ValueError("alias_root must be a normalized absolute virtual directory")
        return self


def sudo_2019(profile: Profile, spec: Behavior, interaction: Interaction,
              session: Session) -> Response | None:
    if interaction.protocol != "ssh":
        return None
    try:
        words = shlex.split(interaction.command)
    except ValueError:
        return None
    if not words or words[0] not in {"sudo", "/usr/bin/sudo"}:
        return None
    options = SudoOptions.model_validate(spec.options)
    args = words[1:]

    def response(text: str, status: int = 0) -> Response:
        return Response(body=text.encode(), exit_status=status, behavior=spec.id)

    version = "1.8.28" if options.patched else "1.8.27"
    if args in (["-V"], ["--version"]):
        return response(f"Sudo version {version}\n")
    allowed_user = profile.identity.username
    if session.username != allowed_user:
        return response(f"{session.username} is not in the sudoers file.\n", 1)
    policy = "ALL, !root" if options.runas_all else allowed_user
    if args in (["-l"], ["--list"]):
        return response(f"User {allowed_user} may run the following commands on "
                        f"{profile.identity.hostname}:\n    ({policy}) NOPASSWD: /usr/bin/id\n")
    target = "root"
    index = 0
    while index < len(args):
        value = args[index]
        if value == "--":
            index += 1
            break
        if value == "-n":
            index += 1
        elif value in {"-u", "--user"}:
            if index + 1 >= len(args):
                return response("sudo: a user must be specified\n", 1)
            target = args[index + 1]
            index += 2
        elif value.startswith("--user="):
            target = value.split("=", 1)[1]
            index += 1
        elif value.startswith("-u") and len(value) > 2:
            target = value[2:]
            index += 1
        else:
            break
    command = args[index:]
    if not command:
        return response("usage: sudo -u user command [arg ...]\n", 1)
    if (command[0] not in {"id", "/usr/bin/id"}
        or command[1:] not in ([], ["-u"], ["-un"])):
        displayed = list(command)
        if displayed[0] == "id":
            displayed[0] = "/usr/bin/id"
        return response(f"Sorry, user {session.username} is not allowed to execute "
                        f"'{' '.join(displayed)}' as {target} on {profile.identity.hostname}.\n", 1)
    special = target in {"#-1", "#4294967295"}
    if target in {"root", "#0"} or (special and (options.patched or not options.runas_all)):
        return response("sudo: requested user is not permitted by policy\n", 1)
    if special:
        uid, user = 0, "root"
    elif target in {allowed_user, f"#{profile.identity.uid}"}:
        uid, user = profile.identity.uid, allowed_user
    elif options.runas_all and re.fullmatch(r"#[1-9][0-9]{0,9}", target):
        uid = int(target[1:])
        if uid >= 4294967295:
            return response("sudo: invalid user ID\n", 1)
        user = str(uid)
    else:
        return response("sudo: requested user is not permitted by policy\n", 1)
    if command[1:] == ["-u"]:
        return response(f"{uid}\n")
    if command[1:] == ["-un"]:
        return response(f"{user}\n")
    # Only the effective UID bypass is claimed. Group output is an explicit
    # simulation fixture, not a claim of binary-accurate sudo/PAM behavior.
    gid = profile.identity.uid
    return response(f"uid={uid}({user}) gid={gid}({allowed_user}) "
                    f"groups={gid}({allowed_user})\n")


def apache_2021(profile: Profile, spec: Behavior, interaction: Interaction,
                session: Session) -> Response | None:
    if interaction.protocol != "http":
        return None
    options = ApacheOptions.model_validate(spec.options)

    def response(body: str, status: int = 200, content_type: str = "text/plain") -> Response:
        return Response(body=body.encode(), status=status, behavior=spec.id,
                        headers=[(b"server", b"Apache/2.4.49"),
                                 (b"content-type", content_type.encode())])

    if interaction.method not in {"GET", "HEAD"}:
        result = response("Method not allowed\n", 405)
        result.headers.append((b"allow", b"GET, HEAD"))
        return result
    try:
        raw = interaction.raw_path.decode("ascii")
    except UnicodeDecodeError:
        return response("Bad request\n", 400)
    if raw == "/":
        return response(profile.files.get("/var/www/html/index.html", ""), content_type="text/html")
    if not raw.startswith(options.alias_prefix):
        return response("Not found\n", 404)
    suffix = raw[len(options.alias_prefix):]
    # One decode only. Double encoding is the later CVE-2021-42013 surface and
    # deliberately outside this profile's agreed fidelity.
    if "%25" in suffix.lower() or re.search(r"%(?![0-9a-fA-F]{2})", suffix):
        return response("Bad request\n", 400)
    try:
        decoded = unquote(suffix, encoding="utf-8", errors="strict")
    except UnicodeError:
        return response("Bad request\n", 400)
    if "\x00" in decoded:
        return response("Bad request\n", 400)
    traversal = any(part.lower() == ".%2e" for part in suffix.split("/"))
    path = posixpath.normpath(options.alias_root + "/" + decoded)
    if traversal:
        if options.protected:
            return response("Forbidden\n", 403)
    elif not path.startswith(options.alias_root + "/"):
        return response("Forbidden\n", 403)
    if path not in profile.files:
        return response("Not found\n", 404)
    return response(profile.files[path])


CVE_HANDLERS = {"sudo-2019-14287": sudo_2019, "apache-2021-41773": apache_2021}


def validate_cve(spec: Behavior, profile: Profile | None = None) -> None:
    if spec.kind == "sudo-2019-14287":
        SudoOptions.model_validate(spec.options)
    elif spec.kind == "apache-2021-41773":
        ApacheOptions.model_validate(spec.options)
    if profile:
        expected = "ssh" if spec.kind == "sudo-2019-14287" else "http"
        if profile.protocol != expected:
            raise ValueError(f"Behavior {spec.kind} requires protocol {expected}")
        if spec.kind == "apache-2021-41773" and set(profile.http_versions) != {"1.1"}:
            raise ValueError("Apache CVE-2021-41773 reference behavior supports HTTP/1.1 only")

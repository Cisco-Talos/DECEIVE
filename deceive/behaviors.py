from __future__ import annotations

import base64
import posixpath
import regex
import shlex

from deceive import virtual_files
from deceive.interaction import Interaction, Response, Session
from deceive.models import Behavior, Profile, Reply
from deceive.vulnerabilities import CVE_HANDLERS, validate_cve


def make_response(reply: Reply, behavior: str = "fallback") -> Response:
    import json
    body = (json.dumps(reply.body_json, ensure_ascii=False, separators=(',', ':')).encode()
            if reply.body_json is not None else base64.b64decode(reply.body_base64, validate=True)
            if reply.body_base64 is not None else reply.body.encode())
    stderr = (base64.b64decode(reply.stderr_base64, validate=True)
              if reply.stderr_base64 is not None else reply.stderr.encode())
    return Response(body=body, stderr=stderr, status=reply.status,
                    headers=[(k.lower().encode("ascii"), v.encode("latin-1"))
                             for k, v in reply.headers], close=reply.close,
                    exit_status=reply.exit_status, behavior=behavior)


def matches(spec: Behavior, interaction: Interaction, session: Session) -> bool:
    match = spec.match
    if match.command is not None and interaction.command != match.command:
        return False
    if match.command_regex is not None and not regex.fullmatch(match.command_regex, interaction.command, timeout=0.05):
        return False
    if match.path is not None and interaction.path != match.path:
        return False
    if match.method is not None and interaction.method != match.method:
        return False
    if match.body_contains is not None and match.body_contains.encode() not in interaction.body:
        return False
    for key, value in match.headers.items():
        if (key.lower().encode(), value.encode()) not in interaction.headers:
            return False
    return all(session.state.get(key) == value for key, value in match.state.items())


def rule(profile: Profile, spec: Behavior, interaction: Interaction,
         session: Session) -> Response | None:
    if not matches(spec, interaction, session):
        return None
    result = make_response(spec.reply, spec.id)
    result.transition = dict(spec.transition)
    return result


def identity(profile: Profile, spec: Behavior, interaction: Interaction,
             session: Session) -> Response | None:
    if interaction.protocol != "ssh":
        return None
    try:
        words = shlex.split(interaction.command)
    except ValueError:
        return Response(body=b"sh: syntax error\n", exit_status=2, behavior=spec.id)
    if not words:
        return Response(exit_status=session.last_exit_status, behavior=spec.id)
    facts = profile.identity
    user = session.state.get("user", session.username)
    uid = session.state.get("uid", str(0 if user == "root" else facts.uid))
    home = "/root" if session.username == "root" else f"/home/{session.username}"
    cwd = session.state.get("cwd", home)
    output = None
    transition = {}
    if words == ["hostname"]:
        output = facts.hostname + "\n"
    elif words in (["whoami"], ["id", "-un"]):
        output = user + "\n"
    elif words == ["id", "-u"]:
        output = uid + "\n"
    elif words == ["id"]:
        output = f"uid={uid}({user}) gid={uid}({user}) groups={uid}({user})\n"
    elif words == ["uname"]:
        output = "Linux\n"
    elif words == ["uname", "-r"]:
        output = facts.kernel + "\n"
    elif words == ["uname", "-m"]:
        output = facts.architecture + "\n"
    elif words == ["uname", "-a"]:
        output = f"Linux {facts.hostname} {facts.kernel} #1 SMP {facts.architecture} GNU/Linux\n"
    elif words == ["pwd"]:
        output = cwd + "\n"
    elif interaction.command.strip() in {"echo $?", 'echo "$?"'}:
        output = str(session.last_exit_status) + "\n"
    elif words and words[0] == "cat" and len(words) == 2:
        path = posixpath.normpath(posixpath.join(cwd, words[1]))
        if path in profile.files:
            output = profile.files[path]
        else:
            return Response(body=f"cat: {words[1]}: No such file or directory\n".encode(),
                            exit_status=1, behavior=spec.id)
    elif words and words[0] == "cd" and len(words) <= 2:
        path = words[1] if len(words) == 2 else home
        path = posixpath.normpath(posixpath.join(cwd, path))
        directories = {"/", "/home", home}
        directories.update(posixpath.dirname(p) for p in profile.files)
        if path not in directories:
            return Response(body=f"sh: cd: {path}: No such file or directory\n".encode(),
                            exit_status=1, behavior=spec.id)
        output = ""
        transition["cwd"] = path
    elif words and words[0] == "ls" and len(words) == 1:
        output = "\n".join(sorted(posixpath.basename(p) for p in profile.files
                                  if posixpath.dirname(p) == cwd)) + "\n"
    elif words == ["exit"] or words == ["logout"]:
        return Response(close=True, exit_status=session.last_exit_status, behavior=spec.id)
    elif (len(words) == 2 and words[0] == "exit" and words[1].isascii()
          and words[1].isdecimal() and len(words[1]) <= 3 and int(words[1]) <= 255):
        return Response(close=True, exit_status=int(words[1]), behavior=spec.id)
    if output is None:
        return None
    return Response(body=output.encode(), behavior=spec.id, transition=transition)


BUILTIN_BEHAVIORS = {"rule": rule, "identity": identity,
                     "virtual_files": virtual_files.respond, **CVE_HANDLERS}


def validate_behavior(spec: Behavior, profile: Profile | None = None) -> None:
    if spec.match.command_regex:
        try:
            regex.compile(spec.match.command_regex)
        except regex.error as exc:
            raise ValueError(f"Invalid command pattern in behavior {spec.id}") from exc
    if len(spec.transition) > 32 or any(len(k) > 128 or len(v) > 4096
                                         for k, v in spec.transition.items()):
        raise ValueError("State transitions exceed supported bounds")
    if set(spec.transition) & {"hostname", "os", "kernel", "architecture"}:
        raise ValueError("State transitions cannot change deployment identity")
    if spec.kind == "virtual_files":
        virtual_files.validate(spec, profile)
    elif spec.kind in CVE_HANDLERS:
        validate_cve(spec, profile)
    elif spec.kind in BUILTIN_BEHAVIORS and spec.options:
        raise ValueError(f"Behavior {spec.kind} does not accept options")

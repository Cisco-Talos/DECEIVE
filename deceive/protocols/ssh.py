from __future__ import annotations

import asyncio
import time

import asyncssh

from deceive.interaction import Interaction
from deceive.material import ssh_key
from deceive.models import Listener
from deceive.providers import ProviderError
from deceive.runtime import CapacityError, Runtime


class SSHConnection(asyncssh.SSHServer):
    def __init__(self, runtime: Runtime, listener: Listener):
        self.runtime = runtime
        self.listener = listener
        self.connection = None
        self.session = None
        self.process_started = False

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self.connection = conn
        try:
            if self.runtime.connections >= self.runtime.limits.sessions:
                raise CapacityError("Connection capacity exceeded")
            self.session = self.runtime.new_session(
                self.listener, source=conn.get_extra_info("peername"),
                destination=conn.get_extra_info("sockname"),
            )
        except CapacityError:
            conn.abort()
            return
        self.runtime.connections += 1
        self.session.expire = conn.close
        conn.set_extra_info(deceive_owner=self)
        self.runtime.emit(self.session, "SSH connection received")

    def connection_lost(self, exc: Exception | None) -> None:
        if self.session:
            self.runtime.connections -= 1
            self.runtime.emit(self.session, "SSH connection closed")
            task = asyncio.create_task(self.runtime.end_session(self.session))
            self.runtime.tasks.add(task)
            task.add_done_callback(self.runtime.tasks.discard)

    def begin_auth(self, username: str) -> bool:
        if self.session is None:
            return True
        self.session.username = username
        if self.listener.accounts.get(username) == "":
            self.runtime.emit(self.session, "Authentication success", username=username, password="")
            return False
        self.runtime.emit(self.session, "User attempting to authenticate", username=username)
        return True

    def password_auth_supported(self) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        return False

    def validate_password(self, username: str, password: str) -> bool:
        expected = self.listener.accounts.get(username, "*")
        success = expected == "*" or password == expected
        if self.session:
            self.runtime.emit(self.session, "Authentication success" if success else "Authentication failed",
                              username=username, password=password)
        return success


def prompt(runtime: Runtime, session) -> bytes:
    profile = runtime.profiles[session.listener]
    user = session.state.get("user", session.username)
    home = "/root" if session.username == "root" else f"/home/{session.username}"
    cwd = session.state.get("cwd", home)
    display = "~" + cwd[len(home):] if cwd == home or cwd.startswith(home + "/") else cwd
    suffix = "#" if user == "root" else "$"
    return f"{user}@{profile.identity.hostname}:{display}{suffix} ".encode()


async def handle_process(process: asyncssh.SSHServerProcess, runtime: Runtime,
                         listener: Listener) -> None:
    owner = process.get_extra_info("deceive_owner")
    if owner is None or owner.session is None or owner.process_started:
        process.exit(1)
        return
    owner.process_started = True
    session = owner.session
    session.username = process.get_extra_info("username", "guest")
    task = asyncio.current_task()
    task.set_name(session.id)
    runtime.tasks.add(task)
    command = process.command
    interactive = command is None
    exit_status = 0
    try:
        async with asyncio.timeout(runtime.limits.total_seconds):
            if not interactive:
                text = command.decode("utf-8", "replace") if isinstance(command, bytes) else command
                result = await runtime.respond(session, Interaction("ssh", command=text,
                    raw_input=command if isinstance(command, bytes) else command.encode()))
                process.stdout.write(result.body)
                exit_status = result.exit_status
                return
            profile = runtime.profiles[listener.name]
            process.stdout.write((profile.identity.banner + "\n").encode() + prompt(runtime, session))
            # Read bytes incrementally: readline() could accumulate an unbounded
            # attacker-controlled line before the configured limit is checked.
            line = bytearray()
            while not session.closed:
                data = await asyncio.wait_for(process.stdin.read(1), runtime.limits.idle_seconds)
                if not data:
                    break
                session.touched = time.monotonic()
                if data == b"\n":
                    result = await runtime.respond(session, Interaction(
                        "ssh", command=line.rstrip(b"\r").decode("utf-8", "replace"),
                        raw_input=bytes(line.rstrip(b"\r")), interactive=True
                    ))
                    line.clear()
                    process.stdout.write(result.body)
                    if result.close:
                        break
                    process.stdout.write(prompt(runtime, session))
                else:
                    line.extend(data)
                    if len(line) > runtime.limits.input_bytes:
                        raise ValueError("SSH input line exceeds configured limit")
    except (TimeoutError, ValueError, CapacityError, ProviderError) as exc:
        exit_status = 1
        runtime.emit(session, "Session limit or response failure", error_type=type(exc).__name__)
        process.stderr.write(b"Session unavailable.\n")
    except (asyncssh.BreakReceived, asyncssh.SignalReceived, asyncssh.ConnectionLost):
        pass
    finally:
        await runtime.end_session(session)
        process.exit(exit_status)
        runtime.tasks.discard(task)


class SSHServerHandle:
    def __init__(self, server, owners: list[SSHConnection], host: str):
        self.server = server
        self.owners = owners
        self.endpoints = [{"host": host, "port": server.get_port(), "transport": "tcp"}]

    async def close(self) -> None:
        self.server.close()
        await self.server.wait_closed()
        for owner in self.owners:
            if owner.connection:
                owner.connection.close()
        await asyncio.gather(*(o.connection.wait_closed() for o in self.owners if o.connection),
                             return_exceptions=True)


class SSHAdapter:
    api_version = 1

    async def start(self, runtime: Runtime, listener: Listener) -> SSHServerHandle:
        owners = []

        def factory() -> SSHConnection:
            owner = SSHConnection(runtime, listener)
            owners.append(owner)
            # Keep only live owners; closed owners must not accumulate forever.
            owners[:] = [o for o in owners if o.connection is None or not o.connection.is_closed()]
            return owner

        key = ssh_key(runtime.config.data_dir, listener.name, listener.host_key)
        server = await asyncssh.listen(
            listener.host, listener.port, server_factory=factory,
            server_host_keys=[str(key)], encoding=None, line_editor=False,
            server_version=runtime.profiles[listener.name].identity.ssh_version,
            login_timeout=min(runtime.limits.idle_seconds, 60),
            process_factory=lambda p: handle_process(p, runtime, listener),
        )
        return SSHServerHandle(server, owners, listener.host)

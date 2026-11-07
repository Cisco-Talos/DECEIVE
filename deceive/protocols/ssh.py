from __future__ import annotations

import asyncio
import re
import time
import uuid
from base64 import b64encode
from collections import deque

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
        self.channel_count = 0
        self.channel_sequence = 0

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
        self.session.context['ssh_client_version'] = self.connection.get_extra_info('client_version')
        if self.runtime.profiles[self.listener.name].ssh_auth:
            self.runtime.emit(self.session, "User attempting to authenticate", username=username)
            return True
        if self.listener.accounts.get(username) == "":
            self.runtime.emit(self.session, "Authentication success", username=username, password="")
            return False
        self.runtime.emit(self.session, "User attempting to authenticate", username=username)
        return True

    def password_auth_supported(self) -> bool:
        policy = self.runtime.profiles[self.listener.name].ssh_auth
        if policy:
            return policy.password_authentication
        return True

    def public_key_auth_supported(self) -> bool:
        return False

    def validate_password(self, username: str, password: str) -> bool:
        policy = self.runtime.profiles[self.listener.name].ssh_auth
        if policy:
            account = policy.accounts.get(username)
            permitted = (policy.password_authentication and account is not None
                         and account.shell not in {'/sbin/nologin', '/usr/sbin/nologin',
                                                   '/bin/false', '/usr/bin/false'}
                         and (username != 'root' or policy.permit_root_login == 'yes'))
            if permitted and account.shadow in {'$5$', '$6$'}:
                success = password == account.password
            elif permitted and account.shadow == '*':
                success = (not policy.use_pam and not policy.patched
                           and any(a.shadow in {'$5$', '$6$'} for a in policy.accounts.values())
                           and 257 <= len(password.encode('utf-8')) <= 1024)
            else:
                success = False
            if success and self.session:
                self.session.state['uid'] = str(account.uid)
        else:
            expected = self.listener.accounts.get(username, "*")
            success = expected == "*" or password == expected
        if self.session:
            self.runtime.emit(self.session, "Authentication success" if success else "Authentication failed",
                              username=username, password=password)
        return success


def prompt(runtime: Runtime, session) -> bytes:
    profile = runtime.profiles[session.listener]
    if profile.command_environment and profile.command_environment.dialect != 'linux':
        from deceive.commands import home
        cwd = session.state.get('cwd', home(profile, session))
        prefix = 'PS ' if profile.command_environment.dialect.startswith('powershell') else ''
        return (prefix + cwd + '> ').encode()
    from deceive.device.engine import prompt as device_prompt
    return device_prompt(profile, session)


def terminal_output(content: bytes, onlcr: bool) -> bytes:
    """Apply the PTY's newline convention without changing SSH exec output."""
    return re.sub(rb"(?<!\r)\n", b"\r\n", content) if onlcr else content


async def handle_process(process: asyncssh.SSHServerProcess, runtime: Runtime,
                         listener: Listener) -> None:
    from deceive.device.engine import ensure, pack, completion, ios_candidates
    from deceive.device.terminal import Decoder, LineEditor, Renderer, TerminalEvent
    from deceive.interaction import Session

    owner = process.get_extra_info('deceive_owner')
    if owner is None or owner.session is None or owner.channel_count >= runtime.limits.channel_limit:
        process.exit(1)
        return
    owner.channel_count += 1
    owner.channel_sequence += 1
    parent = owner.session
    channel_id = 'channel-' + uuid.uuid4().hex
    session = Session(parent.id, parent.listener, process.get_extra_info('username', 'guest'),
                      parent.context | {'channel_id': channel_id}, state=dict(parent.state),
                      lock=asyncio.Lock(), parent=parent)
    runtime.channels[channel_id] = session
    task = asyncio.current_task()
    task.set_name(parent.id + '/' + channel_id)
    runtime.tasks.add(task)
    profile = runtime.profiles[listener.name]
    interactive = process.command is None
    onlcr = (process.get_terminal_type() is not None
             and process.get_terminal_mode(asyncssh.PTY_ONLCR) == 1)
    echo = (process.get_terminal_type() is not None
            and process.get_terminal_mode(asyncssh.PTY_ECHO) == 1)
    columns, rows, _, _ = process.get_terminal_size()
    renderer = Renderer(max(20, min(columns or 80, runtime.limits.screen_columns)),
                        max(5, min(rows or 24, runtime.limits.screen_rows)),
                        process.get_terminal_type() or 'dumb')
    decoder, editor = Decoder(), LineEditor(runtime.limits.input_bytes)
    pending = None
    reading = None
    queued = deque()
    exit_status = 0
    screen = False
    failed = False
    terminal_sequence = 0
    last_refresh = time.monotonic()

    async def send(data: bytes, *, translate: bool = False) -> None:
        nonlocal terminal_sequence
        if len(data) > runtime.limits.output_bytes:
            raise ValueError('Terminal output exceeds configured limit')
        delivered = terminal_output(data, onlcr) if translate else data
        process.stdout.write(delivered)
        await process.stdout.drain()
        if delivered:
            terminal_sequence += 1
            runtime.emit(session, 'Terminal output', details=b64encode(delivered).decode(),
                         terminal_sequence=terminal_sequence)

    def spawn(text: str) -> asyncio.Task:
        request = Interaction('ssh', command=text, raw_input=text.encode(), interactive=True)
        work = asyncio.create_task(runtime.respond(session, request))
        runtime.tasks.add(work)
        work.add_done_callback(runtime.tasks.discard)
        return work

    async def cancel_pending() -> None:
        nonlocal pending
        if pending:
            session.generation += 1
            pending.cancel()
            # retrieve cancellation/failure even if an SDK suppresses cancellation
            pending.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)
            pending = None

    try:
        async with asyncio.timeout(runtime.limits.total_seconds):
            if not interactive:
                command = process.command
                text = command.decode('utf-8', 'replace') if isinstance(command, bytes) else command
                result = await runtime.respond(session, Interaction('ssh', command=text,
                    raw_input=command if isinstance(command, bytes) else command.encode()))
                process.stdout.write(result.body)
                process.stderr.write(result.stderr)
                await process.stdout.drain()
                await process.stderr.drain()
                exit_status = result.exit_status
                return
            await send((profile.identity.banner + '\n').encode(), translate=True)
            await send(prompt(runtime, session))
            while not session.closed:
                if pending is not None and pending.done():
                    result = pending.result()
                    pending = None
                    exit_status = result.exit_status
                    device = ensure(profile, session)
                    page_length = int(session.state.get('terminal_length', str(renderer.rows - 1)))
                    paged = (pack(profile).platform == 'ios'
                             and page_length > 0
                             and len(result.body.splitlines()) > page_length)
                    if paged:
                        from deceive.device.apps import Application
                        device.application = Application('ios-pager', '--More--', result.body.decode('utf-8', 'replace'),
                                                         page_length=page_length)
                    else:
                        for _, content in result.chunks or [('stdout', result.body), ('stderr', result.stderr)]:
                            await send(content, translate=True)
                    if result.close:
                        break
                    device = ensure(profile, session)
                    app = device.application
                    if app:
                        if not renderer.supported and app.kind != 'ios-pager':
                            device.application = None
                            exit_status = 1
                            await send(b'Application requires xterm, xterm-256color or vt100.\n', translate=True)
                        else:
                            screen = True
                            await send(app.enter(renderer) + app.render(profile, session, renderer))
                    if not screen:
                        await send(prompt(runtime, session))
                if queued and pending is None:
                    event = queued.popleft()
                else:
                    if reading is None:
                        reading = asyncio.create_task(process.stdin.read(1))
                    waiters = [reading] + ([pending] if pending else [])
                    done, _ = await asyncio.wait(waiters, timeout=.05, return_when=asyncio.FIRST_COMPLETED)
                    now = time.monotonic()
                    if now - session.touched >= runtime.limits.idle_seconds:
                        raise TimeoutError('SSH channel idle timeout')
                    app = ensure(profile, session).application
                    if screen and app and app.kind == 'top' and now - last_refresh >= app.refresh_seconds:
                        device = ensure(profile, session)
                        from deceive.device.engine import sample_resources
                        sample_resources(profile, session, app.refresh_seconds)
                        await send(app.render(profile, session, renderer))
                        last_refresh = now
                    if reading not in done:
                        if decoder.escape and not done:
                            queued.extend(decoder.flush_escape())
                        continue
                    try:
                        data = reading.result()
                    except asyncssh.TerminalSizeChanged as exc:
                        renderer.columns = max(20, min(exc.width or 80, runtime.limits.screen_columns))
                        renderer.rows = max(5, min(exc.height or 24, runtime.limits.screen_rows))
                        runtime.emit(session, 'Terminal event', event='resize', columns=renderer.columns, rows=renderer.rows)
                        if screen and app:
                            await send(app.render(profile, session, renderer))
                        reading = None
                        continue
                    except asyncssh.SignalReceived as exc:
                        data = b'\x03' if exc.signal == 'INT' else b'\x04'
                    reading = None
                    if not data:
                        break
                    runtime.emit(session, 'Terminal input', details=b64encode(data).decode())
                    session.touched = parent.touched = time.monotonic()
                    events = decoder.feed(data)
                    if not events:
                        continue
                    event = events[0]
                    queued.extend(events[1:])
                device = ensure(profile, session)
                if event.kind in {'interrupt', 'suspend'} and not (screen and device.application):
                    await cancel_pending()
                    queued.clear()
                    editor.clear()
                    if not device.dialogue or device.dialogue.get('kind') != 'python':
                        device.dialogue = None
                    if event.kind == 'suspend' and pack(profile).platform == 'ios':
                        device.mode = 'privileged'
                    if screen:
                        screen, device.application = False, None
                        await send(renderer.leave())
                    session.last_exit_status = 130
                    runtime.emit(session, 'Terminal event', event=event.kind)
                    await send(b'^Z\n' if event.kind == 'suspend' else b'^C\n', translate=True)
                    await send(prompt(runtime, session))
                    continue
                if pending:
                    if len(queued) >= runtime.limits.input_bytes:
                        raise ValueError('Input queue exceeds configured limit')
                    queued.append(event)
                    continue
                if screen and device.application:
                    app = device.application
                    app.handle(event, profile, session, renderer)
                    device.revision += 1
                    runtime.emit(session, 'Terminal event', event=event.kind,
                                 application=app.kind, details=b64encode(event.text.encode()).decode(),
                                 state_revision=device.revision)
                    if app.done:
                        screen, device.application = False, None
                        await send(app.leave(renderer))
                        await send(prompt(runtime, session))
                    else:
                        await send(app.render(profile, session, renderer))
                        if app.done:
                            screen, device.application = False, None
                            await send(app.leave(renderer))
                            await send(prompt(runtime, session))
                    continue
                if event.kind == 'eof' and not editor.text:
                    if device.dialogue and device.dialogue.get('kind') == 'python':
                        pending = spawn('exit()')
                        continue
                    if device.stack:
                        pending = spawn('exit')
                        continue
                    break
                if event.kind == 'enter':
                    text = editor.clear()
                    if echo:
                        await send(b'\r\n')
                    if not device.dialogue:
                        editor.remember(text)
                    pending = spawn(text)
                elif event.kind == 'tab':
                    choices = completion(profile, session, editor.text)
                    if len(choices) == 1:
                        editor.text, editor.cursor = choices[0], len(choices[0])
                    elif choices:
                        await send(('\n' + '  '.join(choices) + '\n').encode(), translate=True)
                    if echo:
                        await send(editor.redraw(prompt(runtime, session)))
                elif event.kind == 'text' and event.text == '?' and pack(profile).platform == 'ios':
                    await send(('\n' + '\n'.join(ios_candidates(device.mode, editor.text)) + '\n').encode(), translate=True)
                    await send(editor.redraw(prompt(runtime, session)))
                else:
                    previous, previous_cursor = editor.text, editor.cursor
                    editor.handle(event)
                    hidden = device.dialogue and (device.dialogue.get('kind') in {'enable', 'password'} or device.dialogue.get('echo') is False)
                    if echo and not hidden:
                        if event.kind == 'text' and previous_cursor == len(previous):
                            await send(event.text.encode())
                        elif event.kind == 'backspace' and previous_cursor == len(previous) and previous:
                            await send(b'\b \b')
                        else:
                            await send(editor.redraw(prompt(runtime, session)))
    except (TimeoutError, ValueError, CapacityError, ProviderError) as exc:
        exit_status = 1
        runtime.emit(session, 'Session limit or response failure', error_type=type(exc).__name__)
        process.stderr.write(b'Session unavailable.\n')
        failed = True
    except (asyncssh.BreakReceived, asyncssh.SignalReceived, asyncssh.ConnectionLost):
        pass
    finally:
        await cancel_pending()
        if reading:
            reading.cancel()
            await asyncio.gather(reading, return_exceptions=True)
        if screen and not process.channel.is_closing():
            app = ensure(profile, session).application
            try:
                await send(app.leave(renderer) if app else renderer.leave())
            except (asyncssh.Error, ConnectionError):
                pass
        await runtime.end_session(session)
        runtime.channels.pop(channel_id, None)
        owner.channel_count -= 1
        process.exit(exit_status)
        if failed:
            await runtime.end_session(parent)
            asyncio.get_running_loop().call_later(.02, owner.connection.close)
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

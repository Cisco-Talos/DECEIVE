"""Deterministic full-screen applications over private virtual objects."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from deceive.device.terminal import Renderer, TerminalEvent, columns

if TYPE_CHECKING:
    from deceive.interaction import Session
    from deceive.models import Profile


def cpu_time(seconds: float, platform: str) -> str:
    minutes, remainder = divmod(int(seconds * 100), 6000)
    whole, hundredths = divmod(remainder, 100)
    if platform == 'freebsd':
        return f'{minutes}:{whole:02}'
    prefix = f'{minutes:02}' if platform == 'macos' else str(minutes)
    return f'{prefix}:{whole:02}.{hundredths:02}'


@dataclass
class Application:
    kind: str
    name: str = ''
    text: str = ''
    original: str = ''
    row: int = 0
    col: int = 0
    offset: int = 0
    mode: str = 'normal'
    entry: str = ''
    message: str = ''
    undo: list[tuple[str, int, int, bool]] = field(default_factory=list)
    has_lines: bool = False
    original_has_lines: bool = False
    edit_pending: bool = False
    selected: int = 0
    ticks: int = 0
    reverse: bool = False
    refresh_seconds: float = 1.0
    page_length: int | None = None
    page_pending: bool = True
    page_step: int | None = None
    done: bool = False

    def enter(self, renderer: Renderer) -> bytes:
        return b'' if self.kind == 'ios-pager' else renderer.enter()

    def leave(self, renderer: Renderer) -> bytes:
        if self.kind == 'ios-pager':
            return b'' if self.row >= len(self.text.splitlines()) else b'\r\x1b[K'
        return renderer.leave()

    @classmethod
    def open(cls, name: str, args: list[str], profile: Profile, session: Session) -> Application:
        from deceive.device.engine import file_view, path, permitted
        filename = args[0] if args else ''
        files, dirs = file_view(profile, session)
        if name in {'vi', 'less'}:
            if not filename:
                raise ValueError(f'{name}: filename required')
            key = path(profile, session, filename)
            if key in dirs or (key in files and not permitted(profile, session, key, 'read')):
                raise ValueError('File unavailable')
            if name == 'less' and key not in files:
                raise ValueError('File not found')
            body = files.get(key, b'')
            if len(body) > 65536 or b'\x00' in body:
                raise ValueError('Application supports bounded text files only')
            text = body.decode('utf-8', 'replace')
            if name == 'vi':
                text = text.removesuffix('\n')
            return cls(name, key, text, text, has_lines=bool(body), original_has_lines=bool(body))
        return cls(name)

    def snapshot(self) -> None:
        self.undo.append((self.text, self.row, self.col, self.has_lines))
        self.undo = self.undo[-16:]
        while sum(len(state[0].encode()) for state in self.undo) > 262144:
            self.undo.pop(0)

    def lines(self) -> list[str]:
        return (self.text.removesuffix('\n') if self.kind == 'less' else self.text).split('\n')

    def position(self) -> int:
        lines = self.lines()
        self.row = min(self.row, len(lines) - 1)
        limit = len(lines[self.row]) if self.mode == 'insert' else max(0, len(lines[self.row]) - 1)
        self.col = min(self.col, limit)
        return sum(len(line) + 1 for line in lines[:self.row]) + self.col

    def move(self, kind: str, height: int) -> None:
        if kind in {'down', 'j'}: self.row += 1
        elif kind in {'up', 'k'}: self.row = max(0, self.row - 1)
        elif kind in {'left', 'h'}: self.col = max(0, self.col - 1)
        elif kind in {'right', 'l'}: self.col += 1
        elif kind in {'home', '0'}: self.col = 0
        elif kind in {'end', '$'}: self.col = len(self.lines()[min(self.row, len(self.lines()) - 1)])
        elif kind == 'pagedown': self.row += height
        elif kind == 'pageup': self.row = max(0, self.row - height)
        self.position()

    def save(self, profile: Profile, session: Session) -> None:
        from deceive.device.engine import write
        body = self.text + ('\n' if self.has_lines or self.text else '')
        write(profile, session, self.name, body.encode())
        self.original = self.text
        self.original_has_lines = self.has_lines
        self.message = f'"{self.name}" written'

    def search(self, value: str) -> None:
        if self.kind == 'vi' and value:
            found = self.text.find(value, self.position() + 1)
            if found < 0:
                found = self.text.find(value)
            if found >= 0:
                prefix = self.text[:found]
                self.row = prefix.count('\n')
                self.col = len(prefix.rsplit('\n', 1)[-1])
                self.message = '/' + value
                return
        for index in range(self.row + 1, len(self.lines())):
            if value in self.lines()[index]:
                self.row = index
                self.col = self.lines()[index].index(value)
                self.message = '/' + value
                return
        self.message = 'Pattern not found: ' + value

    def handle(self, event: TerminalEvent, profile: Profile, session: Session, renderer: Renderer) -> None:
        from deceive.device.engine import ensure
        device = ensure(profile, session)
        kind, key = event.kind, event.text
        if self.kind == 'ios-pager':
            if kind in {'interrupt', 'eof', 'suspend'} or key == 'q':
                self.done = True
            elif key == ' ' or kind == 'enter':
                self.page_pending = True
                self.page_step = 1 if kind == 'enter' else self.page_length
            return
        if kind == 'interrupt' and self.kind in {'less', 'vi'}:
            if self.kind == 'vi' and self.mode == 'insert':
                self.col = max(0, self.col - 1)
            self.edit_pending = False
            self.mode, self.entry, self.message = 'normal', '', ''
            return
        if kind in {'interrupt', 'suspend', 'eof'}:
            self.done = True
            return
        if self.kind == 'top':
            if self.mode in {'kill', 'delay'}:
                if kind == 'escape': self.mode, self.entry = 'normal', ''
                elif kind == 'backspace': self.entry = self.entry[:-1]
                elif kind == 'enter':
                    if self.mode == 'kill':
                        pid = int(self.entry) if self.entry.isdigit() else -1
                        if pid in device.processes and pid not in {1, 120}:
                            del device.processes[pid]
                            self.message = f'Process {pid} removed'
                        else: self.message = 'Operation not permitted or no such process'
                    else:
                        try:
                            delay = float(self.entry)
                        except ValueError:
                            delay = 0
                        if .1 <= delay <= 60:
                            self.refresh_seconds = delay
                            self.message = f'Delay: {delay:g} seconds'
                        else: self.message = 'Delay must be between 0.1 and 60 seconds'
                    self.mode, self.entry = 'normal', ''
                elif kind == 'text': self.entry = (self.entry + key)[:10]
                return
            if key == 'q': self.done = True
            elif key == 'N': self.reverse = False
            elif key == 'R': self.reverse = not self.reverse
            elif key in {'s', 'd'}: self.mode, self.entry = 'delay', ''
            elif kind in {'down', 'up'}: self.selected = max(0, min(len(device.processes) - 1, self.selected + (1 if kind == 'down' else -1)))
            elif key == 'k': self.mode, self.entry = 'kill', ''
            return
        if self.kind == 'device-menu':
            if self.mode == 'normal':
                if key == 'q': self.done = True
                elif kind in {'up', 'down'}: self.selected = (self.selected + (1 if kind == 'down' else -1)) % 2
                elif kind == 'enter': self.mode, self.entry = 'form', ''
            elif self.mode == 'form':
                if kind == 'escape': self.mode = 'normal'
                elif kind == 'text': self.entry = (self.entry + key)[:63]
                elif kind == 'backspace': self.entry = self.entry[:-1]
                elif kind == 'enter':
                    import re
                    if self.selected == 0 and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,62}', self.entry):
                        self.message = 'Invalid hostname'
                    elif not self.entry: self.message = 'Value required'
                    else: self.mode = 'confirm'
            elif self.mode == 'confirm':
                if key == 'y':
                    if self.selected == 0:
                        device.hostname = self.entry
                        session.virtual_files['/etc/hostname'] = (self.entry + '\n').encode()
                    else: device.configuration['description'] = self.entry
                    self.message, self.mode = 'Applied', 'normal'
                elif key == 'n' or kind == 'escape': self.message, self.mode = 'Cancelled', 'normal'
            return
        if self.kind == 'less':
            if self.mode == 'search':
                if kind == 'enter': self.search(self.entry); self.mode = 'normal'
                elif kind == 'escape': self.mode = 'normal'
                elif kind == 'backspace': self.entry = self.entry[:-1]
                elif kind == 'text': self.entry = (self.entry + key)[:256]
            elif key == 'q': self.done = True
            elif key == '/': self.mode, self.entry = 'search', ''
            elif key == 'g': self.row = 0
            elif key == 'G': self.row = len(self.lines()) - 1
            elif key == ' ': self.move('pagedown', self.page_length or renderer.rows - 2)
            else: self.move(key or kind, self.page_length or renderer.rows - 2)
            return
        if self.mode in {'command', 'search'}:
            if kind == 'escape': self.mode = 'normal'
            elif kind == 'backspace': self.entry = self.entry[:-1]
            elif kind == 'text': self.entry = (self.entry + key)[:256]
            elif kind == 'enter':
                command = self.entry
                if self.mode == 'search': self.search(command)
                elif command in {'w', 'wq', 'x'}:
                    try:
                        self.save(profile, session)
                        if command != 'w': self.done = True
                    except ValueError as exc: self.message = str(exc)
                elif command in {'q', 'q!'}:
                    if command == 'q' and (self.text != self.original or self.has_lines != self.original_has_lines):
                        self.message = 'No write since last change (add ! to override)'
                    else: self.done = True
                else: self.message = 'Not an editor command: ' + command
                self.mode = 'normal'
            return
        if self.mode == 'insert':
            if kind == 'escape':
                self.mode, self.edit_pending = 'normal', False
                self.col = max(0, self.col - 1)
            elif kind in {'text', 'enter', 'backspace', 'delete'}:
                if self.edit_pending:
                    self.snapshot()
                    self.edit_pending = False
                index = self.position()
                if kind == 'backspace' and index:
                    self.text = self.text[:index - 1] + self.text[index:]
                    if self.col: self.col -= 1
                    else:
                        self.row = max(0, self.row - 1)
                        self.col = len(self.lines()[self.row])
                elif kind == 'delete': self.text = self.text[:index] + self.text[index + 1:]
                elif kind in {'text', 'enter'}:
                    value = key if kind == 'text' else '\n'
                    if len((self.text + value).encode()) > 65536:
                        self.message = 'Buffer capacity exceeded'
                        return
                    self.text = self.text[:index] + value + self.text[index:]
                    self.has_lines = True
                    if kind == 'enter': self.row, self.col = self.row + 1, 0
                    else: self.col += len(value)
            else: self.move(kind, renderer.rows - 2)
            return
        if key in {'i', 'a', 'o'}:
            if key == 'o' and len(self.text.encode()) >= 65536:
                self.message = 'Buffer capacity exceeded'
                return
            self.edit_pending = True
            self.mode = 'insert'
            if key == 'a': self.col += 1; self.position()
            if key == 'o':
                self.snapshot()
                self.edit_pending = False
                lines = self.lines()
                lines.insert(self.row + 1, '')
                self.text = '\n'.join(lines)
                self.has_lines = True
                self.row, self.col = self.row + 1, 0
            self.mode = 'insert'
        elif key in {':', '/'}: self.mode, self.entry = ('command' if key == ':' else 'search'), ''
        elif key == 'u' and self.undo:
            self.text, self.row, self.col, self.has_lines = self.undo.pop()
            self.position()
        elif key == 'x':
            if self.col < len(self.lines()[self.row]):
                self.snapshot()
                index = self.position()
                self.text = self.text[:index] + self.text[index + 1:]
        elif key == 'G': self.row = len(self.lines()) - 1; self.position()
        else: self.move(key or kind, renderer.rows - 2)

    def render(self, profile: Profile, session: Session, renderer: Renderer) -> bytes:
        from deceive.device.engine import ensure
        device = ensure(profile, session)
        if self.kind == 'ios-pager':
            from deceive.device.terminal import safe_text
            if not self.page_pending:
                return b''
            lines = self.text.splitlines()
            end = min(len(lines), self.row + (self.page_step or self.page_length or renderer.rows - 1))
            content = '\r\x1b[K' if self.row else ''
            content += ''.join(safe_text(line) + '\r\n' for line in lines[self.row:end])
            self.row, self.page_pending = end, False
            self.done = end == len(lines)
            return (content + ('' if self.done else '--More--')).encode()
        if self.kind == 'top':
            from deceive.device.engine import pack, resources
            self.ticks += 1
            facts = resources(profile, session)
            processes = sorted(facts['processes'], key=lambda p: p['pid'], reverse=self.reverse)
            count = len(processes)
            running = sum(p['state'] == 'R' for p in processes)
            user, system = facts['cpu_user_percent'], facts['cpu_system_percent']
            idle = 100 - user - system
            total, used, free = (facts['memory_' + k + '_kib'] // 1024 for k in ['total', 'used', 'free'])
            platform = pack(profile).platform
            if platform == 'macos':
                lines = [f'Processes: {count} total, {running} running, {count - running} sleeping',
                         'Load Avg: 0.03, 0.02, 0.01',
                         f'CPU usage: {user:.1f}% user, {system:.1f}% sys, {idle:.1f}% idle',
                         f'PhysMem: {used}M used, {free}M unused.', 'VM: 0 swapins, 0 swapouts.', '',
                         '  PID COMMAND          %CPU      TIME     MEM STATE']
                lines += [f'{p["pid"]:5} {p["command"]:<16} {p["cpu_percent"]:4.1f} '
                          f'{cpu_time(p["cpu_seconds"], platform):>9} {p["resident_kib"] // 1024:6}M {p["state"]}' for p in processes]
            elif platform == 'freebsd':
                lines = [f'last pid: {max(device.processes, default=0)}; load averages: 0.03, 0.02, 0.01',
                         f'{count} processes: {running} running, {count - running} sleeping',
                         f'CPU: {user:.1f}% user, 0.0% nice, {system:.1f}% system, 0.0% interrupt, {idle:.1f}% idle',
                         f'Mem: {used}M Active, {free}M Free', 'Swap: 2048M Total, 2048M Free', '',
                         '  PID USERNAME     SIZE    RES STATE    TIME   WCPU COMMAND']
                lines += [f'{p["pid"]:5} {p["user"]:<10} {p["virtual_kib"]:6}K {p["resident_kib"]:6}K '
                          f'{"run" if p["state"] == "R" else "sleep":5} {cpu_time(p["cpu_seconds"], platform):>6} '
                          f'{p["cpu_percent"]:5.1f}% {p["command"]}' for p in processes]
            else:
                clock = facts['uptime_seconds'] % 86400
                lines = [f'top - {clock // 3600:02}:{clock // 60 % 60:02}:{clock % 60:02} up 1 day, 1 user, load average: 0.03, 0.02, 0.01',
                         f'Tasks: {count} total, {running} running, {count - running} sleeping, 0 stopped, 0 zombie',
                         f'%Cpu(s): {user:.1f} us, {system:.1f} sy, 0.0 ni, {idle:.1f} id, 0.0 wa',
                         f'MiB Mem : {total} total, {free} free, {used} used',
                         'MiB Swap: 2048 total, 2048 free, 0 used', '',
                         '  PID USER       VIRT    RES S %CPU %MEM     TIME+ COMMAND']
                lines += [f'{p["pid"]:5} {p["user"]:<8} {p["virtual_kib"]:6} {p["resident_kib"]:6} '
                          f'{p["state"]} {p["cpu_percent"]:4.1f} '
                          f'{100 * p["resident_kib"] / facts["memory_total_kib"]:4.1f} '
                          f'{cpu_time(p["cpu_seconds"], platform):>9} {p["command"]}' for p in processes]
            status = ('PID to kill: ' + self.entry if self.mode == 'kill' else
                      'Change delay (0.1-60 seconds): ' + self.entry if self.mode == 'delay' else
                      self.message or 'q quit | s delay | N PID | R reverse | k kill')
            return renderer.draw(lines, status)
        if self.kind == 'device-menu':
            lines = ['Device configuration', 'Hostname: ' + device.hostname,
                     'Description: ' + device.configuration['description'], '',
                     ('> ' if self.selected == 0 else '  ') + 'Edit hostname',
                     ('> ' if self.selected == 1 else '  ') + 'Edit description']
            status = ('Value: ' + self.entry if self.mode == 'form' else 'Apply changes? [y/n]' if self.mode == 'confirm' else self.message or 'Arrows select | Enter edit | q quit')
            return renderer.draw(lines, status)
        if self.kind == 'less':
            self.row = max(0, min(self.row, max(0, len(self.lines()) - renderer.rows + 1)))
            self.offset = self.row
        else:
            if self.row < self.offset: self.offset = self.row
            if self.row >= self.offset + renderer.rows - 1: self.offset = self.row - renderer.rows + 2
        lines = self.lines()[self.offset:self.offset + renderer.rows - 1]
        lines += ['~'] * max(0, renderer.rows - 1 - len(lines))
        status = ('/' if self.mode == 'search' else ':') + self.entry if self.mode in {'search', 'command'} else self.message or f'{self.name} {"-- INSERT --" if self.mode == "insert" else ""} {self.row + 1}/{len(self.lines())}'
        cursor = (self.row - self.offset + 1, columns(self.lines()[self.row][:self.col]) + 1) if self.kind == 'vi' else None
        return renderer.draw(lines, status, cursor)

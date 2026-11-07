"""Incremental terminal input and deterministic screen rendering."""
from __future__ import annotations

import codecs
from dataclasses import dataclass
import unicodedata


@dataclass(frozen=True)
class TerminalEvent:
    kind: str
    text: str = ''


KEYS = {'\x1b[A': 'up', '\x1b[B': 'down', '\x1b[C': 'right', '\x1b[D': 'left',
        '\x1b[H': 'home', '\x1b[F': 'end', '\x1b[1~': 'home', '\x1b[4~': 'end',
        '\x1b[3~': 'delete', '\x1b[5~': 'pageup', '\x1b[6~': 'pagedown',
        '\x1bOA': 'up', '\x1bOB': 'down', '\x1bOC': 'right', '\x1bOD': 'left',
        '\x1bOH': 'home', '\x1bOF': 'end', '\x1b[200~': 'paste-start',
        '\x1b[201~': 'paste-end'}


def safe_text(text: str) -> str:
    """App content cannot inject terminal commands; only the renderer emits controls."""
    return ''.join(c if c == '\t' or not unicodedata.category(c).startswith('C') else '?'
                   for c in text)


def columns(text: str) -> int:
    return sum(0 if unicodedata.combining(c) else
               2 if unicodedata.east_asian_width(c) in {'W', 'F'} else 1 for c in text)


def clip(text: str, width: int) -> str:
    result, used = [], 0
    for char in text:
        size = columns(char)
        if used + size > width:
            break
        result.append(char)
        used += size
    return ''.join(result)


class Decoder:
    def __init__(self) -> None:
        self.utf8 = codecs.getincrementaldecoder('utf-8')('replace')
        self.escape = ''
        self.cr = False
        self.paste = False

    def flush_escape(self) -> list[TerminalEvent]:
        if not self.escape:
            return []
        self.escape = ''
        return [TerminalEvent('escape')]

    def feed(self, data: bytes) -> list[TerminalEvent]:
        events = []
        for c in self.utf8.decode(data):
            if self.escape or c == '\x1b':
                self.escape += c
                if self.escape in KEYS:
                    key = KEYS[self.escape]
                    self.escape = ''
                    if key.startswith('paste-'):
                        self.paste = key == 'paste-start'
                    else:
                        events.append(TerminalEvent(key))
                elif len(self.escape) > 32 or not any(k.startswith(self.escape) for k in KEYS):
                    remainder = self.escape[1:]
                    self.escape = ''
                    events.append(TerminalEvent('escape'))
                    if not remainder.startswith(('[', 'O')):
                        events.extend(self.feed(remainder.encode()))
                continue
            if c == '\n' and self.cr:
                self.cr = False
                continue
            self.cr = c == '\r'
            if c in '\r\n':
                # Paste does not submit commands; the user must explicitly press Enter.
                events.append(TerminalEvent('text', ' ') if self.paste else TerminalEvent('enter'))
            elif c in '\x08\x7f':
                events.append(TerminalEvent('backspace'))
            elif c in '\x03\x04\x1a\t\x01\x05\x15\x0c':
                events.append(TerminalEvent({'\x03': 'interrupt', '\x04': 'eof', '\x1a': 'suspend',
                    '\t': 'tab', '\x01': 'home', '\x05': 'end', '\x15': 'kill-line',
                    '\x0c': 'redraw'}[c]))
            elif c >= ' ':
                events.append(TerminalEvent('text', c))
        return events


class LineEditor:
    def __init__(self, maximum: int) -> None:
        self.text = ''
        self.cursor = 0
        self.maximum = maximum
        self.history: list[str] = []
        self.recall = 0
        self.draft = ''

    def clear(self) -> str:
        text = self.text
        self.text, self.cursor, self.recall = '', 0, len(self.history)
        return text

    def remember(self, text: str) -> None:
        if text.strip():
            self.history.append(text)
            self.history = self.history[-128:]
        while sum(len(item.encode()) for item in self.history) > 65536:
            del self.history[0]
        self.recall = len(self.history)

    def handle(self, event: TerminalEvent) -> None:
        kind = event.kind
        if kind == 'text':
            value = self.text[:self.cursor] + event.text + self.text[self.cursor:]
            if len(value.encode()) > self.maximum:
                raise ValueError('SSH input line exceeds configured limit')
            self.text = value
            self.cursor += len(event.text)
        elif kind == 'left':
            self.cursor = max(0, self.cursor - 1)
        elif kind == 'right':
            self.cursor = min(len(self.text), self.cursor + 1)
        elif kind == 'home':
            self.cursor = 0
        elif kind == 'end':
            self.cursor = len(self.text)
        elif kind == 'backspace' and self.cursor:
            self.text = self.text[:self.cursor - 1] + self.text[self.cursor:]
            self.cursor -= 1
        elif kind == 'delete':
            self.text = self.text[:self.cursor] + self.text[self.cursor + 1:]
        elif kind == 'kill-line':
            self.clear()
        elif kind in {'up', 'down'}:
            if self.recall == len(self.history):
                self.draft = self.text
            self.recall = max(0, min(len(self.history), self.recall + (-1 if kind == 'up' else 1)))
            self.text = self.history[self.recall] if self.recall < len(self.history) else self.draft
            self.cursor = len(self.text)

    def redraw(self, prompt: bytes) -> bytes:
        suffix = columns(self.text[self.cursor:])
        return (b'\r\x1b[2K' + prompt + self.text.encode()
                + (f'\x1b[{suffix}D'.encode() if suffix else b''))


class Renderer:
    def __init__(self, columns: int = 80, rows: int = 24, term: str = 'xterm') -> None:
        self.columns, self.rows, self.term = columns, rows, term

    @property
    def supported(self) -> bool:
        return self.term in {'xterm', 'xterm-256color', 'vt100'}

    def enter(self) -> bytes:
        return (b'\x1b[?1049h' if self.term.startswith('xterm') else b'\x1b7') + b'\x1b[?25l'

    def leave(self) -> bytes:
        return b'\x1b[0m\x1b[r\x1b[?25h' + (
            b'\x1b[?1049l' if self.term.startswith('xterm') else b'\x1b[2J\x1b8')

    def draw(self, lines: list[str], status: str, cursor: tuple[int, int] | None = None) -> bytes:
        output = bytearray(b'\x1b[H\x1b[2J')
        for row, line in enumerate(lines[:self.rows - 1], 1):
            output.extend(f'\x1b[{row};1H'.encode())
            output.extend(clip(safe_text(line).expandtabs(8), self.columns).encode())
        output.extend(f'\x1b[{self.rows};1H\x1b[7m'.encode())
        output.extend(clip(safe_text(status), self.columns).encode())
        output.extend(b'\x1b[0m')
        if cursor:
            row, col = cursor
            output.extend(f'\x1b[{max(1, min(row, self.rows - 1))};{max(1, min(col, self.columns))}H'.encode())
            output.extend(b'\x1b[?25h')
        return bytes(output)

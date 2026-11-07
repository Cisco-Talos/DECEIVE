"""Assessment-side VT emulator with the xterm alternate buffer used by our renderer."""
from __future__ import annotations

from typing import Any

import pyte
from pyte.screens import StaticDefaultDict


class Screen(pyte.Screen):
    """Keep primary content/cursor across DECSET 1049, which base pyte ignores."""

    def __init__(self, columns: int, lines: int) -> None:
        self._primary: dict[str, Any] | None = None
        super().__init__(columns, lines)

    def _bind_buffer(self) -> None:
        self.buffer.default_factory = lambda: StaticDefaultDict(self.default_char)

    def set_mode(self, *modes: int, **kwargs: Any) -> None:
        if kwargs.get('private') and 1049 in modes:
            if self._primary is None:
                primary = self.__dict__.copy()
                alternate = pyte.Screen(self.columns, self.lines)
                self.__dict__.update(alternate.__dict__)
                self._primary = primary
                self._bind_buffer()
            modes = tuple(mode for mode in modes if mode != 1049)
        super().set_mode(*modes, **kwargs)

    def reset_mode(self, *modes: int, **kwargs: Any) -> None:
        if kwargs.get('private') and 1049 in modes:
            if self._primary is not None:
                primary = self._primary
                self.__dict__.clear()
                self.__dict__.update(primary)
                self._bind_buffer()
                self.dirty.update(range(self.lines))
            modes = tuple(mode for mode in modes if mode != 1049)
        super().reset_mode(*modes, **kwargs)

    def resize(self, lines: int | None = None, columns: int | None = None) -> None:
        super().resize(lines, columns)
        if self._primary is not None:
            primary = pyte.Screen(self._primary['columns'], self._primary['lines'])
            primary.__dict__.update({k: v for k, v in self._primary.items() if k != '_primary'})
            primary.buffer.default_factory = lambda: StaticDefaultDict(primary.default_char)
            primary.resize(lines, columns)
            self._primary = primary.__dict__ | {'_primary': None}

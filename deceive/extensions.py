from __future__ import annotations

import asyncio
import copy
from importlib.metadata import entry_points
from typing import Callable, Protocol

from deceive.behaviors import BUILTIN_BEHAVIORS
from deceive.interaction import API_VERSION, Interaction, Response, Session
from deceive.models import Profile, Behavior


class BehaviorHandler(Protocol):
    api_version: int

    def validate(self, behavior: Behavior) -> None: ...

    async def respond(self, profile: Profile, behavior: Behavior,
                      interaction: Interaction, session: Session) -> Response | None: ...


class EventObserver(Protocol):
    api_version: int

    async def observe(self, event: dict) -> None: ...


class ProtocolAdapter(Protocol):
    api_version: int

    async def start(self, runtime: object, listener: object) -> object: ...


class Extensions:
    def __init__(self, enabled: dict[str, list[str]], queue_size: int,
                 report: Callable[..., None]):
        self.behaviors = dict(BUILTIN_BEHAVIORS)
        self.protocols = {}
        self.observers: list[EventObserver] = []
        self.queue_size = queue_size
        self.report = report
        self.queues: list[asyncio.Queue] = []
        self.tasks: list[asyncio.Task] = []
        self.closed = False
        for group, names in enabled.items():
            available = {ep.name: ep for ep in entry_points(group=f"deceive.{group}")}
            for name in names:
                if name not in available:
                    raise ValueError(f"Extension not installed: {group}:{name}")
                extension = available[name].load()()
                if getattr(extension, "api_version", None) != API_VERSION:
                    raise ValueError(f"Unsupported extension API: {group}:{name}")
                if group == "observers":
                    self.observers.append(extension)
                else:
                    registry = getattr(self, group)
                    if name in registry or name in {"ssh", "http", "https"}:
                        raise ValueError(f"Extension cannot replace built-in {name}")
                    registry[name] = extension

    def start(self) -> None:
        for observer in self.observers:
            queue = asyncio.Queue(self.queue_size)
            self.queues.append(queue)
            self.tasks.append(asyncio.create_task(self._observe(observer, queue)))

    async def _observe(self, observer: EventObserver, queue: asyncio.Queue) -> None:
        while not self.closed:
            event = await queue.get()
            try:
                await asyncio.wait_for(observer.observe(event), timeout=5)
            except Exception:
                # Deliberate boundary: installed plugins are trusted executable
                # code, but an optional observer must not break a listener.
                self.report("Observer failed", publish=False)
            finally:
                queue.task_done()

    def publish(self, event: dict) -> None:
        for queue in self.queues:
            try:
                queue.put_nowait(copy.deepcopy(event))
            except asyncio.QueueFull:
                self.report("Observer queue full", publish=False)

    async def close(self) -> None:
        self.closed = True
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)

"""Minimal in-process event bus."""
from collections import defaultdict
from collections.abc import Callable

class EventBus:
    def __init__(self):
        self._handlers = defaultdict(list)

    def subscribe(self, name: str, handler: Callable):
        self._handlers[name].append(handler)

    def publish(self, name: str, event=None):
        for handler in tuple(self._handlers.get(name, ())):
            handler(event)

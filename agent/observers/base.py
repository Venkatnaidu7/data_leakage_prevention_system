"""Base interface for endpoint activity observers."""

from abc import ABC, abstractmethod
from typing import Any, Callable


class BaseObserver(ABC):
    """Abstract base class for all endpoint monitoring observers."""

    def __init__(self, on_event: Callable[[dict[str, Any]], None]):
        self.on_event = on_event
        self.is_running = False

    @abstractmethod
    def start(self) -> None:
        """Start the observer service."""
        self.is_running = True

    @abstractmethod
    def stop(self) -> None:
        """Stop observer execution and release resources."""
        self.is_running = False

    @abstractmethod
    def poll(self) -> None:
        """Perform a single observation inspection tick."""
        pass

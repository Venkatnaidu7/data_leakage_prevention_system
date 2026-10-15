"""Durable, bounded local event queue for offline tolerance and retries."""

import json
import logging
from pathlib import Path
from typing import Any


class EventQueue:
    """Manages an on-disk bounded queue for events awaiting transmission to the DLP server."""

    def __init__(self, queue_file_path: str | Path, max_size: int = 500):
        self.queue_file = Path(queue_file_path)
        self.max_size = max_size
        self._events: list[dict[str, Any]] = []
        self._load()

    def _load(self) -> None:
        """Load pending queue from disk."""
        if self.queue_file.exists():
            try:
                with open(self.queue_file, "r", encoding="utf-8") as f:
                    self._events = json.load(f)
            except Exception:
                self._events = []
        else:
            self._events = []

    def _save(self) -> None:
        """Persist pending queue to disk safely."""
        try:
            temp_path = self.queue_file.with_suffix(".tmp")
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(self._events, f, indent=2)
            temp_path.replace(self.queue_file)
        except Exception as e:
            logging.getLogger("dlp.agent.queue").warning("Failed to persist event queue: %s", e)

    def push(self, event: dict[str, Any]) -> bool:
        """Append an event to the queue with bounded limit check."""
        if len(self._events) >= self.max_size:
            # Drop oldest event to avoid unbounded disk exhaustion
            self._events.pop(0)

        self._events.append(event)
        self._save()
        return True

    def peek(self, batch_size: int = 25) -> list[dict[str, Any]]:
        """Return the next batch of pending events without removing them."""
        return self._events[:batch_size]

    def ack(self, event_ids: list[str]) -> int:
        """Acknowledge delivered events and remove them from the queue."""
        id_set = set(event_ids)
        original_count = len(self._events)
        self._events = [e for e in self._events if e.get("event_id") not in id_set]
        removed_count = original_count - len(self._events)
        if removed_count > 0:
            self._save()
        return removed_count

    def size(self) -> int:
        """Return count of pending events in queue."""
        return len(self._events)

    def clear(self) -> None:
        """Clear all events from queue."""
        self._events = []
        if self.queue_file.exists():
            self.queue_file.unlink()

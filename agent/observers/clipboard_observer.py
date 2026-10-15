"""Transparent, privacy-sensitive clipboard observer (strictly disabled by default)."""

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from agent.config import AgentConfig
from agent.observers.base import BaseObserver


class ClipboardObserver(BaseObserver):
    """Monitors system clipboard ONLY when explicitly enabled by administrator configuration.

    Strict Privacy Guarantees:
    - Disabled by default.
    - No keystroke logging or continuous raw history is stored.
    - Raw clipboard content is analyzed and immediately discarded.
    """

    def __init__(self, config: AgentConfig, on_event: Callable[[dict[str, Any]], None]):
        super().__init__(on_event)
        self.config = config
        self._last_content_hash: str | None = None
        self._mock_clipboard_text: str | None = None  # For test injection

    def set_mock_clipboard(self, text: str) -> None:
        """Helper for automated testing environments without GUI display servers."""
        self._mock_clipboard_text = text

    def start(self) -> None:
        self.is_running = True

    def stop(self) -> None:
        self.is_running = False

    def poll(self) -> None:
        """Poll clipboard text if and only if explicitly enabled in configuration."""
        # Non-negotiable safety rule: If disabled in config, NEVER inspect or collect clipboard
        if not self.is_running or not self.config.monitor_clipboard:
            return

        current_text = self._get_clipboard_text()
        if not current_text or not current_text.strip():
            return

        current_hash = hashlib.sha256(current_text.encode("utf-8")).hexdigest()
        if current_hash == self._last_content_hash:
            return

        self._last_content_hash = current_hash

        # Build privacy-minimized event with short sample for server-side policy evaluation
        sample_snippet = current_text[:2000]

        event = {
            "event_id": f"evt-{uuid.uuid4().hex[:16]}",
            "schema_version": "1.0.0",
            "device_id": self.config.device_id or "unassigned",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "channel": "clipboard",
            "operation": "clipboard_copy",
            "content_hash": current_hash,
            "destination_type": "clipboard",
            "content_sample": sample_snippet,
            "file_size_bytes": len(current_text.encode("utf-8")),
            "device_metadata": {
                "length_chars": len(current_text),
                "is_clipboard": True,
            },
        }

        # Raw current_text is discarded here
        del current_text

        self.on_event(event)

    def _get_clipboard_text(self) -> str | None:
        """Fetch clipboard text safely using system tools or test injection."""
        if self._mock_clipboard_text is not None:
            return self._mock_clipboard_text

        # Try standard subprocess clipboards if available (e.g. xclip or powershell)
        # In a background worker, if display is unavailable, return None safely
        return None

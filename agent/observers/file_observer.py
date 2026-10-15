"""Filesystem activity observer monitoring configured directories."""

import hashlib
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from agent.config import AgentConfig
from agent.observers.base import BaseObserver


class FileObserver(BaseObserver):
    """Monitors configured filesystem directories for creation and modification events."""

    def __init__(self, config: AgentConfig, on_event: Callable[[dict[str, Any]], None]):
        super().__init__(on_event)
        self.config = config
        self._file_snapshots: dict[str, tuple[float, int, str]] = {}  # path -> (mtime, size, sha256)

    def start(self) -> None:
        self.is_running = True
        # Ensure monitored directories exist
        for path_str in self.config.monitored_paths:
            p = Path(path_str)
            p.mkdir(parents=True, exist_ok=True)
            self._scan_initial_state(p)

    def stop(self) -> None:
        self.is_running = False

    def _scan_initial_state(self, directory: Path) -> None:
        """Seed baseline snapshot to avoid flood of created events on startup."""
        try:
            for root, _, files in os.walk(directory):
                for f in files:
                    full_path = Path(root) / f
                    try:
                        stat = full_path.stat()
                        self._file_snapshots[str(full_path)] = (stat.st_mtime, stat.st_size, "")
                    except OSError as e:
                        logging.getLogger("dlp.agent.file").debug("Cannot stat %s: %s", full_path, e)
        except OSError as e:
            logging.getLogger("dlp.agent.file").warning("Failed to scan directory %s: %s", directory, e)

    def poll(self) -> None:
        """Poll monitored paths for new or modified files."""
        if not self.is_running:
            return

        for path_str in self.config.monitored_paths:
            target_dir = Path(path_str)
            if not target_dir.exists():
                continue

            for root, _, files in os.walk(target_dir):
                for file_name in files:
                    file_path = Path(root) / file_name
                    self._check_file(file_path)

    def _check_file(self, file_path: Path) -> None:
        """Inspect file state and emit event if changed."""
        str_path = str(file_path)
        try:
            stat = file_path.stat()
        except (OSError, FileNotFoundError):
            return

        size = stat.st_size
        mtime = stat.st_mtime

        last_state = self._file_snapshots.get(str_path)
        if last_state and last_state[0] == mtime and last_state[1] == size:
            # File unchanged, skip
            return

        operation = "modified" if last_state else "created"

        # Calculate SHA-256 and read sample safely if under size limit
        content_sample = ""
        content_hash = ""

        try:
            if size <= self.config.max_file_size_bytes:
                hasher = hashlib.sha256()
                with open(file_path, "rb") as f:
                    chunk = f.read(65536)
                    while chunk:
                        hasher.update(chunk)
                        chunk = f.read(65536)
                content_hash = hasher.hexdigest()

                # Read first 100KB for text inspection
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content_sample = f.read(100_000)
            else:
                content_hash = "size_limit_exceeded"
        except Exception:
            content_sample = ""

        self._file_snapshots[str_path] = (mtime, size, content_hash)

        event = {
            "event_id": f"evt-{uuid.uuid4().hex[:16]}",
            "schema_version": "1.0.0",
            "device_id": self.config.device_id or "unassigned",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "channel": "file",
            "operation": operation,
            "file_path": str_path,
            "file_name": file_path.name,
            "file_type": file_path.suffix.lstrip(".").lower() or "unknown",
            "file_size_bytes": size,
            "content_hash": content_hash,
            "destination_type": "internal_drive",
            "destination_path": str(file_path.parent),
            "content_sample": content_sample,
            "device_metadata": {"platform": self.config.os_name},
        }

        self.on_event(event)

"""Removable media and USB storage activity observer."""

import hashlib
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from agent.config import AgentConfig
from agent.observers.base import BaseObserver


class RemovableMediaObserver(BaseObserver):
    """Detects removable media (USB) connection, disconnection, and file transfer operations."""

    def __init__(self, config: AgentConfig, on_event: Callable[[dict[str, Any]], None]):
        super().__init__(on_event)
        self.config = config
        self._known_mounts: set[str] = set()
        self._observed_files: dict[str, tuple[float, int]] = {}

    def start(self) -> None:
        self.is_running = True
        self._known_mounts = self._discover_removable_mounts()

    def stop(self) -> None:
        self.is_running = False

    def _discover_removable_mounts(self) -> set[str]:
        """Detect current active removable storage mount points across platforms."""
        mounts = set()

        # 1. Linux standard removable mount locations
        linux_removable_dirs = [Path("/media"), Path("/run/media"), Path("/mnt")]
        for p in linux_removable_dirs:
            if p.exists() and p.is_dir():
                try:
                    for child in p.iterdir():
                        if child.is_dir() and not child.name.startswith("."):
                            mounts.add(str(child.resolve()))
                except OSError as e:
                    logging.getLogger("dlp.agent.usb").debug("Cannot inspect mount path %s: %s", p, e)

        # 2. Check for configured test removable drive path
        test_usb = Path(__file__).resolve().parent.parent.parent / "mock_usb"
        if test_usb.exists():
            mounts.add(str(test_usb.resolve()))

        return mounts

    def poll(self) -> None:
        """Poll for removable storage state transitions and file transfers."""
        if not self.is_running or not self.config.monitor_removable_media:
            return

        current_mounts = self._discover_removable_mounts()

        # 1. Check for newly connected devices
        connected = current_mounts - self._known_mounts
        for mount in connected:
            self._emit_device_event("device_connected", mount)

        # 2. Check for disconnected devices
        disconnected = self._known_mounts - current_mounts
        for mount in disconnected:
            self._emit_device_event("device_disconnected", mount)

        self._known_mounts = current_mounts

        # 3. Check for file activities within active removable mounts
        for mount_str in current_mounts:
            mount_path = Path(mount_str)
            if not mount_path.exists():
                continue

            for root, _, files in os.walk(mount_path):
                for f in files:
                    file_path = Path(root) / f
                    self._check_removable_file(file_path, mount_str)

    def _emit_device_event(self, operation: str, mount_path: str) -> None:
        """Emit device connection or disconnection telemetry."""
        event = {
            "event_id": f"evt-{uuid.uuid4().hex[:16]}",
            "schema_version": "1.0.0",
            "device_id": self.config.device_id or "unassigned",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "channel": "removable_media",
            "operation": operation,
            "destination_type": "external_usb",
            "destination_path": mount_path,
            "device_metadata": {
                "mount_point": mount_path,
                "platform": self.config.os_name,
            },
        }
        self.on_event(event)

    def _check_removable_file(self, file_path: Path, mount_root: str) -> None:
        """Inspect file written to or modified on removable media."""
        str_path = str(file_path)
        try:
            stat = file_path.stat()
        except (OSError, FileNotFoundError):
            return

        mtime = stat.st_mtime
        size = stat.st_size

        last = self._observed_files.get(str_path)
        if last and last[0] == mtime and last[1] == size:
            return

        self._observed_files[str_path] = (mtime, size)

        content_sample = ""
        content_hash = ""
        try:
            if size <= self.config.max_file_size_bytes:
                with open(file_path, "rb") as f:
                    content_hash = hashlib.sha256(f.read()).hexdigest()
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content_sample = f.read(100_000)
        except Exception as e:
            logging.getLogger("dlp.agent.usb").debug("Could not read removable file %s: %s", file_path, e)

        event = {
            "event_id": f"evt-{uuid.uuid4().hex[:16]}",
            "schema_version": "1.0.0",
            "device_id": self.config.device_id or "unassigned",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "channel": "removable_media",
            "operation": "file_transferred",
            "file_path": str_path,
            "file_name": file_path.name,
            "file_type": file_path.suffix.lstrip(".").lower() or "unknown",
            "file_size_bytes": size,
            "content_hash": content_hash,
            "destination_type": "external_usb",
            "destination_path": mount_root,
            "content_sample": content_sample,
            "device_metadata": {
                "mount_point": mount_root,
                "is_removable": True,
            },
        }
        self.on_event(event)

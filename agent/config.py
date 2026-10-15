"""Endpoint DLP Agent Configuration."""

import json
import logging
import os
from pathlib import Path
from typing import Any


class AgentConfig:
    """Configuration management for the endpoint DLP agent."""

    def __init__(self, config_path: str | Path | None = None):
        if config_path:
            self.config_path = Path(config_path)
        else:
            self.config_path = Path(__file__).resolve().parent.parent / "agent_config.json"

        # Default Configuration Settings
        self.server_url: str = os.getenv("DLP_SERVER_URL", "http://localhost:5000")
        self.device_id: str | None = os.getenv("DLP_DEVICE_ID")
        self.agent_token: str | None = os.getenv("DLP_AGENT_TOKEN")
        self.hostname: str = os.uname().nodename if hasattr(os, "uname") else "desktop-endpoint"
        self.os_name: str = "Linux" if os.name == "posix" else "Windows"

        # Channels & Scopes
        self.monitored_paths: list[str] = [str(Path.home() / "Documents" / "DTS" / "monitored_data")]
        self.monitor_removable_media: bool = True

        # Privacy Protection: Clipboard monitoring is strictly disabled by default
        self.monitor_clipboard: bool = False

        # Limits & Intervals
        self.max_file_size_bytes: int = 5 * 1024 * 1024  # 5 MB
        self.poll_interval_seconds: float = 2.0
        self.heartbeat_interval_seconds: float = 30.0
        self.max_queue_size: int = 500
        self.queue_db_path: str = str(Path(__file__).resolve().parent.parent / "agent_queue.json")

        self.load()

    def load(self) -> None:
        """Load persisted configuration from disk if available."""
        if self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.server_url = data.get("server_url", self.server_url)
                    self.device_id = data.get("device_id", self.device_id)
                    self.agent_token = data.get("agent_token", self.agent_token)
                    self.monitored_paths = data.get("monitored_paths", self.monitored_paths)
                    self.monitor_removable_media = data.get("monitor_removable_media", self.monitor_removable_media)
                    self.monitor_clipboard = data.get("monitor_clipboard", False)
                    self.max_file_size_bytes = data.get("max_file_size_bytes", self.max_file_size_bytes)
            except Exception as e:
                logging.getLogger("dlp.agent.config").warning(
                    "Failed to load agent config from %s: %s", self.config_path, e
                )

    def save(self) -> None:
        """Persist current configuration to disk."""
        data = {
            "server_url": self.server_url,
            "device_id": self.device_id,
            "agent_token": self.agent_token,
            "hostname": self.hostname,
            "os_name": self.os_name,
            "monitored_paths": self.monitored_paths,
            "monitor_removable_media": self.monitor_removable_media,
            "monitor_clipboard": self.monitor_clipboard,
            "max_file_size_bytes": self.max_file_size_bytes,
        }
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def is_enrolled(self) -> bool:
        """Return True if device holds enrolled credentials."""
        return bool(self.device_id and self.agent_token)

    def to_dict(self) -> dict[str, Any]:
        """Summary representation without exposing agent token."""
        return {
            "server_url": self.server_url,
            "device_id": self.device_id,
            "is_enrolled": self.is_enrolled(),
            "hostname": self.hostname,
            "os_name": self.os_name,
            "monitored_paths": self.monitored_paths,
            "monitor_removable_media": self.monitor_removable_media,
            "monitor_clipboard": self.monitor_clipboard,
        }

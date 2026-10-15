"""Authenticated API client communicating with central DLP platform."""

import json
import urllib.error
import urllib.request
from typing import Any

from agent.config import AgentConfig


class AgentClient:
    """Handles HTTPS / HTTP authenticated communication with DLP server."""

    def __init__(self, config: AgentConfig, timeout_seconds: float = 8.0):
        self.config = config
        self.timeout = timeout_seconds

    def _request(
        self,
        endpoint: str,
        method: str = "GET",
        payload: dict[str, Any] | None = None,
        use_agent_auth: bool = True,
    ) -> tuple[int, dict[str, Any]]:
        """Perform HTTP request returning (status_code, json_response)."""
        url = f"{self.config.server_url.rstrip('/')}/api/v1{endpoint}"
        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"DLP-Agent/{self.config.to_dict().get('os_name', 'Desktop')}",
        }

        if use_agent_auth and self.config.device_id and self.config.agent_token:
            headers["X-Device-ID"] = self.config.device_id
            headers["X-Device-Token"] = self.config.agent_token

        if not (url.startswith("http://") or url.startswith("https://")):
            return 0, {"error": {"message": f"Disallowed URL scheme: {url}"}}

        data_bytes = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)  # noqa: S310

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:  # nosec B310 # noqa: S310
                body = response.read().decode("utf-8")
                return response.status, json.loads(body) if body else {}
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode("utf-8")
                err_json = json.loads(body)
            except Exception:
                err_json = {"error": {"message": str(e)}}
            return e.code, err_json
        except Exception as e:
            return 0, {"error": {"message": f"Network connection failed: {e}"}}

    def enroll(self) -> dict[str, Any]:
        """Submit device enrollment request."""
        payload = {
            "hostname": self.config.hostname,
            "os_name": self.config.os_name,
            "agent_version": "0.1.0",
        }
        status, resp = self._request("/endpoints/enroll", method="POST", payload=payload, use_agent_auth=False)
        if status == 201:
            self.config.device_id = resp.get("device_id")
            self.config.agent_token = resp.get("agent_token")
            self.config.save()
        return resp

    def heartbeat(self, queue_depth: int = 0, status: str = "OK") -> tuple[int, dict[str, Any]]:
        """Send health heartbeat report to central server."""
        if not self.config.device_id:
            return 400, {"error": {"message": "Agent is not enrolled."}}

        payload = {
            "device_id": self.config.device_id,
            "agent_version": "0.1.0",
            "queue_depth": queue_depth,
            "status": status,
        }
        return self._request("/endpoints/heartbeat", method="POST", payload=payload)

    def submit_event(self, event: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        """Transmit single security event to server."""
        return self._request("/endpoints/events", method="POST", payload=event)

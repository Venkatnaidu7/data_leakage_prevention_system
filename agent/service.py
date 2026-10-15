"""Main Endpoint DLP Agent Service manager and event dispatcher."""

import logging
import signal
import time
from typing import Any

from agent.client import AgentClient
from agent.config import AgentConfig
from agent.observers.clipboard_observer import ClipboardObserver
from agent.observers.file_observer import FileObserver
from agent.observers.usb_observer import RemovableMediaObserver
from agent.queue import EventQueue

logger = logging.getLogger("dlp.agent")


class AgentService:
    """Coordinates observers, local event buffering, and transmission to the central DLP platform."""

    def __init__(self, config: AgentConfig | None = None):
        self.config = config or AgentConfig()
        self.queue = EventQueue(self.config.queue_db_path, max_size=self.config.max_queue_size)
        self.client = AgentClient(self.config)
        self.is_running = False

        # Observers
        self.file_observer = FileObserver(self.config, self._enqueue_event)
        self.usb_observer = RemovableMediaObserver(self.config, self._enqueue_event)
        self.clipboard_observer = ClipboardObserver(self.config, self._enqueue_event)

        self._last_heartbeat_time = 0.0

    def _enqueue_event(self, event: dict[str, Any]) -> None:
        """Callback invoked by observers to stage an event into the local queue."""
        logger.info("Observed event on channel [%s]: %s", event.get("channel"), event.get("operation"))
        self.queue.push(event)

    def start(self) -> None:
        """Start observers and agent background service."""
        logger.info("Starting DLP Endpoint Agent (Device: %s)...", self.config.device_id or "Unenrolled")

        # Automatically enroll if credentials missing
        if not self.config.is_enrolled():
            logger.info("Device is not enrolled. Submitting enrollment request to %s...", self.config.server_url)
            self.client.enroll()

        self.file_observer.start()
        self.usb_observer.start()
        self.clipboard_observer.start()
        self.is_running = True

    def stop(self) -> None:
        """Gracefully terminate agent service."""
        logger.info("Stopping DLP Endpoint Agent...")
        self.is_running = False
        self.file_observer.stop()
        self.usb_observer.stop()
        self.clipboard_observer.stop()

    def tick(self) -> None:
        """Execute a single polling and event flush iteration."""
        # 1. Poll observers
        self.file_observer.poll()
        self.usb_observer.poll()
        self.clipboard_observer.poll()

        # 2. Flush pending event queue if connected
        self.flush_queue()

        # 3. Send periodic heartbeat
        now = time.time()
        if now - self._last_heartbeat_time >= self.config.heartbeat_interval_seconds:
            self._last_heartbeat_time = now
            status_code, resp = self.client.heartbeat(queue_depth=self.queue.size())
            if status_code == 200:
                logger.debug("Heartbeat acknowledged by server.")

    def flush_queue(self) -> int:
        """Attempt to deliver pending queued events to the DLP server with exponential backoff."""
        if self.queue.size() == 0 or not self.config.is_enrolled():
            return 0

        batch = self.queue.peek(batch_size=20)
        delivered_ids = []

        for event in batch:
            # Ensure device_id is current
            event["device_id"] = self.config.device_id
            status_code, resp = self.client.submit_event(event)

            if status_code in (200, 201):
                delivered_ids.append(event["event_id"])
                logger.info(
                    "Event %s delivered. Decision: %s (Risk: %s)",
                    event["event_id"],
                    resp.get("decision"),
                    resp.get("risk_level"),
                )
            elif status_code == 403:
                # Device revoked
                logger.warning("Server rejected event: Device is revoked by administrator.")
                break
            elif status_code == 0:
                # Network unreachable, pause flushing until next tick
                logger.debug("Server connection unavailable. Keeping events in local durable queue.")
                break
            else:
                # Other non-retryable error, acknowledge to avoid queue poison
                delivered_ids.append(event["event_id"])

        if delivered_ids:
            return self.queue.ack(delivered_ids)
        return 0

    def run_forever(self) -> None:
        """Run service loop until termination signal."""
        self.start()

        def _signal_handler(sig, frame):
            logger.info("Termination signal received. Shutting down gracefully...")
            self.stop()

        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)

        while self.is_running:
            try:
                self.tick()
                time.sleep(self.config.poll_interval_seconds)
            except Exception as e:
                logger.error("Error during agent tick: %s", e)
                time.sleep(self.config.poll_interval_seconds)

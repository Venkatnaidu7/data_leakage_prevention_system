"""Tests for Endpoint DLP Agent, Observers, Queue, and Service."""

from unittest.mock import MagicMock

from agent.config import AgentConfig
from agent.observers.clipboard_observer import ClipboardObserver
from agent.observers.file_observer import FileObserver
from agent.observers.usb_observer import RemovableMediaObserver
from agent.queue import EventQueue
from agent.service import AgentService


def test_event_queue_lifecycle(tmp_path):
    """Test EventQueue FIFO pushing, disk persistence, peeking, and acknowledgment."""
    q_file = tmp_path / "test_queue.json"
    queue = EventQueue(q_file, max_size=3)

    # 1. Push events
    evt1 = {"event_id": "evt-1", "channel": "file"}
    evt2 = {"event_id": "evt-2", "channel": "file"}
    evt3 = {"event_id": "evt-3", "channel": "removable_media"}
    queue.push(evt1)
    queue.push(evt2)
    queue.push(evt3)
    assert queue.size() == 3

    # 2. Verify disk persistence across reloads
    reloaded_queue = EventQueue(q_file, max_size=3)
    assert reloaded_queue.size() == 3

    # 3. Bounded capacity drops oldest (FIFO)
    evt4 = {"event_id": "evt-4", "channel": "clipboard"}
    queue.push(evt4)
    assert queue.size() == 3
    # evt-1 was dropped
    peeked = queue.peek(batch_size=5)
    ids = [e["event_id"] for e in peeked]
    assert ids == ["evt-2", "evt-3", "evt-4"]

    # 4. Acknowledgment removes specific delivered IDs
    acked = queue.ack(["evt-2", "evt-4"])
    assert acked == 2
    assert queue.size() == 1
    assert queue.peek()[0]["event_id"] == "evt-3"

    # 5. Clear queue
    queue.clear()
    assert queue.size() == 0
    assert not q_file.exists()


def test_file_observer_creation_and_modification(tmp_path):
    """FileObserver detects new and modified files while debouncing unchanged files."""
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()

    cfg = AgentConfig()
    cfg.monitored_paths = [str(monitored_dir)]
    cfg.max_file_size_bytes = 1024 * 1024

    emitted_events = []

    def on_event(evt):
        emitted_events.append(evt)

    observer = FileObserver(cfg, on_event)
    observer.start()

    # Initial scan should emit nothing
    observer.poll()
    assert len(emitted_events) == 0

    # 1. Create a new file
    test_file = monitored_dir / "confidential.txt"
    test_file.write_text("Customer Card: 4532-0150-1234-5671\nAmount: $250", encoding="utf-8")

    observer.poll()
    assert len(emitted_events) == 1
    evt = emitted_events[0]
    assert evt["channel"] == "file"
    assert evt["operation"] == "created"
    assert evt["file_name"] == "confidential.txt"
    assert len(evt["content_hash"]) == 64  # sha256
    assert "4532-0150-1234-5671" in evt["content_sample"]

    # 2. Second poll without changes must NOT re-emit (debounced)
    observer.poll()
    assert len(emitted_events) == 1

    # 3. Modify the file
    import time

    time.sleep(0.05)  # Ensure mtime changes
    test_file.write_text("Customer Card: 4532-0150-1234-5671\nAmount: $9999", encoding="utf-8")

    observer.poll()
    assert len(emitted_events) == 2
    assert emitted_events[1]["operation"] == "modified"

    observer.stop()


def test_file_observer_size_limit_protection(tmp_path):
    """Files exceeding size limits do not read raw content into memory."""
    monitored_dir = tmp_path / "monitored_large"
    monitored_dir.mkdir()

    cfg = AgentConfig()
    cfg.monitored_paths = [str(monitored_dir)]
    cfg.max_file_size_bytes = 50  # Very small limit for testing

    emitted = []
    observer = FileObserver(cfg, lambda e: emitted.append(e))
    observer.start()

    large_file = monitored_dir / "large.txt"
    large_file.write_text("A" * 200, encoding="utf-8")

    observer.poll()
    assert len(emitted) == 1
    assert emitted[0]["content_hash"] == "size_limit_exceeded"
    assert emitted[0]["content_sample"] == ""


def test_removable_media_observer(tmp_path):
    """RemovableMediaObserver detects device attachment, detachment, and file operations."""
    cfg = AgentConfig()
    cfg.monitor_removable_media = True

    emitted = []
    observer = RemovableMediaObserver(cfg, lambda e: emitted.append(e))

    # Mock mount discovery to simulate USB drive insertion
    mock_usb_dir = tmp_path / "mock_usb_drive"
    observer._discover_removable_mounts = MagicMock(return_value=set())
    observer.start()

    # 1. Connect USB drive
    observer._discover_removable_mounts = MagicMock(return_value={str(mock_usb_dir)})
    observer.poll()
    assert len(emitted) == 1
    assert emitted[0]["channel"] == "removable_media"
    assert emitted[0]["operation"] == "device_connected"

    # 2. Disconnect USB drive
    observer._discover_removable_mounts = MagicMock(return_value=set())
    observer.poll()
    assert len(emitted) == 2
    assert emitted[1]["channel"] == "removable_media"
    assert emitted[1]["operation"] == "device_disconnected"


def test_clipboard_observer_safety_disabled_by_default():
    """Privacy Rule: Clipboard monitoring is strictly disabled by default and NEVER collects data."""
    cfg = AgentConfig()
    assert cfg.monitor_clipboard is False  # Must default to False

    emitted = []
    observer = ClipboardObserver(cfg, lambda e: emitted.append(e))
    observer.start()

    # Attempt to inject clipboard content
    observer.set_mock_clipboard("Sensitive clipboard content")
    observer.poll()

    # MUST NOT emit any event
    assert len(emitted) == 0


def test_clipboard_observer_when_explicitly_enabled():
    """When explicitly enabled, clipboard events are sampled and raw strings discarded."""
    cfg = AgentConfig()
    cfg.monitor_clipboard = True  # Explicit opt-in

    emitted = []
    observer = ClipboardObserver(cfg, lambda e: emitted.append(e))
    observer.start()

    observer.set_mock_clipboard("Sensitive Token: AKIAIOSFODNN7EXAMPLE")
    observer.poll()

    assert len(emitted) == 1
    evt = emitted[0]
    assert evt["channel"] == "clipboard"
    assert evt["operation"] == "clipboard_copy"
    assert evt["content_hash"] is not None
    assert "AKIAIOSFODNN7EXAMPLE" in evt["content_sample"]

    # Repetition with same content must not emit duplicate
    observer.poll()
    assert len(emitted) == 1


def test_agent_service_offline_buffering_and_flush(tmp_path):
    """Events remain in local queue during network outage and flush once server is reachable."""
    cfg = AgentConfig(config_path=tmp_path / "agent_config.json")
    cfg.queue_db_path = str(tmp_path / "agent_queue.json")
    cfg.device_id = "ep-test-device"
    cfg.agent_token = "tok-valid-123"  # noqa: S105

    service = AgentService(cfg)

    # 1. Enqueue two events
    service._enqueue_event({"event_id": "evt-offline-1", "channel": "file", "operation": "created"})
    service._enqueue_event({"event_id": "evt-offline-2", "channel": "file", "operation": "created"})
    assert service.queue.size() == 2

    # 2. Simulate network failure (status_code = 0)
    service.client.submit_event = MagicMock(return_value=(0, {"error": "Server unreachable"}))
    flushed = service.flush_queue()
    assert flushed == 0
    # Both events must remain safely preserved in the durable offline queue
    assert service.queue.size() == 2

    # 3. Simulate connection restored (status_code = 201)
    service.client.submit_event = MagicMock(
        return_value=(201, {"status": "PROCESSED", "decision": "ALLOW", "risk_level": "LOW"})
    )
    flushed = service.flush_queue()
    assert flushed == 2
    # Queue is now cleanly drained
    assert service.queue.size() == 0

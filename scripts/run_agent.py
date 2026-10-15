#!/usr/bin/env python3
"""DLP Endpoint Agent Command-Line Interface.

Usage:
    python scripts/run_agent.py enroll [--server-url http://localhost:5000]
    python scripts/run_agent.py status
    python scripts/run_agent.py run [--poll-interval 2.0]
    python scripts/run_agent.py test-event [--type file|usb|clipboard] [--sensitive]
"""

import argparse
import json
import logging
import sys
import uuid
from pathlib import Path

# Ensure repository root is in python path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from agent.client import AgentClient  # noqa: E402
from agent.config import AgentConfig  # noqa: E402
from agent.queue import EventQueue  # noqa: E402
from agent.service import AgentService  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("dlp.agent.cli")


def cmd_enroll(args: argparse.Namespace) -> int:
    """Enroll this device with the DLP central server."""
    config = AgentConfig(config_path=args.config)
    if args.server_url:
        config.server_url = args.server_url

    print(f"[*] Enrolling device '{config.hostname}' with DLP server at {config.server_url}...")
    client = AgentClient(config)
    resp = client.enroll()

    if config.is_enrolled():
        print("[+] Enrollment successful!")
        print(f"    Device ID   : {config.device_id}")
        print(f"    Agent Token : {config.agent_token[:8]}... (saved securely to {config.config_path})")
        return 0
    else:
        err = resp.get("error", {}).get("message", "Unknown error")
        print(f"[-] Enrollment failed: {err}")
        return 1


def cmd_status(args: argparse.Namespace) -> int:
    """Print the local endpoint agent status and configuration."""
    config = AgentConfig(config_path=args.config)
    queue = EventQueue(config.queue_db_path)

    print("========================================")
    print("       DLP Endpoint Agent Status        ")
    print("========================================")
    print(f"Config File       : {config.config_path}")
    print(f"Server URL        : {config.server_url}")
    print(f"Hostname          : {config.hostname}")
    print(f"OS Platform       : {config.os_name}")
    print(f"Device ID         : {config.device_id or 'NOT ENROLLED'}")
    print(f"Enrolled          : {'YES' if config.is_enrolled() else 'NO'}")
    print(f"Monitored Paths   : {', '.join(config.monitored_paths)}")
    print(f"USB / Removable   : {'ENABLED' if config.monitor_removable_media else 'DISABLED'}")
    print(f"Clipboard (opt-in): {'ENABLED' if config.monitor_clipboard else 'DISABLED (Default)'}")
    print(f"Queued Events     : {queue.size()} event(s) pending")

    if config.is_enrolled():
        print("[*] Testing server connectivity and heartbeat...")
        client = AgentClient(config, timeout_seconds=3.0)
        code, resp = client.heartbeat(queue_depth=queue.size())
        if code == 200:
            print(f"[+] Server Connection : ONLINE (Status: {resp.get('status')})")
        elif code == 403:
            print("[-] Server Connection : REVOKED (This device credential was revoked)")
        else:
            print(
                f"[-] Server Connection : OFFLINE / ERROR ({code}: {resp.get('error', {}).get('message', 'Unreachable')})"
            )
    print("========================================")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Start and run the endpoint monitoring agent service."""
    config = AgentConfig(config_path=args.config)
    if args.server_url:
        config.server_url = args.server_url
    if args.poll_interval:
        config.poll_interval_seconds = args.poll_interval
    if args.enable_clipboard:
        config.monitor_clipboard = True

    print(f"[*] Starting DLP Endpoint Agent on {config.hostname}...")
    print(f"    Monitored Paths: {config.monitored_paths}")
    print(f"    Clipboard Mon  : {'ENABLED' if config.monitor_clipboard else 'DISABLED (Default)'}")
    print(f"    Server URL     : {config.server_url}")
    print("Press Ctrl+C to terminate.")

    service = AgentService(config)
    service.run_forever()
    return 0


def cmd_test_event(args: argparse.Namespace) -> int:
    """Generate and submit a test synthetic event for verification."""
    config = AgentConfig(config_path=args.config)
    if not config.is_enrolled():
        print("[-] Device is not enrolled. Run 'python scripts/run_agent.py enroll' first.")
        return 1

    sample_content = "This is a benign diagnostic test from the endpoint agent."
    if args.sensitive:
        sample_content = (
            "CONFIDENTIAL INTERNAL REPORT\n"
            "Customer Payment Card: 4532-0150-1234-5671\n"
            "AWS Secret Access Key: AKIAIOSFODNN7EXAMPLE\n"
            "Email Contact: security-leak@example.com\n"
        )

    channel = args.type or "file"
    operation = "modified" if channel == "file" else ("file_transferred" if channel == "usb" else "clipboard_copy")

    event = {
        "event_id": f"evt-{uuid.uuid4().hex[:16]}",
        "schema_version": "1.0.0",
        "device_id": config.device_id,
        "timestamp_utc": "2026-10-15T12:00:00Z",
        "channel": "removable_media" if channel == "usb" else channel,
        "operation": operation,
        "file_name": "diagnostic_test.txt" if channel != "clipboard" else None,
        "file_path": "/monitored_data/diagnostic_test.txt" if channel != "clipboard" else None,
        "file_type": "txt" if channel != "clipboard" else None,
        "file_size_bytes": len(sample_content.encode("utf-8")),
        "destination_type": "external_usb"
        if channel == "usb"
        else ("clipboard" if channel == "clipboard" else "internal_drive"),
        "destination_path": "/media/usb_drive" if channel == "usb" else None,
        "content_sample": sample_content,
        "device_metadata": {
            "test_run": True,
            "platform": config.os_name,
        },
    }

    print(f"[*] Submitting synthetic {channel} event (sensitive={args.sensitive})...")
    client = AgentClient(config)
    status_code, resp = client.submit_event(event)

    print(f"[*] Response Code : {status_code}")
    print(f"[*] Response Body : {json.dumps(resp, indent=2)}")

    if status_code in (200, 201):
        print(
            f"[+] Event ingested successfully! Decision: {resp.get('decision')} | Risk: {resp.get('risk_level')} ({resp.get('risk_score')}/100)"
        )
        return 0
    else:
        print("[-] Event submission failed.")
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="DLP Endpoint Agent CLI")
    parser.add_argument("--config", help="Path to custom agent configuration JSON", default=None)
    parser.add_argument("--server-url", help="DLP server base URL", default=None)

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: enroll
    subparsers.add_parser("enroll", help="Enroll device with DLP server")

    # Subcommand: status
    subparsers.add_parser("status", help="Display agent status")

    # Subcommand: run
    run_parser = subparsers.add_parser("run", help="Run the agent monitor daemon")
    run_parser.add_argument("--poll-interval", type=float, default=2.0, help="Observer poll interval in seconds")
    run_parser.add_argument(
        "--enable-clipboard", action="store_true", help="Explicitly enable clipboard monitoring (opt-in)"
    )

    # Subcommand: test-event
    test_parser = subparsers.add_parser("test-event", help="Submit a synthetic test event")
    test_parser.add_argument("--type", choices=["file", "usb", "clipboard"], default="file", help="Event channel type")
    test_parser.add_argument("--sensitive", action="store_true", help="Include sensitive credit card/secret content")

    args = parser.parse_args()

    if args.command == "enroll":
        return cmd_enroll(args)
    elif args.command == "status":
        return cmd_status(args)
    elif args.command == "run":
        return cmd_run(args)
    elif args.command == "test-event":
        return cmd_test_event(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())

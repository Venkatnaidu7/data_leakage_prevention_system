"""Tests for safe scanning pipeline, file ingestion, and extraction."""

import io

import pytest

from app.extensions import db
from app.models.incident import Incident
from app.models.scan import ScanRecord
from app.scanning.extractors import ExtractionError, extract_safe_text, validate_file_safety
from app.scanning.scanner import ScanService


def test_validate_file_safety_path_traversal():
    """Ensure path traversal attempts in filename are rejected."""
    stream = io.BytesIO(b"safe text content")
    with pytest.raises(ExtractionError, match="Path traversal"):
        validate_file_safety("../../etc/passwd.txt", stream, 1024, {"txt"})

    with pytest.raises(ExtractionError, match="Path traversal"):
        validate_file_safety("sub/folder/file.txt", stream, 1024, {"txt"})


def test_validate_file_safety_disallowed_extension():
    """Ensure disallowed extensions are blocked."""
    stream = io.BytesIO(b"echo evil")
    with pytest.raises(ExtractionError, match="not authorized"):
        validate_file_safety("script.sh", stream, 1024, {"txt", "csv"})


def test_validate_file_safety_binary_magic_bytes():
    """Ensure ELF or PE binary magic bytes are detected and rejected."""
    elf_stream = io.BytesIO(b"\x7fELF\x02\x01\x01\x00")
    with pytest.raises(ExtractionError, match="binary or executable"):
        validate_file_safety("binary.txt", elf_stream, 1024, {"txt"})

    pe_stream = io.BytesIO(b"MZ\x90\x00\x03\x00")
    with pytest.raises(ExtractionError, match="binary or executable"):
        validate_file_safety("installer.csv", pe_stream, 1024, {"csv"})


def test_validate_file_safety_size_limit():
    """Ensure files exceeding max size are rejected."""
    stream = io.BytesIO(b"A" * 2048)
    with pytest.raises(ExtractionError, match="exceeds maximum allowable limit"):
        validate_file_safety("large.txt", stream, 1024, {"txt"})


def test_extract_safe_text():
    """Test safe text decoding and null-byte rejection."""
    # Plain UTF-8
    stream = io.BytesIO("Hello DLP scanner!".encode("utf-8"))
    assert extract_safe_text(stream, 1024) == "Hello DLP scanner!"

    # Null byte rejection
    binary_stream = io.BytesIO(b"Text with \x00 null bytes")
    with pytest.raises(ExtractionError, match="contains binary null bytes"):
        extract_safe_text(binary_stream, 1024)


def test_scan_service_incident_creation(app):
    """ScanService must create an Incident in DB for non-simulation scans with findings."""
    with app.app_context():
        content = "Confidential customer list:\nContact: analyst@dlp-security.org\nPhone: +1-800-555-0199"
        result = ScanService.scan_text(content, source_name="customer_list.txt", is_simulation=False)

        assert result["findings_count"] >= 2
        assert result["incident_created"] is True
        assert result["incident_id"] is not None

        incident = db.session.get(Incident, result["incident_id"])
        assert incident is not None
        assert incident.source_name == "customer_list.txt"
        assert len(incident.findings) >= 2
        # Ensure evidence is redacted
        for f in incident.findings:
            assert "*" in f.redacted_value


def test_scan_service_simulation_mode(app):
    """ScanService must NOT create an incident when running in simulation mode."""
    with app.app_context():
        content = "Secret leak: AKIAIOSFODNN7EXAMPLE"
        result = ScanService.scan_text(content, source_name="aws_keys.txt", is_simulation=True)

        assert result["findings_count"] >= 1
        assert result["incident_created"] is False
        assert result["incident_id"] is None
        assert result["policy_evaluation"]["is_simulation"] is True

        # ScanRecord is saved for metrics
        record = db.session.get(ScanRecord, result["scan_id"])
        assert record.is_simulation is True

"""Comprehensive tests for DLP detection registry and detector modules."""

import pytest

from app.detection.detectors.credit_card_detector import CreditCardDetector, luhn_checksum
from app.detection.detectors.custom_regex_detector import CustomRegexDetector
from app.detection.detectors.email_detector import EmailDetector
from app.detection.detectors.national_id_detector import NationalIdDetector
from app.detection.detectors.phone_detector import PhoneDetector
from app.detection.detectors.secret_detector import SecretDetector
from app.detection.redaction import (
    build_context_snippet,
    mask_credit_card,
    mask_email,
    mask_generic,
    mask_national_id,
    mask_phone,
    mask_secret,
)
from app.detection.registry import DetectorRegistry


def test_luhn_checksum():
    """Verify Luhn algorithm implementation."""
    # Standard test numbers passing Luhn
    assert luhn_checksum("4532015012345678") is False  # Fake
    assert luhn_checksum("49927398716") is True  # Valid Luhn test
    assert luhn_checksum("79927398713") is True  # Standard Luhn test
    assert luhn_checksum("79927398710") is False  # Corrupted check digit


def test_credit_card_detector():
    """Test credit card detection with Luhn check."""
    detector = CreditCardDetector()
    text = "Payment details: Visa card 4532-0150-1234-5678 is fake, but 4532-0150-1234-5671 passes."
    findings = detector.detect(text)
    # Should catch valid Luhn match
    assert len(findings) >= 1
    assert any("*" in f.redacted_value for f in findings)
    assert findings[0].classification == "PCI_CARD_NUMBER"
    assert findings[0].confidence == 0.95


def test_email_detector():
    """Test email address detection."""
    detector = EmailDetector()
    text = (
        "Contact security analyst at analyst@dlp-security.org or john.doe+alert@example.co.uk.\n"
        "Ignore malformed strings like user@ or @domain.com or user..name@domain.com."
    )
    findings = detector.detect(text)
    assert len(findings) == 2
    emails_found = [f.redacted_value for f in findings]
    assert "a***@dlp-security.org" in emails_found
    assert "j***@example.co.uk" in emails_found


def test_phone_detector():
    """Test phone number detection and date exclusion."""
    detector = PhoneDetector()
    text = (
        "Call the SOC hotline at +1-800-555-0199 or (555) 234-5678.\n"
        "Do not flag calendar dates like 2026-10-15 or short numbers like 12345."
    )
    findings = detector.detect(text)
    assert len(findings) >= 2
    for f in findings:
        assert f.classification == "PHONE_NUMBER"
        assert "***-***-" in f.redacted_value


def test_secret_detector():
    """Test high-entropy tokens, AWS keys, GitHub tokens, and private keys."""
    detector = SecretDetector()
    text = (
        "AWS credentials: AKIAIOSFODNN7EXAMPLE\n"
        "GitHub token: ghp_1234567890abcdefghijklmnopqrstuvwxyz1234\n"
        "Certificate:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0\n"
        "Bogus: api_key = 'your-api-key-here' (low entropy)\n"
        "Real: api_key = 'xK9$mZ2!pL9#vB7&qW1*eR5^tY3@uI0?' (high entropy)\n"
    )
    findings = detector.detect(text)
    subtypes = [f.metadata.get("secret_subtype") for f in findings]
    assert "AWS_ACCESS_KEY" in subtypes
    assert "GITHUB_TOKEN" in subtypes
    assert "PRIVATE_KEY_HEADER" in subtypes
    # Verify masking
    for f in findings:
        assert not f.redacted_value.endswith("EXAMPLE")


def test_national_id_detector_us_ssn():
    """Test US SSN validation and invalid area/group/serial rejection."""
    detector = NationalIdDetector(jurisdiction="US")
    text = (
        "Valid test SSN: 123-45-6789\n"
        "Invalid area 000: 000-12-3456\n"
        "Invalid area 666: 666-12-3456\n"
        "Invalid group 00: 123-00-6789\n"
        "Invalid serial 0000: 123-45-0000\n"
    )
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].redacted_value == "***-**-6789"
    assert findings[0].line_number == 1


def test_custom_regex_detector():
    """Test custom organization-defined identifier pattern."""
    detector = CustomRegexDetector(
        name="project_codename",
        pattern_str=r"\bPROJ-[A-Z]{3}-\d{4}\b",
        classification="INTERNAL_PROJECT_ID",
    )
    text = "Refer to project PROJ-SEC-8921 for DLP roll-out."
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].classification == "INTERNAL_PROJECT_ID"
    assert findings[0].detector_name == "project_codename"

    # Test invalid regex raises ValueError
    with pytest.raises(ValueError, match="Invalid regular expression"):
        CustomRegexDetector(name="bad", pattern_str="[unclosed")


def test_redaction_utilities():
    """Test all redaction masking utilities."""
    assert mask_email("analyst@example.com") == "a***@example.com"
    assert mask_credit_card("4532 0150 1234 5678") == "************5678"
    assert mask_phone("+1-555-123-4567") == "***-***-4567"
    assert mask_national_id("123-45-6789") == "***-**-6789"
    assert mask_secret("AKIAIOSFODNN7EXAMPLE").startswith("AKIA")
    assert mask_generic("SENSITIVE") == "SE*****VE"

    snippet = build_context_snippet("Prefix text SECRET_VALUE suffix text", 12, 24)
    assert "SECRET_VALUE" not in snippet


def test_detector_registry_and_unicode_handling():
    """Test registry execution, Unicode, and long payloads."""
    registry = DetectorRegistry()
    unicode_text = (
        "Audit log in 日本語 and Français with email: sécurité@banque-paris.fr\n"
        "Another line with test card: 79927398713"
    )
    findings = registry.scan_text(unicode_text)
    assert len(findings) >= 1

    # Adversarial long string (100k characters of 'A')
    long_payload = "A" * 100_000 + "\nemail@example.com\n" + "B" * 50_000
    findings_long = registry.scan_text(long_payload)
    assert len(findings_long) >= 1

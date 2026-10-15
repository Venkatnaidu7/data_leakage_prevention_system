"""Detector registry for pluggable sensitive data discovery."""

from typing import Any

from app.detection.base import BaseDetector, Finding
from app.detection.detectors import (
    CreditCardDetector,
    EmailDetector,
    NationalIdDetector,
    PhoneDetector,
    SecretDetector,
)


class DetectorRegistry:
    """Central registry holding active DLP detectors."""

    def __init__(self):
        self._detectors: dict[str, BaseDetector] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        """Register the baseline security detectors."""
        self.register(CreditCardDetector())
        self.register(EmailDetector())
        self.register(PhoneDetector())
        self.register(SecretDetector())
        self.register(NationalIdDetector(jurisdiction="US"))

    def register(self, detector: BaseDetector) -> None:
        """Register a new detector instance."""
        self._detectors[detector.name] = detector

    def unregister(self, name: str) -> bool:
        """Remove a detector by name."""
        if name in self._detectors:
            del self._detectors[name]
            return True
        return False

    def get(self, name: str) -> BaseDetector | None:
        """Retrieve detector by name."""
        return self._detectors.get(name)

    def list_detectors(self) -> list[dict[str, Any]]:
        """List registered detectors and their metadata."""
        return [
            {
                "name": d.name,
                "classification": d.classification,
                "description": d.description,
                "is_jurisdiction_specific": d.is_jurisdiction_specific,
            }
            for d in self._detectors.values()
        ]

    def scan_text(self, text: str, allowed_detectors: list[str] | None = None) -> list[Finding]:
        """Run enabled detectors across text and collect findings."""
        if not text:
            return []

        findings: list[Finding] = []
        for name, detector in self._detectors.items():
            if allowed_detectors and name not in allowed_detectors and "*" not in allowed_detectors:
                continue

            try:
                results = detector.detect(text)
                findings.extend(results)
            except Exception as e:
                import logging

                logging.getLogger("dlp.detection").warning("Detector '%s' failed processing: %s", name, e)
                continue

        # Sort findings by line number, then confidence descending
        findings.sort(key=lambda f: (f.line_number, -f.confidence))
        return findings


# Global default registry singleton
default_registry = DetectorRegistry()

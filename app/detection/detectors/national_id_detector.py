"""Jurisdiction-specific National ID detector (e.g., US Social Security Numbers)."""

import re

from app.detection.base import BaseDetector, Finding
from app.detection.redaction import build_context_snippet, mask_national_id


class NationalIdDetector(BaseDetector):
    """Detects national identity numbers with explicit jurisdiction specification."""

    name = "national_id"
    classification = "GOVERNMENT_NATIONAL_ID"
    description = "Jurisdiction-specific government identifiers (US SSN with validation)"
    is_jurisdiction_specific = True

    # Standard US Social Security Number format: AAA-GG-SSSS
    US_SSN_PATTERN = re.compile(r"\b(\d{3})-(\d{2})-(\d{4})\b")

    def __init__(self, jurisdiction: str = "US"):
        self.jurisdiction = jurisdiction.upper()

    def detect(self, text: str) -> list[Finding]:
        findings = []
        if self.jurisdiction != "US":
            # For non-US jurisdictions, require specific extensions
            return findings

        for match in self.US_SSN_PATTERN.finditer(text):
            area, group, serial = match.groups()
            candidate = match.group()

            # SSA validation rules:
            # 1. Area number cannot be "000", "666", or in "900-999"
            area_int = int(area)
            if area == "000" or area == "666" or (900 <= area_int <= 999):
                continue
            # 2. Group number cannot be "00"
            if group == "00":
                continue
            # 3. Serial number cannot be "0000"
            if serial == "0000":
                continue

            line_num = text.count("\n", 0, match.start()) + 1
            redacted = mask_national_id(candidate)
            snippet = build_context_snippet(text, match.start(), match.end())

            findings.append(
                Finding(
                    detector_name=self.name,
                    classification=self.classification,
                    confidence=0.90,
                    redacted_value=redacted,
                    raw_length=len(candidate),
                    line_number=line_num,
                    context_snippet=snippet,
                    metadata={"jurisdiction": self.jurisdiction, "type": "US_SSN"},
                )
            )

        return findings

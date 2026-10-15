"""Phone number detector."""

import re

from app.detection.base import BaseDetector, Finding
from app.detection.redaction import build_context_snippet, mask_phone


class PhoneDetector(BaseDetector):
    """Detects domestic and international telephone numbers."""

    name = "phone"
    classification = "PHONE_NUMBER"
    description = "Telephone and mobile phone numbers (domestic and international)"

    # Matches formatted telephone numbers with optional country code
    PHONE_PATTERN = re.compile(r"(?:(?:\+|00)\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{4}\b")

    def detect(self, text: str) -> list[Finding]:
        findings = []
        for match in self.PHONE_PATTERN.finditer(text):
            candidate = match.group()
            digits = re.sub(r"\D", "", candidate)

            # Ignore values with fewer than 10 digits or more than 15 digits (ITU-T E.164 standard)
            if len(digits) < 10 or len(digits) > 15:
                continue

            # Filter out obvious false positives like dates (e.g., 2026-10-15 or 1999-12-31)
            if re.match(r"^\d{4}[-/]\d{2}[-/]\d{2}$", candidate.strip()):
                continue

            line_num = text.count("\n", 0, match.start()) + 1
            redacted = mask_phone(candidate)
            snippet = build_context_snippet(text, match.start(), match.end())

            findings.append(
                Finding(
                    detector_name=self.name,
                    classification=self.classification,
                    confidence=0.85,
                    redacted_value=redacted,
                    raw_length=len(candidate),
                    line_number=line_num,
                    context_snippet=snippet,
                    metadata={"digits_count": len(digits)},
                )
            )

        return findings

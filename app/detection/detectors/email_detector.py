"""Email address detector."""

import re

from app.detection.base import BaseDetector, Finding
from app.detection.redaction import build_context_snippet, mask_email


class EmailDetector(BaseDetector):
    """Detects standard email addresses."""

    name = "email"
    classification = "EMAIL_ADDRESS"
    description = "Personal and enterprise email addresses"

    EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")

    def detect(self, text: str) -> list[Finding]:
        findings = []
        for match in self.EMAIL_PATTERN.finditer(text):
            candidate = match.group()
            # Basic sanity filter to exclude invalid patterns like double dots
            if ".." in candidate or candidate.startswith(".") or candidate.endswith("."):
                continue

            line_num = text.count("\n", 0, match.start()) + 1
            redacted = mask_email(candidate)
            snippet = build_context_snippet(text, match.start(), match.end())

            findings.append(
                Finding(
                    detector_name=self.name,
                    classification=self.classification,
                    confidence=0.98,
                    redacted_value=redacted,
                    raw_length=len(candidate),
                    line_number=line_num,
                    context_snippet=snippet,
                    metadata={"domain": candidate.split("@")[-1].lower()},
                )
            )

        return findings

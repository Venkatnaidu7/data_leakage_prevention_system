"""Custom organization-defined regex detector."""

import re

from app.detection.base import BaseDetector, Finding
from app.detection.redaction import build_context_snippet, mask_generic


class CustomRegexDetector(BaseDetector):
    """Detector dynamically configured with an organization-defined regular expression."""

    def __init__(
        self,
        name: str,
        pattern_str: str,
        classification: str = "ORGANIZATION_IDENTIFIER",
        description: str = "Custom regex detector",
        confidence: float = 0.85,
    ):
        self.name = name
        self.classification = classification
        self.description = description
        self.confidence = confidence
        self.pattern_str = pattern_str

        # Validate that the pattern compiles safely
        try:
            self.pattern = re.compile(pattern_str)
        except re.error as e:
            raise ValueError(f"Invalid regular expression pattern '{pattern_str}': {e}") from e

    def detect(self, text: str) -> list[Finding]:
        findings = []
        for match in self.pattern.finditer(text):
            candidate = match.group()
            line_num = text.count("\n", 0, match.start()) + 1
            redacted = mask_generic(candidate)
            snippet = build_context_snippet(text, match.start(), match.end())

            findings.append(
                Finding(
                    detector_name=self.name,
                    classification=self.classification,
                    confidence=self.confidence,
                    redacted_value=redacted,
                    raw_length=len(candidate),
                    line_number=line_num,
                    context_snippet=snippet,
                    metadata={"pattern": self.pattern_str},
                )
            )

        return findings

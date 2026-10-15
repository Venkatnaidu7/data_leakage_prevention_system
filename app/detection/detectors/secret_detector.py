"""High-confidence secrets and credentials detector."""

import math
import re

from app.detection.base import BaseDetector, Finding
from app.detection.redaction import build_context_snippet, mask_secret


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy to measure randomness/entropy."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += -p_x * math.log2(p_x)
    return entropy


class SecretDetector(BaseDetector):
    """Detects API keys, tokens, and private key headers."""

    name = "secret_key"
    classification = "CREDENTIAL_OR_TOKEN"
    description = "API keys, AWS credentials, GitHub tokens, Slack tokens, and private keys"

    PATTERNS = [
        # AWS Access Key ID
        (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "AWS_ACCESS_KEY", 0.99),
        # GitHub Personal Access Token
        (re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b"), "GITHUB_TOKEN", 0.99),
        # Slack API Token
        (re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"), "SLACK_TOKEN", 0.95),
        # Private Key Header
        (
            re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
            "PRIVATE_KEY_HEADER",
            1.0,
        ),
        # Generic API Key / Secret assignments
        (
            re.compile(
                r'(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,80})["\']'
            ),
            "GENERIC_SECRET_ASSIGNMENT",
            0.90,
        ),
    ]

    def detect(self, text: str) -> list[Finding]:
        findings = []
        seen_spans = set()

        for pattern, subtype, confidence in self.PATTERNS:
            for match in pattern.finditer(text):
                # Extract group 1 if present, otherwise entire match
                target_token = match.group(1) if match.lastindex else match.group()
                start = match.start(1) if match.lastindex else match.start()
                end = match.end(1) if match.lastindex else match.end()

                span = (start, end)
                if span in seen_spans:
                    continue
                seen_spans.add(span)

                # Entropy check for generic assignments
                if subtype == "GENERIC_SECRET_ASSIGNMENT":
                    entropy = shannon_entropy(target_token)
                    if entropy < 3.2:
                        # Low randomness string likely a placeholder like "your-api-key-here"
                        continue

                line_num = text.count("\n", 0, start) + 1
                redacted = mask_secret(target_token)
                snippet = build_context_snippet(text, start, end)

                findings.append(
                    Finding(
                        detector_name=self.name,
                        classification=self.classification,
                        confidence=confidence,
                        redacted_value=redacted,
                        raw_length=len(target_token),
                        line_number=line_num,
                        context_snippet=snippet,
                        metadata={"secret_subtype": subtype},
                    )
                )

        return findings

"""Payment card detector with Luhn checksum validation."""

import re

from app.detection.base import BaseDetector, Finding
from app.detection.redaction import build_context_snippet, mask_credit_card


def luhn_checksum(card_number: str) -> bool:
    """Validate card number using the standard Luhn algorithm."""
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) < 2:
        return False

    total = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


class CreditCardDetector(BaseDetector):
    """Detects payment card numbers with delimiter stripping and Luhn validation."""

    name = "credit_card"
    classification = "PCI_CARD_NUMBER"
    description = "Payment card numbers (Visa, Mastercard, Amex, Discover) validated by Luhn algorithm"

    # Regex targeting 13-19 digit card patterns with optional hyphens or spaces
    CARD_PATTERN = re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|"  # Visa
        r"(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}|"  # Mastercard
        r"3[47][0-9]{13}|"  # American Express
        r"3(?:0[0-5]|[68][0-9])[0-9]{11}|"  # Diners Club
        r"6(?:011|5[0-9]{2})[0-9]{12})\b",  # Discover
    )

    # Secondary pattern allowing spaced or hyphenated format
    DELIMITED_CARD_PATTERN = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{1,7}\b")

    def detect(self, text: str) -> list[Finding]:
        findings = []
        seen_spans = set()

        for pattern in (self.CARD_PATTERN, self.DELIMITED_CARD_PATTERN):
            for match in pattern.finditer(text):
                span = (match.start(), match.end())
                if span in seen_spans:
                    continue

                raw_candidate = match.group()
                digits_only = re.sub(r"\D", "", raw_candidate)

                if 13 <= len(digits_only) <= 19 and luhn_checksum(digits_only):
                    seen_spans.add(span)
                    line_num = text.count("\n", 0, match.start()) + 1
                    redacted = mask_credit_card(digits_only)
                    snippet = build_context_snippet(text, match.start(), match.end())

                    findings.append(
                        Finding(
                            detector_name=self.name,
                            classification=self.classification,
                            confidence=0.95,
                            redacted_value=redacted,
                            raw_length=len(raw_candidate),
                            line_number=line_num,
                            context_snippet=snippet,
                            metadata={"card_length": len(digits_only)},
                        )
                    )

        return findings

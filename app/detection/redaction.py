"""Redaction utilities for masking sensitive findings."""

import re


def mask_credit_card(card_str: str) -> str:
    """Mask credit card digits, preserving only the last 4 digits."""
    digits = re.sub(r"\D", "", card_str)
    if len(digits) < 4:
        return "************"
    return "*" * (len(digits) - 4) + digits[-4:]


def mask_email(email_str: str) -> str:
    """Mask email preserving first character and domain."""
    email_str = email_str.strip()
    if "@" not in email_str:
        return mask_generic(email_str)
    local_part, domain = email_str.split("@", 1)
    if len(local_part) <= 1:
        masked_local = "*"
    else:
        masked_local = local_part[0] + "***"
    return f"{masked_local}@{domain}"


def mask_phone(phone_str: str) -> str:
    """Mask phone number preserving last 4 digits."""
    digits = re.sub(r"\D", "", phone_str)
    if len(digits) <= 4:
        return "***-****"
    return f"***-***-{digits[-4:]}"


def mask_secret(secret_str: str) -> str:
    """Mask secrets and API keys showing only first 4 prefix characters."""
    secret_str = secret_str.strip()
    if len(secret_str) <= 6:
        return "******"
    prefix = secret_str[:4]
    return f"{prefix}{'*' * min(20, len(secret_str) - 4)}"


def mask_national_id(nid_str: str) -> str:
    """Mask national IDs like US SSN (***-**-1234)."""
    digits = re.sub(r"\D", "", nid_str)
    if len(digits) == 9:
        return f"***-**-{digits[-4:]}"
    if len(digits) > 4:
        return "*" * (len(digits) - 4) + digits[-4:]
    return "****"


def mask_generic(val: str) -> str:
    """Mask generic sensitive string, keeping edge characters if long enough."""
    val = val.strip()
    if len(val) <= 4:
        return "*" * len(val)
    return val[:2] + ("*" * (len(val) - 4)) + val[-2:]


def build_context_snippet(text: str, start: int, end: int, window: int = 30) -> str:
    """Build a safely redacted context window around a finding."""
    total_len = len(text)
    ctx_start = max(0, start - window)
    ctx_end = min(total_len, end + window)

    prefix = text[ctx_start:start]
    target = text[start:end]
    suffix = text[end:ctx_end]

    # Redact target
    redacted_target = mask_generic(target)

    snippet = f"{prefix}{redacted_target}{suffix}".strip()
    # Replace multiline breaks with single space in snippet
    return re.sub(r"\s+", " ", snippet)

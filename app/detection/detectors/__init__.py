"""Built-in detector implementations."""

from app.detection.detectors.credit_card_detector import CreditCardDetector
from app.detection.detectors.custom_regex_detector import CustomRegexDetector
from app.detection.detectors.email_detector import EmailDetector
from app.detection.detectors.national_id_detector import NationalIdDetector
from app.detection.detectors.phone_detector import PhoneDetector
from app.detection.detectors.secret_detector import SecretDetector

__all__ = [
    "CreditCardDetector",
    "EmailDetector",
    "PhoneDetector",
    "SecretDetector",
    "NationalIdDetector",
    "CustomRegexDetector",
]

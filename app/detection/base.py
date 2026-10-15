"""Base classes and data structures for DLP detectors."""

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Finding:
    """Represents a classified sensitive data finding."""

    detector_name: str
    classification: str
    confidence: float  # Value between 0.0 and 1.0
    redacted_value: str
    raw_length: int
    line_number: int = 1
    context_snippet: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to serializable dictionary."""
        return asdict(self)


class BaseDetector(ABC):
    """Abstract base class for all DLP detectors."""

    name: str = "base_detector"
    classification: str = "SENSITIVE_DATA"
    description: str = ""
    is_jurisdiction_specific: bool = False

    @abstractmethod
    def detect(self, text: str) -> list[Finding]:
        """Analyze text and return structured list of findings."""
        pass

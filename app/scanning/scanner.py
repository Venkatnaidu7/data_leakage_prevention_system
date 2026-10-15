"""Central DLP Scanning Service connecting detection, policies, and incidents."""

from typing import Any, BinaryIO

from flask import current_app
from werkzeug.datastructures import FileStorage

from app.audit.services import record_audit
from app.detection.registry import default_registry
from app.extensions import db
from app.models.incident import Incident, IncidentFinding, IncidentStatus
from app.models.scan import ScanRecord
from app.models.user import User
from app.policies.engine import PolicyEngine
from app.scanning.extractors import extract_safe_text, validate_file_safety


class ScanService:
    """Coordinates file ingestion, detection, redaction, policy evaluation, and incident storage."""

    @classmethod
    def scan_text(
        cls,
        text: str,
        source_name: str = "direct_input.txt",
        is_simulation: bool = False,
        user: User | None = None,
    ) -> dict[str, Any]:
        """Scan raw string content safely."""
        findings = default_registry.scan_text(text)
        evaluation = PolicyEngine.evaluate(findings, simulate=is_simulation)

        incident_created = False
        incident_id = None

        # Create incident if findings exist and this is not a simulation
        if findings and not evaluation.is_simulation:
            incident = Incident(
                title=f"DLP Alert: {evaluation.action} on {source_name}",
                description=evaluation.rationale,
                severity=evaluation.severity,
                status=IncidentStatus.NEW.value,
                source_name=source_name,
                action_taken=evaluation.action,
                matched_policy_name=evaluation.matched_policy_name,
            )
            db.session.add(incident)
            db.session.flush()  # populate incident.id

            for finding in findings:
                finding_model = IncidentFinding(
                    incident_id=incident.id,
                    detector_name=finding.detector_name,
                    classification=finding.classification,
                    confidence=finding.confidence,
                    redacted_value=finding.redacted_value,
                    line_number=finding.line_number,
                    context_snippet=finding.context_snippet,
                )
                db.session.add(finding_model)

            incident_created = True
            incident_id = incident.id

        # Persist scan job record (metadata only, no raw payload content)
        scan_record = ScanRecord(
            source_name=source_name,
            file_size_bytes=len(text.encode("utf-8")),
            findings_count=len(findings),
            action_taken=evaluation.action,
            is_simulation=evaluation.is_simulation,
            user_id=user.id if user else None,
        )
        db.session.add(scan_record)
        db.session.commit()

        # Audit log the scan
        record_audit(
            action="SCAN_COMPLETED",
            target_type="scan",
            target_id=scan_record.id,
            details={
                "source_name": source_name,
                "findings_count": len(findings),
                "action": evaluation.action,
                "is_simulation": evaluation.is_simulation,
                "incident_id": incident_id,
            },
            user=user,
        )

        return {
            "scan_id": scan_record.id,
            "source_name": source_name,
            "findings_count": len(findings),
            "findings": [f.to_dict() for f in findings],
            "policy_evaluation": evaluation.to_dict(),
            "incident_created": incident_created,
            "incident_id": incident_id,
        }

    @classmethod
    def scan_file(
        cls,
        file: FileStorage,
        is_simulation: bool = False,
        user: User | None = None,
    ) -> dict[str, Any]:
        """Validate, extract, and scan an uploaded file safely."""
        max_size = current_app.config.get("MAX_CONTENT_LENGTH", 10 * 1024 * 1024)
        allowed_exts = current_app.config.get("ALLOWED_EXTENSIONS", {"txt", "csv", "json", "log", "md"})

        filename = file.filename or "uploaded_file.txt"
        file_stream: BinaryIO = file.stream

        # Validate file safety
        validate_file_safety(
            filename=filename,
            file_stream=file_stream,
            max_size_bytes=max_size,
            allowed_extensions=allowed_exts,
        )

        # Extract text safely
        extracted_text = extract_safe_text(file_stream, max_bytes=max_size)

        return cls.scan_text(
            text=extracted_text,
            source_name=filename,
            is_simulation=is_simulation,
            user=user,
        )

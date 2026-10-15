"""Seed script to populate initial users, default policies, and sample audit records."""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app
from app.audit.services import record_audit
from app.extensions import db
from app.models.policy import Policy, PolicyAction, PolicySeverity
from app.models.user import Role, User


def seed():
    app = create_app()
    with app.app_context():
        db.create_all()

        # 1. Seed Roles & Users
        users_config = [
            ("admin", "admin@dlp.local", "AdminPass123!@#", Role.ADMIN.value, "dev_admin_api_key_12345"),
            ("analyst", "analyst@dlp.local", "AnalystPass123!@#", Role.ANALYST.value, "dev_analyst_api_key_67890"),
            ("auditor", "auditor@dlp.local", "AuditorPass123!@#", Role.AUDITOR.value, "dev_auditor_api_key_abcde"),
        ]

        for username, email, password, role, key in users_config:
            user = User.query.filter_by(username=username).first()
            if not user:
                user = User(
                    username=username,
                    email=email,
                    role=role,
                    api_key=key,
                )
                user.set_password(password)
                db.session.add(user)
                print(f"Created user: {username} ({role})")

        db.session.commit()

        # 2. Seed Default Policies
        policies_config = [
            {
                "name": "PCI-DSS Cardholder Data Protection",
                "description": "Block transactions and transfers containing valid Luhn-verified payment card numbers",
                "priority": 1,
                "target_detectors": ["credit_card"],
                "match_threshold": 1,
                "action": PolicyAction.BLOCK.value,
                "severity": PolicySeverity.CRITICAL.value,
            },
            {
                "name": "High-Entropy Secrets & Tokens Blocker",
                "description": "Block AWS access keys, GitHub tokens, Slack tokens, and private keys",
                "priority": 2,
                "target_detectors": ["secret_key"],
                "match_threshold": 1,
                "action": PolicyAction.BLOCK.value,
                "severity": PolicySeverity.CRITICAL.value,
            },
            {
                "name": "US Government ID / SSN Exposure Control",
                "description": "Quarantine transfers containing US Social Security numbers for compliance review",
                "priority": 3,
                "target_detectors": ["national_id"],
                "match_threshold": 1,
                "action": PolicyAction.QUARANTINE.value,
                "severity": PolicySeverity.HIGH.value,
            },
            {
                "name": "Bulk PII Exfiltration Alert",
                "description": "Escalate alerts when 3 or more email addresses or phone numbers appear together",
                "priority": 5,
                "target_detectors": ["email", "phone"],
                "match_threshold": 3,
                "action": PolicyAction.ESCALATE.value,
                "severity": PolicySeverity.HIGH.value,
            },
            {
                "name": "Baseline PII Audit Logging",
                "description": "Log single email or phone number appearances for operational hygiene",
                "priority": 20,
                "target_detectors": ["email", "phone"],
                "match_threshold": 1,
                "action": PolicyAction.LOG.value,
                "severity": PolicySeverity.LOW.value,
            },
        ]

        for pol_data in policies_config:
            policy = Policy.query.filter_by(name=pol_data["name"]).first()
            if not policy:
                policy = Policy(
                    name=pol_data["name"],
                    description=pol_data["description"],
                    priority=pol_data["priority"],
                    match_threshold=pol_data["match_threshold"],
                    action=pol_data["action"],
                    severity=pol_data["severity"],
                    enabled=True,
                    version=1,
                )
                policy.target_detectors = pol_data["target_detectors"]
                db.session.add(policy)
                print(f"Created policy: {policy.name}")

        db.session.commit()

        # 3. Seed an initial system audit record
        admin_user = User.query.filter_by(username="admin").first()
        record_audit(
            action="SYSTEM_INITIALIZED",
            target_type="system",
            target_id="dlp_system",
            details={"version": "0.1.0", "default_policies_count": len(policies_config)},
            user=admin_user,
        )

        print("Database seeding completed successfully.")


if __name__ == "__main__":
    seed()

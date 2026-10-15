# Threat Model: DLP System

## 1. Overview and Scope

This document provides a formal STRIDE threat analysis for the Data Leakage Prevention (DLP) system. The scope includes web analyst interfaces, REST APIs, detection engines, policy evaluation, database storage, and file upload processing.

## 2. STRIDE Threat Analysis

| Threat Category | Potential Attack Vector | Impact | Mitigations Implemented |
|---|---|---|---|
| **Spoofing** | Credential guessing, session hijacking, or forged API tokens. | Unauthorized access as an Analyst or Admin. | Argon2id password hashing, session regeneration on login, `HttpOnly`, `SameSite=Lax`, and `Secure` cookie flags, IP/User-Agent tracking, strict API key validation. |
| **Tampering** | Policy modification to disable detection rules; altering audit trails; modifying incident status without authorization. | Malicious insider disables DLP detection or erases evidence. | Strict RBAC (`Admin` required for policy and user edits), CSRF tokens on all state-changing requests, append-only application audit log table, validation schemas. |
| **Repudiation** | An analyst claims they did not modify a policy or close an incident. | Lack of accountability in security incident handling. | Comprehensive audit trail capturing user ID, username, IP address, timestamp, action name, target entity, and diff metadata. |
| **Information Disclosure** | Sensitive data leaked through application logs, error traces, dashboard tables, or exported files. | The DLP system itself becomes a vector for data leakage. | Mandatory redaction before storage; raw secrets never logged; exception handling suppresses stack traces in production; strict authorization on incident details. |
| **Denial of Service** | Oversized file uploads, zip bombs, or regex ReDoS attacks designed to exhaust memory or CPU. | Scanner downtime, preventing analysis of legitimate transfers. | Enforced 10 MB payload limit; non-recursive parsing; strict timeouts and bounded regexes; rate limiting on authentication and scan endpoints via Flask-Limiter. |
| **Elevation of Privilege** | An Analyst or Auditor accesses Admin configuration routes; IDOR on incident assignment. | Unauthorized policy creation, user role alteration. | Server-side role verification decorators (`@role_required(Role.ADMIN)`); server-side object ownership and existence verification. |

## 3. High-Risk Attack Scenarios & Mitigations

### 3.1 Malicious Insiders & Policy Tampering
- **Risk:** An authorized user with access attempts to weaken a detection pattern or whitelist a specific transfer channel.
- **Mitigation:** Only the `Admin` role can create or modify policies. Every policy change creates an immutable audit log record showing previous and updated rule configurations.

### 3.2 File Upload & Code Execution
- **Risk:** An adversary uploads an executable, script, macro-enabled office document, or polyglot file hoping the server executes it.
- **Mitigation:** The application does **not** execute uploaded files, invoke system shells, or pass content to external subprocesses. Text is extracted in memory using bounded readers with strict MIME and extension allowlists (`txt`, `csv`, `json`, `xml`, `md`, `log`, `yaml`).

### 3.3 Log and Evidence Leakage
- **Risk:** Unredacted payment card numbers, credentials, or personal emails are written to standard error or application logs during detection.
- **Mitigation:** The `RedactionService` masks matched tokens at the detector layer. Only masked representations (e.g., `************1234` or `a***@example.com`) are passed to the logger, incident repository, and UI.

## 4. Residual Risks & Security Boundaries

1. **Local Audit Log Tampering:** Database administrators with root database access can alter rows in the audit table. Organizations requiring regulatory-grade non-repudiation must forward audit logs to an external write-once-read-many (WORM) storage or dedicated SIEM.
2. **Network-level Evasion:** Encrypted archives, steganography, or custom obfuscation cannot be inspected by plain regex/heuristic detectors.
3. **Enforcement Scope:** This application provides detection, alert generation, and API hooks for enforcement. It does **not** natively intercept kernel network packets or USB devices unless paired with dedicated endpoint agents.

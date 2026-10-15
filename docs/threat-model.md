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

## 4. Endpoint Threat Model & Analysis

With the introduction of the endpoint DLP agent, additional threat vectors emerge at the endpoint and transport boundaries:

| Endpoint Threat Vector | Impact | Mitigations Implemented | Residual Risks & Limits |
|---|---|---|---|
| **Compromised Endpoint Credentials** | Adversary extracts `device_id` and `agent_token` from `agent_config.json` to spoof events. | Administrator can immediately revoke the device via the UI or `POST /api/v1/endpoints/<id>/revoke`. Revoked devices are denied event ingestion (HTTP 403). | Local users with root/admin access can read configuration files. Hardware TPM/Secure Enclave credential storage required for high-assurance enterprise deployments. |
| **Forged, Replayed, or Duplicate Events** | Attacker intercepts or replays prior security events to flood alert systems or create phantom incidents. | Idempotency deduplication using `event_id` and `idempotency_key`. Duplicate submissions return cached decisions without creating duplicate incidents. | If an attacker generates unique IDs for forged telemetry, server evaluates payload normally; however, telemetry is tied to authenticated device ID. |
| **Local Tampering with Agent Service** | Local user disables agent process, alters `agent_config.json` scopes, or deletes `agent_queue.json`. | Agent emits heartbeats every 30s. Missing heartbeats flag device as inactive in dashboard. Changes to configuration require local user permissions. | Plain user-space agents cannot withstand termination by local OS administrators. Kernel driver or protected service required for tamper-resistance. |
| **Backend Outage & Offline Toleration** | Network connectivity loss between agent and central DLP server. | Bounded on-disk FIFO queue (`agent_queue.json`) caches events locally with retries and exponential backoff. Queue drops oldest events on overflow (max 500) to protect disk space. | If disconnection exceeds queue capacity, oldest events are dropped. Local queue content is stored in plaintext JSON on disk unless full-disk encryption (BitLocker/LUKS) is active. |
| **Malicious or Stale Policy Updates** | Endpoint operates on outdated or compromised policies. | Heartbeat sync checks server policy version on each ping. Server serves as the authoritative evaluation engine for central policy enforcement. | During network disconnects, agent relies on cached rules or monitor-only defaults. |
| **False Positives & False Negatives** | Benign business data flagged as leak, or obfuscated/encrypted sensitive data bypassed. | Multi-tier confidence scoring, Luhn algorithm validation for credit cards, and deterministic four-tier classification (`PUBLIC` to `RESTRICTED`). | High-entropy base64 data, encrypted ZIPs, and non-text files cannot be decrypted without endpoint certificate keys. |
| **Privacy Risks from File & Clipboard Monitoring** | Agent collects sensitive personal files or clipboard passwords of authorized users. | Strict consent and privacy rules: Clipboard monitoring is **disabled by default**. Keystroke logging is strictly prohibited. Agent minimises data by uploading only metadata, hashes, and short bounded samples; server saves only redacted tokens. | Administrators who enable clipboard monitoring must ensure employee notification and compliance with applicable privacy regulations (GDPR/CCPA). |
| **Resource Exhaustion & Event Storms** | Rapid file operations (e.g. `git checkout` or automated builds) trigger CPU/disk saturation. | FileObserver debounces events using mtime and file size caching. File reading is capped to 5 MB per file and sample extraction is capped to 100 KB max. | Monitoring system root directories (`/` or `C:\`) without path exclusions will cause high CPU usage. Administrators must configure targeted directory paths. |

## 5. Residual Risks & Security Boundaries

1. **Local Audit Log Tampering:** Database administrators with root database access can alter rows in the audit table. Organizations requiring regulatory-grade non-repudiation must forward audit logs to an external write-once-read-many (WORM) storage or dedicated SIEM.
2. **Network-level Evasion:** Encrypted archives, steganography, or custom obfuscation cannot be inspected by plain regex/heuristic detectors.
3. **Enforcement Scope & Honesty:** This prototype provides detection, telemetry, alert generation, and policy evaluation. It does **not** claim to provide kernel-level filesystem write blocking, network packet filtering, or hardware USB lockouts. Where blocking cannot be verified at the OS level, the decision is explicitly reported as `NOT_ENFORCED`.


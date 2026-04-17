# Severity Classification Guide

Use these criteria to assign severity levels to findings. When a finding could fall into multiple levels, use the highest applicable severity.

## CRITICAL

Direct, exploitable vulnerabilities that allow:
- **Remote Code Execution (RCE)**: OS command injection, unsafe deserialization
- **SQL Injection**: Unsanitized input in SQL queries allowing data exfiltration or modification
- **Authentication Bypass**: Hardcoded credentials, JWT `none` algorithm, broken auth logic
- **Arbitrary File Read/Write**: Path traversal with file operations

**Characteristics**: Exploitable without authentication or with minimal user interaction. Can lead to full system compromise.

**Report includes**: Proof of Concept section with non-destructive verification steps (see `format.md`).

**CWE examples**: CWE-89 (SQLi), CWE-78 (OS Command Injection), CWE-502 (Deserialization), CWE-798 (Hardcoded Credentials)

## HIGH

Vulnerabilities that can be exploited to steal data, impersonate users, or escalate privileges:
- **Cross-Site Scripting (XSS)**: Stored or reflected XSS in user-facing pages
- **Server-Side Request Forgery (SSRF)**: Internal network access via URL manipulation
- **Insecure Direct Object References (IDOR)**: Accessing other users' data without authorization checks
- **XML External Entity (XXE)**: External entity injection in XML parsers
- **Broken Access Control**: Missing authorization checks on sensitive endpoints
- **Sensitive Data Exposure**: Plaintext passwords, unencrypted PII in transit/storage

**Characteristics**: Requires some user interaction or specific conditions. Can lead to data breach or account takeover.

**Report includes**: Proof of Concept section with non-destructive verification steps (see `format.md`).

**CWE examples**: CWE-79 (XSS), CWE-918 (SSRF), CWE-611 (XXE), CWE-862 (Missing AuthZ), CWE-639 (IDOR)

## MEDIUM

Security weaknesses that reduce defense depth or enable attacks when combined with other issues:
- **CSRF**: Missing or disabled cross-site request forgery protection
- **Missing Security Headers**: Absent Content-Security-Policy, X-Frame-Options, HSTS
- **Weak Cryptography**: SHA-1 for signatures, short key lengths, ECB mode
- **Session Management Issues**: Missing session regeneration, overly long timeouts
- **Mass Assignment**: Binding request data directly to entities without filtering
- **Overly Permissive CORS**: `Access-Control-Allow-Origin: *` on authenticated endpoints
- **Missing Input Validation**: No validation on request parameters (without proven injection)
- **Verbose Error Messages**: Stack traces or internal details in error responses

**Characteristics**: Not directly exploitable alone. Weakens security posture or enables attack chains.

**CWE examples**: CWE-352 (CSRF), CWE-693 (Missing Headers), CWE-327 (Weak Crypto), CWE-915 (Mass Assignment)

## LOW

Best practice violations and informational findings:
- **Missing Cookie Attributes**: HttpOnly, Secure, or SameSite not set (non-session cookies)
- **Deprecated APIs**: Using deprecated security functions still functional but not recommended
- **Logging Gaps**: Missing audit logging on security-relevant operations
- **Dependency Hygiene**: Outdated but not known-vulnerable dependencies
- **Configuration Hardening**: Running as root in Docker, missing resource limits in K8s
- **Informational Leakage**: Server version headers, technology fingerprinting

**Characteristics**: No direct security impact but indicates areas for improvement.

**CWE examples**: CWE-1004 (Missing HttpOnly), CWE-532 (Log Injection), CWE-16 (Configuration)

## INFO

Observations and recommendations with no direct vulnerability:
- **Architecture Suggestions**: Design improvements for better security posture
- **Framework Features**: Available security features not currently utilized
- **Documentation**: Missing security documentation or threat model
- **Positive Findings**: Correctly implemented security controls (for completeness in reports)

# Security Policy - Entramox Reconciler

**Turning realms into real users, one sudo at a time.**

This document explains how to report security issues, what is in scope, expected triage timelines, and which versions of Entramox Reconciler receive security fixes.

---

## Supported Versions

| Version     | Supported?            |
| ----------- | --------------------- |
| **2.0.x**   | ✅ Security fixes      |
| **1.4.x**   | ⚠️ Critical fixes only |
| ≤ **1.3.x** | ❌ End of support      |

Entramox Reconciler follows semantic versioning.  
The latest major version receives full security fixes.  
Previous majors receive critical fixes only for a limited time.

---

## Scope

### In scope

* Entramox Reconciler Python code
* Installer and update logic
* systemd service and timer units provided by this repository
* Integrity, permission, and safety guardrails implemented by the project
* Documentation that impacts security posture or safe operation

### Out of scope

* Proxmox VE itself and official tooling (`pve*`, `pvesh`, `pveum`)
* Linux distributions, kernels, or system packages
* Microsoft Entra ID, Microsoft Graph, or external identity providers
* Third party Python libraries or system utilities

If you are unsure whether something is in scope, report it anyway and it will be triaged appropriately.

---

## Reporting a Vulnerability

Please **do not open a public GitHub issue** for security related reports.

### Preferred method

* Create a **private GitHub Security Advisory**
  * Repository → Security → Advisories → Report a vulnerability

### Include the following where applicable

* Clear description of the issue and impact
* Steps to reproduce or proof of concept
* Affected version(s)
* Environment details (OS, Python version, Proxmox version)
* Relevant logs or stack traces (remove secrets and identifiers)
* Any known mitigations or workarounds

Good faith security research is welcomed.  
Please do not test against systems you do not own or have permission to assess.

---

## Vulnerability Handling Process

* **Acknowledgement:** within 2 business days
* **Triage and initial assessment:** within 5 business days
* **Fix and advisory publication:**  
  * High or Critical severity within 30 days  
  * Medium or Low severity as soon as practical
* **Coordinated disclosure:** agreed with the reporter

Severity is assessed using CVSS v3.1 and GitHub severity guidance.  
Where appropriate, a GitHub Security Advisory will be published and a CVE requested.

Reporter credit is provided on request.

---

## Security Expectations for Operators

Entramox Reconciler manages local users, groups, sudoers, and Proxmox access.  
It must be operated defensively.

### File ownership and permissions

* Script file  
  `/usr/local/sbin/entramoxreconciler.py`  
  `root:root`, mode `0700`

* Integrity checker  
  `/usr/local/sbin/entramox_check.sh`  
  `root:root`, mode `0700`

* Config file  
  `/etc/entramoxreconciler.env`  
  `root:root`, mode `0600`

* Encryption key  
  `/etc/entramoxreconciler.key`  
  `root:root`, mode `0600`

* Log directory  
  `/var/log/entramoxreconciler`  
  `root:root`, mode `0750`

* State directory  
  `/var/lib/entramoxreconciler`  
  `root:root`, mode `0750`

* Managed sudoers files  
  `/etc/sudoers.d/*`  
  `root:root`, mode `0440`

---

### Integrity enforcement

Entramox Reconciler enforces integrity at runtime:

* SHA-256 checksum validation of the installed script
* Refusal to execute if permissions or ownership are unsafe
* systemd `ExecCondition` gate before execution

If these checks fail, the service exits without making changes.

Do not bypass or remove these checks.

---

### Execution model

* Always run via **systemd timer**
* Never run as a long lived root daemon
* Never run from user writable paths
* Avoid cron unless you fully understand locking and environment behaviour

---

### Privilege and sudo guidance

* Avoid `NOPASSWD` unless absolutely required
* Treat `sudo`, `wheel`, and `admin` as highly privileged groups
* Sudo access should normally be granted only via Entra Super Admin groups
* All sudoers files are validated with `visudo` before being applied

---

### Entra and Graph credentials

* Store secrets only in root protected locations
* Prefer encrypted secrets in the env file
* Never commit secrets to the repository
* Rotate client secrets regularly
* Use application credentials for timers and automation

---

## Responsible Disclosure

* Keep reports private until fixes or mitigations are available
* Coordinated disclosure timelines will be agreed together
* If timelines cannot be met, status and mitigations will be communicated
* Disagreements on severity or scope will be handled transparently

There is currently no paid bug bounty.  
High quality reports may be acknowledged in release notes with permission.

---

## Dependencies and Supply Chain

If a vulnerability exists in:

* Proxmox VE
* Linux system tools
* Microsoft Entra ID or Graph
* Python standard library or third party modules

Please report it to the upstream project and notify this repository so mitigations or guidance can be added if appropriate.

---

## Non Vulnerability Security Issues

Operational misconfiguration is not a software vulnerability, but reports that improve defaults, guardrails, or documentation are welcome.

Examples include:

* Overly permissive sudo settings
* Unsafe environment file handling
* Risky username mapping defaults
* Ambiguous documentation

---

## Policy Updates

This security policy may change over time.  
The `SECURITY.md` file in the main branch is the authoritative version.  
Significant changes will be noted in release notes.

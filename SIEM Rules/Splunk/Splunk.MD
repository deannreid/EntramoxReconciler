# EntramoxReconciler – Splunk Detection Guide

## Overview

**Splunk searches, alerting guidance, and deployable saved search templates** for monitoring identity and privilege lifecycle events from **entramoxreconciler**.

**V2.5 additions:** Tiered accounts, Proxmox Backup Server (PBS), Proxmox Datacenter Manager (PDM), JSON audit log events, remote API errors.

---

## Log Sources

### Required

| Source | Path |
|--------|------|
| EntramoxReconciler app log | `/var/log/entramoxreconciler/thelog.log` |
| Linux auth log | `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL) |

### Optional (recommended)

| Source | Purpose |
|--------|---------|
| `auditd` | Sudoers file FIM, process events |
| `/var/log/entramoxreconciler/audit.log` | Structured JSON security events (v2.5+) |

---

## Index / Sourcetype Assumptions

```text
index=linux
sourcetype=linux_auth OR linux_secure
source=/var/log/entramoxreconciler/thelog.log
```

For the JSON audit log, index as `sourcetype=entramox_audit` or use a JSON sourcetype with field extractions. Adjust all `entramox_audit` references below to match your environment.

---

## 1. Local User Created (auth log)

```spl
(index=linux (sourcetype=linux_auth OR sourcetype=linux_secure))
("useradd[" OR "new user:")
| rex field=_raw "new user:\s+name=(?<user>\S+)"
| stats count earliest(_time) as first_seen latest(_time) as last_seen by host user
| convert ctime(first_seen) ctime(last_seen)
```

**Alert:** count > 0 | **Severity:** Medium

---

## 2. Local User Deleted (auth log)

```spl
(index=linux (sourcetype=linux_auth OR sourcetype=linux_secure))
("userdel[" OR "deleted user")
| rex field=_raw "deleted user\s+(?<user>\S+)"
| stats count latest(_time) as deleted_at by host user
| convert ctime(deleted_at)
```

**Alert:** count > 0 | **Severity:** High

---

## 3. User Locked / Unlocked (auth log)

```spl
(index=linux (sourcetype=linux_auth OR sourcetype=linux_secure))
("usermod[" AND ("lock" OR "unlock" OR "-L" OR "-U"))
| rex field=_raw "usermod\[\d+\]:\s+(?<action>lock|unlock).*'(?<user>[^']+)'"
| stats count latest(_time) as last_seen by host user action
| convert ctime(last_seen)
```

**Alert:** count > 0 | **Severity:** Lock = Medium, Unlock = High

---

## 4. Sudo Group Membership Change (auth log)

```spl
(index=linux (sourcetype=linux_auth OR sourcetype=linux_secure))
(("usermod[" AND "sudo") OR ("gpasswd[" AND "sudo"))
| eval action=case(
    like(_raw, "%usermod%") AND like(_raw, "%sudo%"), "sudo_granted",
    like(_raw, "%gpasswd%") AND like(_raw, "%-d%") AND like(_raw, "% sudo%"), "sudo_revoked",
    true(), "unknown"
)
| rex field=_raw "('(?<user>[^']+)'|user\s+(?<user2>\S+))"
| eval user=coalesce(user, user2)
| stats count latest(_time) as last_seen by host user action
| convert ctime(last_seen)
```

**Alert:** count > 0 | **Severity:** Grant = High, Revoke = Medium

---

## 5. Sudoers File Created / Modified / Removed (auditd/FIM)

```spl
(index=linux (sourcetype=auditd OR sourcetype=ossec))
("/etc/sudoers.d/pve_realm-" AND ("CREATE" OR "WRITE" OR "DELETE" OR "modified" OR "deleted"))
| rex field=_raw "/etc/sudoers\.d/pve_realm-(?<user>[A-Za-z0-9._-]+)"
| eval action=case(
    match(_raw, "DELETE|deleted"), "sudoers_removed",
    match(_raw, "CREATE|created"), "sudoers_created",
    match(_raw, "WRITE|modified"),  "sudoers_modified",
    true(), "sudoers_change"
)
| stats count latest(_time) as last_seen by host user action
| convert ctime(last_seen)
```

**Alert:** count > 0 | **Severity:** Create/Modify = Critical, Remove = Medium

---

## 6. Reconciler — User Created (authoritative)

```spl
index=linux source="/var/log/entramoxreconciler/thelog.log"
"Created local user:"
| rex "Created local user:\s+(?<user>\S+)"
| stats count latest(_time) as created_at by host user
| convert ctime(created_at)
```

---

## 7. Reconciler — User Marked for Deletion (Grace Period)

```spl
index=linux source="/var/log/entramoxreconciler/thelog.log"
"locked and marked for deletion"
| rex "User\s+(?<user>\S+)\s+not in Entra allow-groups; locked and marked for deletion"
| stats count latest(_time) as marked_at by host user
| convert ctime(marked_at)
```

**Severity:** Medium

---

## 8. Reconciler — Sudo Granted / Revoked

```spl
index=linux source="/var/log/entramoxreconciler/thelog.log"
("Updated sudoers for" OR "Removed sudoers file for")
| rex "for\s+(?<user>\S+)"
| eval action=if(match(_raw, "Updated sudoers"), "sudo_granted", "sudo_revoked")
| stats count latest(_time) as last_seen by host user action
| convert ctime(last_seen)
```

---

## 9. Tiered Account Created (v2.5)

```spl
index=linux source="/var/log/entramoxreconciler/thelog.log"
"Created tiered account"
| rex "Created tiered account '(?<tiered_user>[^']+)' for base user '(?<base_user>[^']+)'"
| stats count latest(_time) as created_at by host tiered_user base_user
| convert ctime(created_at)
```

**Severity:** High — A new privileged account has been provisioned.

---

## 10. Tiered Account Removed (v2.5)

```spl
index=linux source="/var/log/entramoxreconciler/thelog.log"
"Tiered account removed (no longer superadmin)"
| rex "no longer superadmin\):\s+(?<tiered_user>\S+)"
| stats count latest(_time) as removed_at by host tiered_user
| convert ctime(removed_at)
```

**Severity:** Medium — Privileged account deprovisioned.

---

## 11. PBS User Provisioned / State Changed (v2.5)

```spl
index=linux source="/var/log/entramoxreconciler/thelog.log"
"PBS user" ("created:" OR "updated:" OR "set enable")
| rex "PBS user (?:created|updated):\s+(?<userid>\S+)" 
| rex "PBS user\s+(?<userid2>[^\s]+)\s+set enable=(?<enabled>[01])"
| eval userid=coalesce(userid, userid2)
| eval action=case(
    match(_raw, "created:"), "provisioned",
    match(_raw, "updated:"), "updated",
    enabled="1", "enabled",
    enabled="0", "disabled",
    true(), "unknown"
)
| stats count latest(_time) as last_seen by host userid action
| convert ctime(last_seen)
```

---

## 12. PDM User Provisioned / State Changed (v2.5)

```spl
index=linux source="/var/log/entramoxreconciler/thelog.log"
"PDM user" ("created:" OR "updated:" OR "set enable")
| rex "PDM user (?:created|updated):\s+(?<userid>\S+)"
| rex "PDM user\s+(?<userid2>[^\s]+)\s+set enable=(?<enabled>[01])"
| eval userid=coalesce(userid, userid2)
| eval action=case(
    match(_raw, "created:"), "provisioned",
    match(_raw, "updated:"), "updated",
    enabled="1", "enabled",
    enabled="0", "disabled",
    true(), "unknown"
)
| stats count latest(_time) as last_seen by host userid action
| convert ctime(last_seen)
```

---

## 13. Remote API Auth Failure — PBS / PDM (v2.5)

```spl
index=linux source="/var/log/entramoxreconciler/thelog.log"
"Remote API HTTP" ("401:" OR "403:")
| rex "Remote API HTTP\s+(?<method>\S+)\s+(?<url>\S+)\s+(?<status>[0-9]{3})"
| stats count latest(_time) as last_seen by host method url status
| convert ctime(last_seen)
```

**Severity:** High | **Tactic:** CredentialAccess (T1552)

> Repeated 401/403s mean the PBS or PDM API token has expired, been revoked, or is wrong.

---

## 14. Remote API Credentials Missing (v2.5)

```spl
index=linux source="/var/log/entramoxreconciler/thelog.log"
("PBS auth header missing" OR "PDM auth header missing")
| eval system=if(match(_raw, "^PBS"), "PBS", "PDM")
| stats count latest(_time) as last_seen by host system
| convert ctime(last_seen)
```

**Severity:** Critical — PBS/PDM sync is silently failing.

---

## 15. PVE User Enabled / Disabled

```spl
index=linux source="/var/log/entramoxreconciler/thelog.log"
"PVE user" ("created" OR "set enable")
| rex "PVE user\s+(?<userid>\S+)"
| rex "enable=(?<enabled>[01])"
| eval state=if(enabled=="1", "enabled", "disabled")
| stats count latest(_time) as last_seen by host userid state
| convert ctime(last_seen)
```

---

## 16. JSON Audit Log — Security Events (v2.5)

If ingesting `/var/log/entramoxreconciler/audit.log` as `sourcetype=entramox_audit`:

```spl
index=linux sourcetype=entramox_audit
| spath input=_raw
| eval event=spath(_raw, "event")
| eval user=coalesce(spath(_raw, "user"), spath(_raw, "tiered_user"), spath(_raw, "userid"))
| eval base_user=spath(_raw, "base_user")
| eval enabled=spath(_raw, "enabled")
| search event IN ("USER_CREATED", "SUDO_GRANTED", "TIERED_ACCOUNT_CREATED", "TIERED_ACCOUNT_DELETED",
                   "PBS_USER_CREATED", "PBS_USER_TOGGLED", "PDM_USER_CREATED", "PDM_USER_TOGGLED")
| table _time host event user base_user enabled
| sort -_time
```

---

## 17. Integrity Checker — Script Checksum Mismatch (v2.5)

Fires when `entramox_check.sh` detects the reconciler binary SHA-256 has changed.

```spl
index=linux source="/var/log/entramoxreconciler/thelog.log"
"[entramox_check]" "script checksum mismatch"
| rex "\[entramox_check\] Integrity: script checksum mismatch file=(?<path>\S+) have=(?<have>[0-9a-f]+) expect=(?<expect>[0-9a-f]+)"
| stats count latest(_time) as last_seen values(have) as observed_hash values(expect) as expected_hash by host path
| convert ctime(last_seen)
```

**Severity:** Critical — treat as active tamper until proven otherwise.

---

## 18. Integrity Checker — File Tampering (Symlink / Owner / Permissions) (v2.5)

```spl
index=linux source="/var/log/entramoxreconciler/thelog.log"
"[entramox_check]"
("symlink refused" OR "file not owned by root" OR "permissions too broad")
| rex "\[entramox_check\] Integrity: (?<check_type>symlink refused|file not owned by root|permissions too broad) path=(?<path>\S+)"
| rex "uid=(?<uid>\d+)"
| rex "mode=(?<mode>\S+)"
| eval detail=coalesce("uid=".uid, "mode=".mode, "")
| stats count latest(_time) as last_seen by host check_type path detail
| convert ctime(last_seen)
```

**Severity:** Critical — symlink hijack or privilege on managed file indicates active attack.

---

## 19. Integrity Checker — Env / Key File Hash Changed (v2.5)

```spl
index=linux source="/var/log/entramoxreconciler/thelog.log"
"[entramox_check]" ("env checksum changed" OR "key checksum changed")
| rex "\[entramox_check\] Integrity: (?<file_type>env|key) checksum changed path=(?<path>\S+) have=(?<have>[0-9a-f]+) expect=(?<expect>[0-9a-f]+)"
| stats count latest(_time) as last_seen by host file_type path have expect
| convert ctime(last_seen)
```

**Severity:** High — could be a legitimate reconfigure or credential swap. Correlate with change records.

---

## 20. Integrity Checker — Missing Monitored File (v2.5)

```spl
index=linux source="/var/log/entramoxreconciler/thelog.log"
"[entramox_check]" "missing file"
| rex "\[entramox_check\] Integrity: missing file path=(?<path>.+)$"
| stats count latest(_time) as last_seen by host path
| convert ctime(last_seen)
```

**Severity:** High — missing binary or env file means sync is broken.

---

## Alerting Strategy

| Event | Source | Severity | Notes |
|-------|--------|----------|-------|
| User created | App log | Medium | Expected automation |
| User deleted | App log | High | Review timing |
| Sudo granted | App log | High | Always alert |
| Sudoers modified (FIM) | auditd | Critical | Possible manual escalation |
| Tiered account created | App log | High | New privileged login provisioned |
| Tiered account removed | App log | Medium | Privileged account cleaned up |
| User marked for deletion | App log | Medium | IAM / offboarding audit |
| Remote API 401/403 | App log | High | Credential problem — PBS/PDM sync broken |
| Auth credentials missing | App log | Critical | Sync silently failing |
| PVE user enabled | App log | High | Re-enablement risk |
| PBS/PDM user provisioned | App log | Medium | Cross-system IAM event |
| **Script checksum mismatch** | **App log** | **Critical** | **Binary may be tampered** |
| **Symlink / owner / perms** | **App log** | **Critical** | **Active file hijack indicator** |
| **Env/key hash changed** | **App log** | **High** | **Credential file modified** |
| **Missing monitored file** | **App log** | **High** | **Sync silently broken** |

---

## Deployable Saved Searches (JSON)

Deploy via Splunk REST API: `POST /servicesNS/<owner>/<app>/saved/searches` (form-encoded per search).

```json
{
  "saved_searches": [
    {
      "name": "ENTRAMOX - Local User Created (authlog)",
      "search": "index=linux (sourcetype=linux_auth OR sourcetype=linux_secure) (\"useradd[\" OR \"new user:\") | rex field=_raw \"new user:\\s+name=(?<user>\\S+)\" | stats count earliest(_time) as first_seen latest(_time) as last_seen by host user | convert ctime(first_seen) ctime(last_seen)",
      "cron_schedule": "*/5 * * * *",
      "dispatch.earliest_time": "-10m",
      "dispatch.latest_time": "now",
      "is_scheduled": 1,
      "alert_type": "number of events",
      "alert_comparator": "greater than",
      "alert_threshold": "0",
      "alert.severity": "3",
      "alert.suppress": "1",
      "alert.suppress.period": "1h"
    },
    {
      "name": "ENTRAMOX - Local User Deleted (authlog)",
      "search": "index=linux (sourcetype=linux_auth OR sourcetype=linux_secure) (\"userdel[\" OR \"deleted user\") | rex field=_raw \"deleted user\\s+(?<user>\\S+)\" | stats count latest(_time) as deleted_at by host user | convert ctime(deleted_at)",
      "cron_schedule": "*/5 * * * *",
      "dispatch.earliest_time": "-10m",
      "dispatch.latest_time": "now",
      "is_scheduled": 1,
      "alert_type": "number of events",
      "alert_comparator": "greater than",
      "alert_threshold": "0",
      "alert.severity": "4",
      "alert.suppress": "1",
      "alert.suppress.period": "2h"
    },
    {
      "name": "ENTRAMOX - Sudo Granted/Revoked (authlog)",
      "search": "index=linux (sourcetype=linux_auth OR sourcetype=linux_secure) ((\"usermod[\" AND \"sudo\") OR (\"gpasswd[\" AND \"sudo\")) | eval action=case(like(_raw,\"%usermod%\") AND like(_raw,\"%sudo%\"),\"sudo_granted\", like(_raw,\"%gpasswd%\") AND like(_raw,\"%-d%\") AND like(_raw,\"% sudo%\"),\"sudo_revoked\", true(),\"unknown\") | rex field=_raw \"('(?<user>[^']+)'|user\\s+(?<user2>\\S+))\" | eval user=coalesce(user,user2) | stats count latest(_time) as last_seen by host user action | convert ctime(last_seen)",
      "cron_schedule": "*/5 * * * *",
      "dispatch.earliest_time": "-10m",
      "dispatch.latest_time": "now",
      "is_scheduled": 1,
      "alert_type": "number of events",
      "alert_comparator": "greater than",
      "alert_threshold": "0",
      "alert.severity": "5",
      "alert.suppress": "1",
      "alert.suppress.period": "2h"
    },
    {
      "name": "ENTRAMOX - Sudoers File Changed (/etc/sudoers.d)",
      "search": "index=linux (sourcetype=auditd OR sourcetype=ossec) \"/etc/sudoers.d/pve_realm-\" (\"CREATE\" OR \"WRITE\" OR \"DELETE\" OR \"modified\" OR \"deleted\") | rex field=_raw \"/etc/sudoers\\.d/pve_realm-(?<user>[A-Za-z0-9._-]+)\" | eval action=case(match(_raw,\"DELETE|deleted\"),\"sudoers_removed\", match(_raw,\"CREATE|created\"),\"sudoers_created\", match(_raw,\"WRITE|modified\"),\"sudoers_modified\", true(),\"sudoers_change\") | stats count latest(_time) as last_seen by host user action | convert ctime(last_seen)",
      "cron_schedule": "*/5 * * * *",
      "dispatch.earliest_time": "-10m",
      "dispatch.latest_time": "now",
      "is_scheduled": 1,
      "alert_type": "number of events",
      "alert_comparator": "greater than",
      "alert_threshold": "0",
      "alert.severity": "6",
      "alert.suppress": "1",
      "alert.suppress.period": "4h"
    },
    {
      "name": "ENTRAMOX - Reconciler: User Created",
      "search": "index=linux source=\"/var/log/entramoxreconciler/thelog.log\" \"Created local user:\" | rex \"Created local user:\\s+(?<user>\\S+)\" | stats count latest(_time) as created_at by host user | convert ctime(created_at)",
      "cron_schedule": "*/5 * * * *",
      "dispatch.earliest_time": "-10m",
      "dispatch.latest_time": "now",
      "is_scheduled": 1,
      "alert_type": "number of events",
      "alert_comparator": "greater than",
      "alert_threshold": "0",
      "alert.severity": "3",
      "alert.suppress": "1",
      "alert.suppress.period": "1h"
    },
    {
      "name": "ENTRAMOX - Reconciler: User Marked For Deletion",
      "search": "index=linux source=\"/var/log/entramoxreconciler/thelog.log\" \"locked and marked for deletion\" | rex \"User\\s+(?<user>\\S+)\\s+not in Entra allow-groups; locked and marked for deletion\" | stats count latest(_time) as marked_at by host user | convert ctime(marked_at)",
      "cron_schedule": "*/5 * * * *",
      "dispatch.earliest_time": "-10m",
      "dispatch.latest_time": "now",
      "is_scheduled": 1,
      "alert_type": "number of events",
      "alert_comparator": "greater than",
      "alert_threshold": "0",
      "alert.severity": "4",
      "alert.suppress": "1",
      "alert.suppress.period": "1h"
    },
    {
      "name": "ENTRAMOX - Reconciler: Sudo Granted/Revoked",
      "search": "index=linux source=\"/var/log/entramoxreconciler/thelog.log\" (\"Updated sudoers for\" OR \"Removed sudoers file for\") | rex \"for\\s+(?<user>\\S+)\" | eval action=if(match(_raw,\"Updated sudoers\"),\"sudo_granted\",\"sudo_revoked\") | stats count latest(_time) as last_seen by host user action | convert ctime(last_seen)",
      "cron_schedule": "*/5 * * * *",
      "dispatch.earliest_time": "-10m",
      "dispatch.latest_time": "now",
      "is_scheduled": 1,
      "alert_type": "number of events",
      "alert_comparator": "greater than",
      "alert_threshold": "0",
      "alert.severity": "5",
      "alert.suppress": "1",
      "alert.suppress.period": "2h"
    },
    {
      "name": "ENTRAMOX - Reconciler: Tiered Account Created",
      "description": "Detect privileged tiered account provisioning (v2.5+).",
      "search": "index=linux source=\"/var/log/entramoxreconciler/thelog.log\" \"Created tiered account\" | rex \"Created tiered account '(?<tiered_user>[^']+)' for base user '(?<base_user>[^']+)'\" | stats count latest(_time) as created_at by host tiered_user base_user | convert ctime(created_at)",
      "cron_schedule": "*/5 * * * *",
      "dispatch.earliest_time": "-10m",
      "dispatch.latest_time": "now",
      "is_scheduled": 1,
      "alert_type": "number of events",
      "alert_comparator": "greater than",
      "alert_threshold": "0",
      "alert.severity": "5",
      "alert.suppress": "1",
      "alert.suppress.period": "2h"
    },
    {
      "name": "ENTRAMOX - Reconciler: Tiered Account Removed",
      "description": "Detect privileged tiered account deprovisioning (v2.5+).",
      "search": "index=linux source=\"/var/log/entramoxreconciler/thelog.log\" \"Tiered account removed (no longer superadmin)\" | rex \"no longer superadmin\\):\\s+(?<tiered_user>\\S+)\" | stats count latest(_time) as removed_at by host tiered_user | convert ctime(removed_at)",
      "cron_schedule": "*/5 * * * *",
      "dispatch.earliest_time": "-10m",
      "dispatch.latest_time": "now",
      "is_scheduled": 1,
      "alert_type": "number of events",
      "alert_comparator": "greater than",
      "alert_threshold": "0",
      "alert.severity": "3",
      "alert.suppress": "1",
      "alert.suppress.period": "2h"
    },
    {
      "name": "ENTRAMOX - Reconciler: Remote API Auth Failure (PBS/PDM)",
      "description": "Detect 401/403 errors from PBS or PDM REST API calls (v2.5+).",
      "search": "index=linux source=\"/var/log/entramoxreconciler/thelog.log\" \"Remote API HTTP\" (\"401:\" OR \"403:\") | rex \"Remote API HTTP\\s+(?<method>\\S+)\\s+(?<url>\\S+)\\s+(?<status>[0-9]{3})\" | stats count latest(_time) as last_seen by host method url status | convert ctime(last_seen)",
      "cron_schedule": "*/5 * * * *",
      "dispatch.earliest_time": "-10m",
      "dispatch.latest_time": "now",
      "is_scheduled": 1,
      "alert_type": "number of events",
      "alert_comparator": "greater than",
      "alert_threshold": "0",
      "alert.severity": "5",
      "alert.suppress": "1",
      "alert.suppress.period": "1h"
    },
    {
      "name": "ENTRAMOX - Reconciler: PBS/PDM Auth Credentials Missing",
      "description": "Detect missing PBS or PDM API credentials — sync will silently fail (v2.5+).",
      "search": "index=linux source=\"/var/log/entramoxreconciler/thelog.log\" (\"PBS auth header missing\" OR \"PDM auth header missing\") | eval system=if(match(_raw,\"^PBS\"),\"PBS\",\"PDM\") | stats count latest(_time) as last_seen by host system | convert ctime(last_seen)",
      "cron_schedule": "*/5 * * * *",
      "dispatch.earliest_time": "-10m",
      "dispatch.latest_time": "now",
      "is_scheduled": 1,
      "alert_type": "number of events",
      "alert_comparator": "greater than",
      "alert_threshold": "0",
      "alert.severity": "6",
      "alert.suppress": "1",
      "alert.suppress.period": "4h"
    },
    {
      "name": "ENTRAMOX - Reconciler: PVE User Enabled/Disabled",
      "search": "index=linux source=\"/var/log/entramoxreconciler/thelog.log\" \"PVE user\" (\"created\" OR \"set enable\") | rex \"PVE user\\s+(?<userid>\\S+)\" | rex \"enable=(?<enabled>[01])\" | eval state=if(enabled==\"1\",\"enabled\",\"disabled\") | stats count latest(_time) as last_seen by host userid state | convert ctime(last_seen)",
      "cron_schedule": "*/5 * * * *",
      "dispatch.earliest_time": "-10m",
      "dispatch.latest_time": "now",
      "is_scheduled": 1,
      "alert_type": "number of events",
      "alert_comparator": "greater than",
      "alert_threshold": "0",
      "alert.severity": "4",
      "alert.suppress": "1",
      "alert.suppress.period": "2h"
    },
    {
      "name": "ENTRAMOX - Integrity: Script Checksum Mismatch",
      "description": "Detect binary hash mismatch from entramox_check.sh — possible tampering (v2.5+).",
      "search": "index=linux source=\"/var/log/entramoxreconciler/thelog.log\" \"[entramox_check]\" \"script checksum mismatch\" | rex \"\\[entramox_check\\] Integrity: script checksum mismatch file=(?<path>\\S+) have=(?<have>[0-9a-f]+) expect=(?<expect>[0-9a-f]+)\" | stats count latest(_time) as last_seen values(have) as observed_hash values(expect) as expected_hash by host path | convert ctime(last_seen)",
      "cron_schedule": "*/5 * * * *",
      "dispatch.earliest_time": "-10m",
      "dispatch.latest_time": "now",
      "is_scheduled": 1,
      "alert_type": "number of events",
      "alert_comparator": "greater than",
      "alert_threshold": "0",
      "alert.severity": "6",
      "alert.suppress": "1",
      "alert.suppress.period": "1h"
    },
    {
      "name": "ENTRAMOX - Integrity: File Tampering (Symlink/Owner/Perms)",
      "description": "Detect symlink, wrong owner, or broad permissions on managed files (v2.5+).",
      "search": "index=linux source=\"/var/log/entramoxreconciler/thelog.log\" \"[entramox_check]\" (\"symlink refused\" OR \"file not owned by root\" OR \"permissions too broad\") | rex \"\\[entramox_check\\] Integrity: (?<check_type>symlink refused|file not owned by root|permissions too broad) path=(?<path>\\S+)\" | rex \"uid=(?<uid>\\d+)\" | rex \"mode=(?<mode>\\S+)\" | eval detail=coalesce(\"uid=\".uid, \"mode=\".mode, \"\") | stats count latest(_time) as last_seen by host check_type path detail | convert ctime(last_seen)",
      "cron_schedule": "*/5 * * * *",
      "dispatch.earliest_time": "-10m",
      "dispatch.latest_time": "now",
      "is_scheduled": 1,
      "alert_type": "number of events",
      "alert_comparator": "greater than",
      "alert_threshold": "0",
      "alert.severity": "6",
      "alert.suppress": "1",
      "alert.suppress.period": "1h"
    },
    {
      "name": "ENTRAMOX - Integrity: Env or Key File Hash Changed",
      "description": "Detect env or key file checksum change from entramox_check.sh (v2.5+).",
      "search": "index=linux source=\"/var/log/entramoxreconciler/thelog.log\" \"[entramox_check]\" (\"env checksum changed\" OR \"key checksum changed\") | rex \"\\[entramox_check\\] Integrity: (?<file_type>env|key) checksum changed path=(?<path>\\S+) have=(?<have>[0-9a-f]+) expect=(?<expect>[0-9a-f]+)\" | stats count latest(_time) as last_seen by host file_type path have expect | convert ctime(last_seen)",
      "cron_schedule": "*/5 * * * *",
      "dispatch.earliest_time": "-10m",
      "dispatch.latest_time": "now",
      "is_scheduled": 1,
      "alert_type": "number of events",
      "alert_comparator": "greater than",
      "alert_threshold": "0",
      "alert.severity": "5",
      "alert.suppress": "1",
      "alert.suppress.period": "4h"
    },
    {
      "name": "ENTRAMOX - Integrity: Missing Monitored File",
      "description": "Detect missing script, env, or key file from entramox_check.sh (v2.5+).",
      "search": "index=linux source=\"/var/log/entramoxreconciler/thelog.log\" \"[entramox_check]\" \"missing file\" | rex \"\\[entramox_check\\] Integrity: missing file path=(?<path>.+)$\" | stats count latest(_time) as last_seen by host path | convert ctime(last_seen)",
      "cron_schedule": "*/15 * * * *",
      "dispatch.earliest_time": "-30m",
      "dispatch.latest_time": "now",
      "is_scheduled": 1,
      "alert_type": "number of events",
      "alert_comparator": "greater than",
      "alert_threshold": "0",
      "alert.severity": "5",
      "alert.suppress": "1",
      "alert.suppress.period": "4h"
    }
  ]
}
```

---

## Splunk ES Notable Templates

### ES Notable: Sudo Privilege Granted (Critical)

```json
{
  "name": "ES - ENTRAMOX - Sudo Privilege Granted",
  "search": "index=linux source=\"/var/log/entramoxreconciler/thelog.log\" \"Updated sudoers for\" | rex \"for\\s+(?<user>\\S+)\" | stats latest(_time) as _time by host user | eval signature=\"ENTRAMOX sudo granted\"",
  "cron_schedule": "*/5 * * * *",
  "dispatch.earliest_time": "-10m",
  "dispatch.latest_time": "now",
  "is_scheduled": 1,
  "actions": "notable",
  "action.notable.param.rule_title": "ENTRAMOX: Sudo privilege granted",
  "action.notable.param.rule_description": "entramoxreconciler granted sudo. Confirm change control and expected provisioning path.",
  "action.notable.param.severity": "critical",
  "action.notable.param.urgency": "high",
  "action.notable.param.default_owner": "secops",
  "action.notable.param.default_status": "1",
  "action.notable.param.drilldown_search": "index=linux host=\"$result.host$\" (\"$result.user$\" OR \"pve_realm-$result.user$\") earliest=-24h"
}
```

### ES Notable: Tiered Account Provisioned (High)

```json
{
  "name": "ES - ENTRAMOX - Tiered Account Provisioned",
  "search": "index=linux source=\"/var/log/entramoxreconciler/thelog.log\" \"Created tiered account\" | rex \"Created tiered account '(?<tiered_user>[^']+)' for base user '(?<base_user>[^']+)'\" | stats latest(_time) as _time by host tiered_user base_user | eval signature=\"ENTRAMOX tiered account provisioned\"",
  "cron_schedule": "*/5 * * * *",
  "dispatch.earliest_time": "-10m",
  "dispatch.latest_time": "now",
  "is_scheduled": 1,
  "actions": "notable",
  "action.notable.param.rule_title": "ENTRAMOX: Privileged tiered account provisioned",
  "action.notable.param.rule_description": "A superadmin user received a tiered privileged Linux account. Verify Entra group membership and change request.",
  "action.notable.param.severity": "high",
  "action.notable.param.urgency": "high",
  "action.notable.param.default_owner": "iam-ops",
  "action.notable.param.default_status": "1",
  "action.notable.param.drilldown_search": "index=linux host=\"$result.host$\" (\"$result.tiered_user$\" OR \"$result.base_user$\") earliest=-24h"
}
```

### ES Notable: Remote API Auth Failure (High)

```json
{
  "name": "ES - ENTRAMOX - Remote API Auth Failure",
  "search": "index=linux source=\"/var/log/entramoxreconciler/thelog.log\" \"Remote API HTTP\" (\"401:\" OR \"403:\") | rex \"Remote API HTTP\\s+(?<method>\\S+)\\s+(?<url>\\S+)\\s+(?<status>[0-9]{3})\" | stats latest(_time) as _time count by host url status | eval signature=\"ENTRAMOX remote API auth failure\"",
  "cron_schedule": "*/5 * * * *",
  "dispatch.earliest_time": "-10m",
  "dispatch.latest_time": "now",
  "is_scheduled": 1,
  "actions": "notable",
  "action.notable.param.rule_title": "ENTRAMOX: PBS/PDM API authentication failure",
  "action.notable.param.rule_description": "PBS or PDM returned 401/403. API token may be expired or revoked. Entramox sync is degraded.",
  "action.notable.param.severity": "high",
  "action.notable.param.urgency": "high",
  "action.notable.param.default_owner": "secops",
  "action.notable.param.default_status": "1",
  "action.notable.param.drilldown_search": "index=linux host=\"$result.host$\" \"Remote API\" earliest=-4h"
}
```

### ES Notable: User Marked for Deletion (High)

```json
{
  "name": "ES - ENTRAMOX - User Marked For Deletion",
  "search": "index=linux source=\"/var/log/entramoxreconciler/thelog.log\" \"locked and marked for deletion\" | rex \"User\\s+(?<user>\\S+)\\s+not in Entra allow-groups\" | stats latest(_time) as _time by host user | eval signature=\"ENTRAMOX user marked for deletion\"",
  "cron_schedule": "*/5 * * * *",
  "dispatch.earliest_time": "-10m",
  "dispatch.latest_time": "now",
  "is_scheduled": 1,
  "actions": "notable",
  "action.notable.param.rule_title": "ENTRAMOX: User marked for deletion (grace period)",
  "action.notable.param.rule_description": "User removed from Entra allow-groups. Account locked; deletion countdown started. Verify leaver/mover process.",
  "action.notable.param.severity": "high",
  "action.notable.param.urgency": "high",
  "action.notable.param.default_owner": "iam-ops",
  "action.notable.param.default_status": "1",
  "action.notable.param.drilldown_search": "index=linux host=\"$result.host$\" \"$result.user$\" earliest=-7d"
}
```

### ES Notable: Sudoers File Modified (Critical)

```json
{
  "name": "ES - ENTRAMOX - Sudoers File Modified",
  "search": "index=linux (sourcetype=auditd OR sourcetype=ossec) \"/etc/sudoers.d/pve_realm-\" (\"WRITE\" OR \"modified\") | rex \"/etc/sudoers\\.d/pve_realm-(?<user>[A-Za-z0-9._-]+)\" | stats latest(_time) as _time values(_raw) as evidence by host user | eval signature=\"Sudoers file modified\"",
  "cron_schedule": "*/5 * * * *",
  "dispatch.earliest_time": "-10m",
  "dispatch.latest_time": "now",
  "is_scheduled": 1,
  "actions": "notable",
  "action.notable.param.rule_title": "Sudoers file modified (managed pve_realm)",
  "action.notable.param.rule_description": "Managed sudoers file changed outside reconciler flow. Potential manual privilege escalation or tampering.",
  "action.notable.param.severity": "critical",
  "action.notable.param.urgency": "high",
  "action.notable.param.default_owner": "secops",
  "action.notable.param.default_status": "1",
  "action.notable.param.drilldown_search": "index=linux host=\"$result.host$\" \"/etc/sudoers.d/pve_realm-$result.user$\" earliest=-24h"
}
```

### ES Notable: Integrity Script Checksum Mismatch (Critical)

```json
{
  "name": "ES - ENTRAMOX - Integrity Script Checksum Mismatch",
  "search": "index=linux source=\"/var/log/entramoxreconciler/thelog.log\" \"[entramox_check]\" \"script checksum mismatch\" | rex \"\\[entramox_check\\] Integrity: script checksum mismatch file=(?<path>\\S+) have=(?<have>[0-9a-f]+) expect=(?<expect>[0-9a-f]+)\" | stats latest(_time) as _time values(have) as observed_hash values(expect) as expected_hash by host path | eval signature=\"ENTRAMOX integrity: script tampered\"",
  "cron_schedule": "*/5 * * * *",
  "dispatch.earliest_time": "-10m",
  "dispatch.latest_time": "now",
  "is_scheduled": 1,
  "actions": "notable",
  "action.notable.param.rule_title": "ENTRAMOX: Script checksum mismatch — possible binary tamper",
  "action.notable.param.rule_description": "entramox_check.sh detected that the reconciler script SHA-256 does not match the stored baseline. The binary may have been replaced. Treat as Critical until ruled out. Disable the service and investigate.",
  "action.notable.param.severity": "critical",
  "action.notable.param.urgency": "high",
  "action.notable.param.default_owner": "secops",
  "action.notable.param.default_status": "1",
  "action.notable.param.drilldown_search": "index=linux host=\"$result.host$\" \"[entramox_check]\" earliest=-24h"
}
```

### ES Notable: Integrity File Tampering — Symlink / Owner / Perms (Critical)

```json
{
  "name": "ES - ENTRAMOX - Integrity File Tampering",
  "search": "index=linux source=\"/var/log/entramoxreconciler/thelog.log\" \"[entramox_check]\" (\"symlink refused\" OR \"file not owned by root\" OR \"permissions too broad\") | rex \"\\[entramox_check\\] Integrity: (?<check_type>symlink refused|file not owned by root|permissions too broad) path=(?<path>\\S+)\" | stats latest(_time) as _time count by host check_type path | eval signature=\"ENTRAMOX integrity: file tampering indicator\"",
  "cron_schedule": "*/5 * * * *",
  "dispatch.earliest_time": "-10m",
  "dispatch.latest_time": "now",
  "is_scheduled": 1,
  "actions": "notable",
  "action.notable.param.rule_title": "ENTRAMOX: File tampering indicator ($result.check_type$)",
  "action.notable.param.rule_description": "entramox_check.sh found a monitored file with suspicious attributes: symlink, wrong owner, or permissions too broad. Investigate $result.path$ on $result.host$ immediately.",
  "action.notable.param.severity": "critical",
  "action.notable.param.urgency": "high",
  "action.notable.param.default_owner": "secops",
  "action.notable.param.default_status": "1",
  "action.notable.param.drilldown_search": "index=linux host=\"$result.host$\" \"[entramox_check]\" earliest=-24h"
}
```

---

## Final Notes

* Prefer **script log–based detections** (searches 6–20) for high signal and low false positives.
* Use auth/auditd logs for **corroboration**, not primary alerting.
* **Suppress** raw `useradd/usermod` alerts when the reconciler log confirms legitimacy.
* Monitor the **audit log** for tiered account events — these are high-privilege actions.
* Repeated remote API errors (searches 13–14) indicate a broken PBS/PDM sync that needs immediate investigation.
* Integrity checker alerts (searches 17–20) are **always high/critical** — the checker only fires on genuine anomalies. Suppress period should be short (≤1h) to catch repeated attempts.

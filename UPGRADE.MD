# Upgrade Guide
## Sudomatic 5000 → Entramox Reconciler (v2.0.0a)

This document explains how to safely upgrade from **Sudomatic 5000 (1.3.x / 1.4.x)** to **Entramox Reconciler (2.0.0a)**.

Version 2.0.0a is a **major upgrade** with structural and behavioural changes.  
Read this fully before running the installer.

---

## TL;DR

* Upgrade **is supported** from 1.3.x and 1.4.x
* Existing users are **not deleted**
* State, logs, and config are **migrated automatically**
* Enforcement logic is stricter and more explicit
* You **must review group and role mappings** after upgrade

---

## What Changes in v2

### Naming
* Project name: **Sudomatic 5000 → Entramox Reconciler**
* Script:
  * `/usr/local/sbin/sudomatic5000.py`
  * → `/usr/local/sbin/entramoxreconciler.py`
* systemd units:
  * `sudomatic.service / sudomatic.timer`
  * → `entramoxreconciler.service / entramoxreconciler.timer`

### Paths
| Purpose | Old | New |
|------|-----|-----|
| Logs | `/var/log/sudomatic5000/` | `/var/log/entramoxreconciler/` |
| State | `/var/lib/sudomatic5000/` | `/var/lib/entramoxreconciler/` |
| Env | `/etc/sudomatic5000.env` | `/etc/entramoxreconciler.env` |

Old paths are detected and migrated automatically.

---

## Pre-Upgrade Checklist

Before upgrading, confirm:

1. You are running as root
2. The current service is healthy
3. You know which Entra groups are authoritative

Recommended checks:

```bash
systemctl status sudomatic.service
journalctl -u sudomatic.service -n 50 --no-pager
````

Optional but recommended backup:

```bash
sudo cp -a /etc/sudomatic5000.env /root/sudomatic5000.env.bak
sudo cp -a /var/lib/sudomatic5000 /root/sudomatic5000-state.bak
```

---

## Upgrade Procedure

### Step 1: Stop the old service

```bash
sudo systemctl stop sudomatic.timer sudomatic.service
```

Do not disable yet. The installer will handle cleanup.

---

### Step 2: Run the installer update

From your repo working directory:

```bash
sudo ./installer.py update
```

What this does:

* Detects Sudomatic 5000 installation
* Renames scripts and units
* Migrates logs and state
* Migrates env file
* Migrates encryption key if present
* Installs new service and timer

No users are modified during this step.

---

### Step 3: Review the new environment file

Open the migrated config:

```bash
sudoedit /etc/entramoxreconciler.env
```

Key things to review carefully:

#### Required (new or changed)

```ini
# One or more Entra groups to enforce
ENTRA_GROUP_IDS="group-id-1 group-id-2"

# Optional role mapping (JSON)
ENTRA_ROLE_MAP='[
  {"group":"group-id-1","pve_role":"Administrator"}
]'
```

#### Legacy variables that may no longer apply

* `ENTR_SUPERUSR_ID`
* `GRAPH_ENFORCE`
* `EXTRA_GROUPS=sudo`

These still work, but behaviour is more explicit in v2.

---

### Step 4: Dry-run sanity check

Run once manually before enabling the timer:

```bash
sudo /usr/local/sbin/entramoxreconciler.py
```

Confirm:

* No unexpected users are locked
* No mass deletion warnings
* Graph groups resolve correctly
* Logs look sane

Check logs:

```bash
tail -n 100 /var/log/entramoxreconciler/thelog.log
```

---

### Step 5: Enable new service and timer

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now entramoxreconciler.service
sudo systemctl enable --now entramoxreconciler.timer
```

Verify:

```bash
systemctl status entramoxreconciler.service
systemctl list-timers | grep entramox
```

---

## Behavioural Differences You Must Understand

### Group enforcement

* v1: single group allowed users
* v2: **multiple groups** may allow users
* Removal from **all** allow-groups triggers lifecycle actions

### Entra disabled users

If a user is still in an allow-group but disabled in Entra:

* Account is locked locally
* Sudo is revoked
* PVE account is disabled
* User is **not deleted**

### Removed users

If a user is no longer in any allow-group:

* Account is locked immediately
* PVE account is disabled
* User enters deletion grace period
* Deleted after `DELETE_AFTER`

---

## Rollback Strategy

If something looks wrong:

```bash
sudo systemctl stop entramoxreconciler.timer entramoxreconciler.service
```

Restore backups if required:

```bash
sudo mv /etc/entramoxreconciler.env /etc/entramoxreconciler.env.bad
sudo cp /root/sudomatic5000.env.bak /etc/sudomatic5000.env
```

Then reinstall v1.x from your tagged release.

No irreversible actions are taken until a user passes the deletion grace period.

---

## Common Upgrade Issues

### No users detected

* Check `REALM` spelling
* Verify Entra group IDs
* Ensure `User.Read.All` and `GroupMember.Read.All` are granted

### Users locked unexpectedly

* Confirm group membership logic
* Remember v2 is stricter than v1
* Check `GRAPH_FAIL_OPEN` behaviour

### Sudo missing

* Only Super Admin users receive sudo
* Verify `ENTRA_SUPERADMIN_GROUP_ID`
* Confirm `GRANT_SUDO=true`

---

## Final Notes

* Upgrading early is recommended
* v1.x will receive only limited security fixes
* v2.x is the foundation for future features
* Behaviour is more explicit, logged, and auditable

If in doubt, run the script manually and read the logs.
It tells you exactly why it is doing what it is doing.

---

End of upgrade guide.

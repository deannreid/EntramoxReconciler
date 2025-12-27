# Entramox Reconciler

***Turning realms into real users, one sudo at a time.***

Entramox Reconciler syncs OIDC users from **Proxmox VE** into real **Linux** accounts, with optional enforcement from **Microsoft Entra ID (Graph)**.

It creates local users, sets a random expired password, manages groups and sudoers idempotently, and handles leavers with a lock then delete lifecycle. It also keeps **Proxmox (PVE) users** aligned, including enable or disable state, ACL roles, and metadata.

Logs are written to:

```

/var/log/entramoxreconciler/thelog.log

````

The service is safe by default. Reserved system accounts are never touched, binaries are pinned, integrity is enforced, and runs are protected by a lockfile.

---

## ⚠️ Casual Cyber Warning

> **This script will refuse to start unless it is owned by `root:root` and has `0700` permissions.**
> That is intentional, so nobody can swap it and mint sudo.
>
> The systemd service uses an **ExecCondition integrity check**.  
> A helper script verifies the **SHA-256 checksum** of:
>
> * `/usr/local/sbin/entramoxreconciler.py`
> * `/etc/entramoxreconciler.env`
> * `/etc/entramoxreconciler.key`
>
> If the script checksum does not match what was captured during install or update, **the service will not run**.

Before enabling the service or timer, ensure permissions are correct:

```bash
sudo chown root:root /usr/local/sbin/entramoxreconciler.py /usr/local/sbin/entramox_check.sh
sudo chmod 700        /usr/local/sbin/entramoxreconciler.py /usr/local/sbin/entramox_check.sh
sudo install -d -m 0750 -o root -g root /var/log/entramoxreconciler
sudo install -d -m 0750 -o root -g root /var/lib/entramoxreconciler
````

**The service must run as root.**
Do not place the script or env files in user writable locations.

To update the code, do **not** edit the installed file directly. Update from the repo and refresh the checksum:

```bash
sudo ./installer.py update --restart
```

If ownership, permissions, or checksums do not match, the script exits immediately to prevent privilege escalation.

---

## What Entramox Reconciler does

For each run:

* Reads users from the configured **Proxmox OIDC realm**
* Optionally intersects them with one or more **Entra ID groups**
* Maps UPNs to local Unix usernames using configurable rules
* Creates missing local users and expires their passwords
* Manages baseline groups and sudo access idempotently
* Disables PVE users when Entra users are disabled
* Locks users removed from the desired set
* Deletes locked users after a configurable grace period
* Updates Proxmox user comments to reflect lifecycle state

---

## Quick start

### Supported authentication models

Entramox Reconciler supports **two Graph authentication modes**:

1. **Application credentials (recommended)**

   * Uses client credentials
   * Safe for timers and unattended execution

2. **Delegated access token**

   * Useful for testing
   * Short lived and not suitable for timers

---

## Required Entra permissions

### Application permissions (service mode)

These are required when using client credentials:

* **GroupMember.Read.All**
* **User.Read.All**
* Optional: **Member.Read.Hidden** (only if group membership is hidden)

Admin consent is required.

### Delegated permissions (optional)

Only needed for interactive testing:

* **email**
* **openid**
* **profile**
* Optional: **GroupMember.Read.All**

---

## Entra portal steps

1. Register an app
   Entra ID → App registrations → New registration
   Single tenant is sufficient

2. Create a client secret
   Certificates and secrets → New client secret

3. Add API permissions
   Microsoft Graph → Application permissions
   Grant admin consent

4. Collect the following values:

   * Tenant ID
   * Client ID
   * Client secret
   * Entra group Object IDs

---

## Installation

### First time install

```bash
sudo ./installer.py install
```

This will:

* Install Python dependencies
* Deploy the script and checker
* Generate an encryption key
* Create `/etc/entramoxreconciler.env`
* Write systemd service and timer
* Enable and start the timer

### Update existing install

```bash
sudo ./installer.py update
sudo ./installer.py update --restart
```

Legacy **sudomatic5000** installs are detected and migrated automatically.

### Uninstall

```bash
sudo ./installer.py uninstall
```

To fully purge config, logs, and state:

```bash
sudo ./installer.py uninstall --purge
```

---

## Configuration model

Entramox Reconciler is **env driven**.

The primary config file is:

```
/etc/entramoxreconciler.env
```

It must be owned by root and have `0600` permissions.

Edit it safely:

```bash
sudoedit /etc/entramoxreconciler.env
sudo systemctl daemon-reload
sudo systemctl restart entramoxreconciler.service
```

---

## Minimal configuration example

```ini
REALM='MY-REALM'
DEFAULT_SHELL='/bin/bash'

GRAPH_ENFORCE='true'
GRAPH_FAIL_OPEN='true'

ALLOWED_UPN_DOMAINS='example.com sub.example.com'

ENTRA_ALLUSERS_GROUP_ID='00000000-0000-0000-0000-000000000000'
ENTRA_ALLUSERS_PVE_ROLE='PVEUser'

ENTRA_SUPERADMIN_GROUP_ID='11111111-1111-1111-1111-111111111111'
ENTRA_SUPERADMIN_PVE_ROLE='Administrator'

ENTR_TENANT_ID='tenant-guid'
ENTR_CLNT_ID='client-guid'
ENTR_CLNT_SEC_ENC='fernet:...'
```

---

## Username mapping behaviour

Username mapping is configurable:

* `USERNAME_MODE=useronly`
  `user@domain.com` → `user`

* `USERNAME_MODE=upn_concat`
  `user@domain.com` → `user_domain.com`

Additional controls:

* `USERNAME_SEPARATOR`
* `USERNAME_LOWERCASE`
* `USERNAME_MAXLEN`

All usernames are sanitised before creation.

---

## Lifecycle behaviour

### Desired users

A user is desired if:

* They exist in the configured Proxmox realm
* AND they are a member of at least one enforced Entra group (when enabled)
* AND their UPN domain is allowed

### Entra disabled users

If an Entra account is disabled but still in the group:

* Local account is locked
* Sudo is revoked
* PVE user is disabled
* No deletion countdown is started

This state is reversible.

### Group removal

If a user leaves all allowed groups:

* Local account is locked immediately
* Sudo is revoked
* PVE user is disabled
* User enters a grace period
* Proxmox comment is updated with remaining time
* User is deleted after `DELETE_AFTER`

---

## Logging and visibility

Logs are written to:

```
/var/log/entramoxreconciler/thelog.log
```

Journal view:

```bash
journalctl -u entramoxreconciler.service -f
```

Logrotate is installed automatically.

---

## Safety features

* Root ownership enforcement
* Strict file permissions
* SHA-256 integrity checks
* Atomic file writes
* Lockfile to prevent concurrent runs
* Reserved users are never touched
* Fail open or fail closed Graph behaviour is configurable

---

## Troubleshooting

* No users synced
  Check `REALM` matches Proxmox exactly

* Graph 403 errors
  Verify permissions and admin consent

* Users never deleted
  Check `GRAPH_FAIL_OPEN` and grace period

* Sudo not applied
  Confirm `GRANT_SUDO=true` and user is in superadmin group

* Service not reading env
  Run:

  ```bash
  systemctl show entramoxreconciler.service -p EnvironmentFiles -p Environment
  ```



Enjoy the realm wrangling 🧙‍♂️
# Rollback Guide
## Entramox Reconciler (v2.x) → Sudomatic 5000 (v1.x)

This document explains how to rollback from **Entramox Reconciler (v2.x)** to **Sudomatic 5000 (v1.x)**.

Rollback is safe if performed promptly. The only potentially irreversible action is **local user deletion**, which only occurs if the v2 deletion grace period elapsed and deletion was enabled.

---

## When to Rollback

Rollback is appropriate if you observe:

* Unexpected account locks
* Incorrect group membership interpretation
* Graph / Entra failures causing enforcement behaviour you do not want
* Mis-mapped PVE roles or permissions
* A config migration you do not trust yet

---

## What Rollback Does (and Does Not) Do

### Rollback does
* Stops v2 service and timer
* Restores v1 service and timer
* Restores v1 env/config
* Restores v1 paths for logs/state (if you choose)

### Rollback does not
* Undelete local users that were deleted
* Automatically revert local password changes
* Recreate PVE tokens, API keys, or external secrets
* Repair Entra group membership issues

---

## Safety Notes

1. **Stop enforcement first**  
   Do not leave v2 running while restoring v1.

2. **Check deletion settings**  
   If v2 deletion is enabled and you leave it running, it may delete users after the grace period.

3. **Prefer restoring from backup**  
   If you made backups during upgrade, use them.

---

## Quick Rollback (Recommended)

### Step 1: Stop v2

```bash
sudo systemctl stop entramoxreconciler.timer entramoxreconciler.service
sudo systemctl disable entramoxreconciler.timer entramoxreconciler.service
````

Confirm it is down:

```bash
systemctl status entramoxreconciler.service
systemctl list-timers | grep -i entramox || true
```

---

### Step 2: Restore v1 installer or package

Rollback requires a **known-good v1 release**. Use the tagged version you upgraded from.

Example:

```bash
git fetch --tags
git checkout v1.3.5
```

---

### Step 3: Reinstall v1

Run the v1 installer in install or repair mode.

```bash
sudo ./installer.py install
```

If your v1 installer supports `update` as idempotent repair, use that instead:

```bash
sudo ./installer.py update
```

---

### Step 4: Restore v1 config

If you backed up the env file:

```bash
sudo cp -a /root/sudomatic5000.env.bak /etc/sudomatic5000.env
sudo chmod 600 /etc/sudomatic5000.env
```

If you did not back it up, you may still have it:

* `/etc/sudomatic5000.env`
* or `/etc/entramoxreconciler.env` (copy values back)

---

### Step 5: Restore v1 state (optional but recommended)

If you backed up state:

```bash
sudo rsync -a /root/sudomatic5000-state.bak/ /var/lib/sudomatic5000/
```

If v2 migrated the state and you want to reuse it, prefer restoring from the backup anyway.
If you do not have a backup, you can usually proceed without it.

---

### Step 6: Enable v1 service and timer

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sudomatic.service
sudo systemctl enable --now sudomatic.timer
```

Verify:

```bash
systemctl status sudomatic.service
systemctl list-timers | grep -i sudomatic
```

---

## Manual Rollback (If You Cannot Use the Installer)

Use this if the repo or installer is unavailable.

### Step 1: Stop and disable v2

```bash
sudo systemctl stop entramoxreconciler.timer entramoxreconciler.service
sudo systemctl disable entramoxreconciler.timer entramoxreconciler.service
```

### Step 2: Remove v2 unit files (optional)

```bash
sudo rm -f /etc/systemd/system/entramoxreconciler.service
sudo rm -f /etc/systemd/system/entramoxreconciler.timer
sudo systemctl daemon-reload
```

### Step 3: Restore v1 unit files

If you have copies of the original unit files, restore them:

```bash
sudo cp -a /root/sudomatic.service /etc/systemd/system/sudomatic.service
sudo cp -a /root/sudomatic.timer   /etc/systemd/system/sudomatic.timer
sudo systemctl daemon-reload
```

If you do not have copies, reinstalling from the v1 tag is strongly preferred.

### Step 4: Restore v1 script

```bash
sudo cp -a /usr/local/sbin/sudomatic5000.py /usr/local/sbin/sudomatic5000.py
sudo chmod 755 /usr/local/sbin/sudomatic5000.py
```

If the file is missing, you must reinstall from v1 source.

### Step 5: Restore v1 env

```bash
sudo cp -a /etc/sudomatic5000.env /etc/sudomatic5000.env
sudo chmod 600 /etc/sudomatic5000.env
```

### Step 6: Start v1

```bash
sudo systemctl enable --now sudomatic.service
sudo systemctl enable --now sudomatic.timer
```

---

## Post-Rollback Validation

Run v1 manually once:

```bash
sudo /usr/local/sbin/sudomatic5000.py
```

Check logs:

```bash
tail -n 100 /var/log/sudomatic5000/thelog.log
```

Confirm:

* Script runs without Graph auth errors
* Expected users remain enabled
* Expected sudo mappings exist
* No unexpected deletion actions are pending

---

## Handling “Damage” After Rollback

### Users were deleted under v2

If users were deleted locally, v1 cannot restore them automatically.

Options:

* Recreate users from Entra membership (manual or scripted)
* Restore from system backup / snapshot if available
* Reimage if required by policy

### Users were locked

Locks are reversible. After rollback, v1 should correct state on next run if the user is still authorised.

If you need to unlock immediately:

```bash
sudo usermod -U <username>
```

Also validate sudo group membership if applicable.

---

## Cleanup (Optional)

After successful rollback, you may remove v2 artefacts:

* `/var/log/entramoxreconciler/`
* `/var/lib/entramoxreconciler/`
* `/etc/entramoxreconciler.env`
* `/usr/local/sbin/entramoxreconciler.py`

Do not delete anything until you are confident you will not re-upgrade.

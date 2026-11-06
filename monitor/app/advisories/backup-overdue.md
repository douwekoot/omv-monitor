## What is measured

Each backup target reports the time of its last successful run (`omv_device_backup_last_success_timestamp_seconds`) and whether the last run succeeded (`omv_device_backup_last_ok`). The age is compared with the backup age threshold (default 36 h, changeable in Settings).

## When it is raised

- **Advisory** when the last success is older than the threshold, when it is not reported, or when a configured target has no metrics.
- **Finding** when the last run failed or the last success is older than twice the threshold.

## Why it matters

A backup that has quietly stopped leaves no recent copy to restore from.

## How to fix

1. Look at the target's backup log and the last error.
2. Check that the device is reachable and the NAS has free space.
3. Run the backup by hand and confirm it finishes.

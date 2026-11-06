## What is measured

The host script reads the SMART overall health of each disk with `smartctl -H` and stores it as `omv_smart_healthy` (1 = passed, 0 = failed).

## When it is raised

- **Finding** when a disk fails its SMART health check.
- **Advisory** when a disk has no value, or when no disk is reported at all.

## Why it matters

A failed SMART check means the disk expects to fail soon. The data on it, and anything stored only there, is at risk.

## How to fix

1. Look at the details: `smartctl -a /dev/<device>`.
2. Check that a recent backup exists and can be restored.
3. Replace the disk. If nothing is reported, check that `smartmontools` is installed and that the metrics script can run it.

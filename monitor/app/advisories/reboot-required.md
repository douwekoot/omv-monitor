## What is measured

The host script checks whether `/var/run/reboot-required` exists and stores it as `omv_reboot_required` (1 = a restart is needed).

## When it is raised

- **Advisory** when a restart is needed.

## Why it matters

Some updates, kernel updates in particular, only take effect after a restart. Until then the old code keeps running.

## How to fix

Restart the server at a quiet moment: OMV: System, Power Management, or `reboot` over SSH.

## What is measured

The time since each WireGuard device last completed a handshake (`omv_wg_latest_handshake_timestamp_seconds`). The threshold defaults to 7 days and can be changed in Settings.

## When it is raised

- **Finding** when a device has not connected for longer than the threshold.
- **Advisory** when a device has never connected.

## Why it matters

A device that has been silent for a day has probably lost its VPN, so it cannot reach home.

## How to fix

1. Open the WireGuard app on the device and check that the tunnel is on.
2. Check the device's endpoint, keys and allowed IPs against the peer on this server.

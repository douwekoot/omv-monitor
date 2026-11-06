## What is measured

The used share of each real filesystem, from `node_filesystem_size_bytes` and `node_filesystem_avail_bytes` (tmpfs and overlay mounts are left out). The threshold defaults to 85% and can be changed in Settings.

## When it is raised

- **Advisory** when a filesystem is at or above the threshold, or its size is not reported.
- **Finding** when it is also at or above 95%.

## Why it matters

A full disk stops services, corrupts writes and makes backups fail.

## How to fix

1. Find what takes the space: `du -xh --max-depth=1 /srv | sort -h`.
2. Remove what is not needed, or add storage.

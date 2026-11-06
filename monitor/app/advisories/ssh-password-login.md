## What is measured

The effective SSH server setting from `sshd -T`: whether `passwordauthentication` is `yes`. Stored as `omv_ssh_password_auth`.

## When it is raised

- **Finding** when password login is allowed.
- **Advisory** when the value is missing.

## Why it matters

SSH is reachable from the whole LAN and over the VPN. With passwords allowed, anything on those networks can try to guess one, including for root. With keys only, guessing is impossible.

## How to fix

OMV writes `/etc/ssh/sshd_config` from its own settings, so editing that file by hand is overwritten. Change it in OMV instead.

1. First make sure key login works for every account you use. From your laptop, `ssh -o PasswordAuthentication=no root@192.168.1.10` must log in without asking for a password.
2. In the OMV web interface, open Services, SSH, turn off **Password authentication**, save, and apply the pending changes.
3. Keep your current SSH session open and test a new key login from a second terminal before you close it.
4. Optional, later: once you have a normal user with a key and sudo, turn off **Permit root login** on the same page. It is on today.

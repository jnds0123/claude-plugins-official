---
name: mac-security-audit
description: This skill should be used when interpreting macOS security scan output, or when the user asks to "check my Mac for malware", "see what's running in the background", "find unauthorized scripts or programs", "audit launch agents", or asks whether a specific macOS process, launchd plist, or login item is safe. Provides knowledge of macOS persistence mechanisms, benign-vs-suspicious signals, and safe remediation steps.
version: 1.0.0
---

# macOS Security Audit Knowledge

Defensive knowledge for auditing a Mac: where background programs hide, how to
tell legitimate software from malware, and how to remediate safely. Use it to
interpret output from the mac-security-monitor scripts or any manual audit.

## Where background code runs from (persistence mechanisms)

Checked in rough order of how often real malware uses them:

| Mechanism | Location | Notes |
|---|---|---|
| User LaunchAgents | `~/Library/LaunchAgents/*.plist` | Most common malware persistence; runs at login as the user |
| System LaunchAgents | `/Library/LaunchAgents/` | Runs at login for every user; needs admin to install |
| LaunchDaemons | `/Library/LaunchDaemons/` | Runs as root at boot; highest impact |
| Login items / BTM | System Settings, `sfltool dumpbtm` | macOS 13+ registers all launch items here |
| Cron | `crontab -l`, `/usr/lib/cron/tabs/` | Old-school but still used |
| Shell startup files | `~/.zshrc`, `~/.zprofile`, `~/.bash_profile` | A single appended line re-infects on every terminal |
| Configuration profiles | `profiles list` | Can enforce settings and install payloads; check who installed them |
| Login/Logout hooks | `defaults read com.apple.loginwindow LoginHook` | Deprecated; almost always malicious if set |
| emond, StartupItems | `/etc/emond.d/rules`, `/Library/StartupItems` | Legacy; should be empty/Apple sample only |
| System extensions | `systemextensionsctl list` | Modern kext replacement; require user approval |

`/System/Library/LaunchDaemons` and `.../LaunchAgents` are SIP-protected Apple
territory — malware cannot normally write there, so don't audit them file by
file.

## Signals that an item is suspicious

Strong signals (any one warrants investigation):
- **Label mimicry**: a `com.apple.*` label in `/Library/` or `~/Library/`
  launch folders. Apple never installs there — this is a classic disguise.
- **Executable in a temp or shared path**: /tmp, /private/tmp, /var/tmp,
  /Users/Shared, ~/Downloads, or hidden dot-directories in $HOME.
- **Unsigned or ad-hoc-signed binary with RunAtLoad/KeepAlive**.
- **Download-and-execute arguments**: `curl ... | sh`, `base64 -d`, `osascript
  -e` with obfuscated strings, python one-liners with `exec`/`socket`.
- **Plist program path that no longer exists** (payload deleted itself or
  moved), or a plist owned by the wrong user.
- **Random-looking names**: `com.3fA9x.update.plist`, single-letter binaries.

Weak signals (common in legitimate software too — don't alarm the user):
- KeepAlive=true by itself (updaters and sync clients do this).
- Listening on localhost ports (dev tools, IDE helpers).
- High CPU (browsers, Spotlight `mds`, backups).

## Recognizing legitimate items

Name the vendor when clearing an item. Common benign third-party launch items:
Google (`com.google.keystone.*` — Chrome updater), Microsoft
(`com.microsoft.update.agent`, `com.microsoft.autoupdate.*`), Adobe
(`com.adobe.*`), Dropbox, Docker (`com.docker.*`), Zoom (`us.zoom.*`),
Spotify, 1Password, Logitech, corporate MDM/EDR agents (Jamf `com.jamf.*`,
CrowdStrike `com.crowdstrike.*`, SentinelOne). A valid Developer ID signature
whose Team ID matches the claimed vendor is the deciding evidence — verify
with `codesign -dvv` rather than trusting the filename.

## Verifying a specific binary

```bash
codesign -dvv /path/to/binary        # signer + Team ID
spctl -a -vv /path/to/binary         # Gatekeeper assessment
shasum -a 256 /path/to/binary        # hash for lookup (VirusTotal etc.)
xattr -p com.apple.quarantine /path  # where it was downloaded from
stat -f 'created %SB, modified %Sm' /path
```

An unsigned binary is not automatically malware (homebrew builds, personal
scripts), and a signed one is not automatically safe (revoked or stolen
certs) — combine signature, location, persistence behavior, and provenance.

## Safe remediation sequence

Never jump straight to deletion. The reversible order:

1. **Capture evidence first**: copy the plist and binary path, record the
   sha256 — needed if the user wants to report it or restore a false positive.
2. **Unload**: `launchctl bootout gui/$(id -u) <path.plist>` for user agents;
   `sudo launchctl bootout system <path.plist>` for daemons.
3. **Quarantine, don't delete**: `mkdir -p ~/quarantine && mv <plist> <binary>
   ~/quarantine/` — removes execution while staying reversible.
4. **Kill the running process** only after unloading (otherwise KeepAlive
   restarts it): `kill <pid>`.
5. **Verify after reboot** that it did not come back — if it does, a second
   persistence mechanism exists; re-scan everything.
6. **If real malware was confirmed**: recommend changing passwords from a
   different device, checking browser extensions and Safari/Chrome settings,
   reviewing `profiles list` for rogue configuration profiles, and considering
   a clean macOS reinstall for anything that ran as root.

Every remediation action must be explicitly confirmed by the user — the
scan/investigate flows themselves stay read-only.

## Ongoing monitoring posture

- Save a baseline when the machine is believed clean; diff it periodically
  (weekly, or after installing new software). New plists and changed hashes
  are the highest-value diff lines.
- Keep macOS built-ins on: SIP enabled, Gatekeeper enabled, XProtect current
  (comes with system updates), FileVault on, firewall on.
- Point users to System Settings → General → Login Items & Extensions to see
  Apple's own view of what launches at login (macOS 13+).
- For continuous real-time detection beyond periodic scans, suggest
  reputable tools rather than building one: Objective-See's free utilities
  (KnockKnock for persistence, BlockBlock for install-time alerts, LuLu
  firewall) complement this plugin's on-demand audits well.

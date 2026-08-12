# Mac Security Monitor

Defensive monitoring for your Mac from inside Claude Code: find out what is
running in the background, spot unauthorized scripts and programs, and catch
new persistence the moment it appears — with Claude interpreting the results
instead of leaving you a wall of terminal output.

Everything the plugin runs is **read-only**. Nothing is killed, unloaded, or
deleted unless you explicitly ask for it after reviewing the evidence.

## Commands

### `/mac-security-monitor:scan [section]`

Audits the machine and explains what it finds. Sections: `full` (default),
`persistence`, `processes`, `network`, `protection`.

Covered ground:
- **Persistence**: LaunchDaemons, LaunchAgents (system + user), login items
  and Background Task Management, cron, login/logout hooks, emond, legacy
  StartupItems, configuration profiles, and shell startup files
  (`.zshrc` etc.) scanned for download-and-execute patterns.
- **Processes**: non-Apple processes by CPU, anything running from /tmp,
  /Users/Shared or Downloads, executables parked in temp locations, and
  non-Apple kernel/system extensions.
- **Network**: listening ports and established connections mapped to
  processes.
- **Protection**: SIP, Gatekeeper, firewall, FileVault, and XProtect status.

Launchd jobs get per-item detail: label, program, arguments, RunAtLoad /
KeepAlive, file owner and modification time, and a code-signature check —
with `[!]` flags on unsigned binaries, suspicious paths, missing executables,
and shell/downloader invocations.

### `/mac-security-monitor:baseline [save|diff|show]`

Saves a snapshot of the persistence inventory (plist hashes, login items,
cron, extensions, listening ports, shell startup file hashes) to
`~/.mac-security-monitor/`, then diffs later runs against it. A new plist or
a changed hash stands out immediately, which is the fastest way to answer
"did anything install itself since last week?"

### `/mac-security-monitor:investigate <pid | path | label>`

Deep-dives one suspicious item: process details and open files/connections,
code signature and Team ID, Gatekeeper assessment, sha256 for reputation
lookup, quarantine provenance, and persistence behavior — ending in a
verdict with a stated confidence level.

## Suggested workflow

1. Run `/mac-security-monitor:scan` and review anything flagged.
2. Once the machine looks clean, `/mac-security-monitor:baseline save`.
3. Periodically (or after installing software) run
   `/mac-security-monitor:baseline diff` — a clean diff takes seconds to read.
4. Use `/mac-security-monitor:investigate` on anything you don't recognize.

## Notes and limits

- Some checks (root crontabs, `sudo sfltool dumpbtm`, all listening ports,
  system configuration profiles) need sudo; the scan tells you exactly which
  command to re-run when it matters.
- This is on-demand auditing, not a resident antivirus. macOS's built-in
  XProtect/Gatekeeper handle known-malware blocking; for real-time
  install alerts consider Objective-See's free BlockBlock and KnockKnock,
  which pair well with these scans.
- macOS 13+ (Ventura and later) gets the most complete results; earlier
  versions still work with reduced Background Task Management detail.

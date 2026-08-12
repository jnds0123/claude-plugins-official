---
description: Deep-dive a specific suspicious process, launch agent, or file on this Mac
argument-hint: "<pid | plist path | file path | label>"
allowed-tools: [Bash, Read, Grep, WebSearch]
---

# Investigate a Suspicious Item

The user wants a verdict on a specific item: $ARGUMENTS

Work through this read-only checklist, adapting to whether the item is a
process (PID or name), a launchd plist, or a file on disk. Use the
`mac-security-audit` skill for interpretation. Do not kill, unload, or delete
anything during the investigation.

## Checklist

1. **Identify the executable.**
   - PID → `ps -p <pid> -o pid,user,ppid,lstart,etime,command` and
     `lsof -p <pid> -nP | head -40` (open files + network connections).
   - Plist → read it (`plutil -p <path>`) and extract the Program /
     ProgramArguments; that path is the executable to judge.
   - Label → `launchctl list <label>` and find the matching plist under
     /Library/Launch{Agents,Daemons} or ~/Library/LaunchAgents.

2. **Judge the binary.**
   - `codesign -dvv <path> 2>&1` — signer identity and Team ID.
   - `spctl -a -vv <path> 2>&1` — does Gatekeeper accept it?
   - `shasum -a 256 <path>` — give the user the hash and offer to look it up.
     If WebSearch is available, search the hash and the file/label name for
     known malware reports or the legitimate vendor.
   - `stat -f 'created %SB, modified %Sm' <path>` and where it lives —
     /tmp, /Users/Shared, or Downloads is a red flag; a vendor's app bundle
     is reassuring.
   - `xattr -p com.apple.quarantine <path> 2>/dev/null` — shows what
     downloaded it, if anything.

3. **Judge the behavior.**
   - Is it set to persist (RunAtLoad/KeepAlive, login item, cron)?
   - Is it listening on a port or holding connections (`lsof -p <pid> -i`)?
   - Do its arguments contain download-and-execute patterns, base64 blobs,
     or references to /tmp paths?

4. **Deliver a verdict with confidence level:** legitimate (name the vendor),
   suspicious (say exactly what to verify next), or likely malicious (say
   which evidence points that way).

5. **Only if the user asks to remove it**, follow the remediation sequence in
   the `mac-security-audit` skill: unload first, quarantine the files rather
   than deleting, verify it stays gone after reboot, and recommend changing
   passwords if the item had access to sensitive data.

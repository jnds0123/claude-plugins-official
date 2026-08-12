---
description: Audit this Mac for unauthorized background programs, scripts, and persistence
argument-hint: "[persistence|processes|network|protection|full]"
allowed-tools: ["Bash(${CLAUDE_PLUGIN_ROOT}/scripts/scan.sh:*)"]
---

# Mac Security Scan

Run a read-only audit of this Mac and interpret the results for the user.

## Steps

1. Run the scan script (default section is `full` if the user gave no argument):

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/scan.sh" $ARGUMENTS
```

2. Interpret the output using the `mac-security-audit` skill. Do NOT just dump
   the raw output. For each section, separate findings into:
   - **Needs attention** — items marked `[!]` plus anything you recognize as
     suspicious (unsigned RunAtLoad jobs, programs in /tmp, `com.apple.*`
     labels in user LaunchAgents, shell one-liners that download and execute).
   - **Looks legitimate** — recognizable vendor software (browsers, updaters,
     Docker, Dropbox, corporate MDM agents, etc.). Name the vendor.
   - **Could not check** — items that need sudo or extra permissions; tell the
     user the exact command to run if they want full coverage.

3. For each item that needs attention, explain in plain language what it is,
   why it was flagged, and how confident you are. Never present a flag as a
   confirmed infection — these are leads to verify.

4. If something looks genuinely malicious, walk the user through verification
   first (check the code signature, look up the file hash, inspect the plist)
   before suggesting removal. Removal must always be the user's decision; use
   the remediation guidance in the `mac-security-audit` skill and prefer
   reversible steps (unload + quarantine the file) over deletion.

5. End with a one-paragraph verdict: overall risk picture and the single most
   important next step. If nothing is suspicious, say so clearly — no alarmism.

## Notes

- The script is read-only and safe to run repeatedly.
- Some sections show more when run with sudo; only suggest sudo re-runs for
  specific checks the user cares about, and show the exact command.
- If this is the user's first scan, suggest saving a baseline afterwards with
  `/mac-security-monitor:baseline save` so future scans can diff against it.

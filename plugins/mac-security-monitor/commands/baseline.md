---
description: Save a snapshot of this Mac's background items, or diff current state against it
argument-hint: "[save|diff|show]"
allowed-tools: ["Bash(${CLAUDE_PLUGIN_ROOT}/scripts/baseline.sh:*)"]
---

# Mac Security Baseline

Manage a known-good snapshot of this Mac's persistence inventory (launchd
plists with hashes, login items, cron, kernel/system extensions, listening
ports, shell startup file hashes) so that anything NEW stands out on later
checks.

## Steps

1. Run the baseline script with the user's argument (default `diff`):

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/baseline.sh" $ARGUMENTS
```

2. For `save`: confirm what was recorded and where (~/.mac-security-monitor/).
   Remind the user to only save a baseline when the machine is believed clean —
   ideally right after a full `/mac-security-monitor:scan` came back healthy.

3. For `diff`: interpret every change, using the `mac-security-audit` skill:
   - A **new launchd plist or changed plist hash** is the most important kind
     of change — identify what it is and whether it matches software the user
     recently installed. If the user doesn't recognize it, investigate it
     (signature, vendor, program path) before moving on.
   - New listening ports, new login items, or changed shell startup file
     hashes also deserve an explanation each.
   - Expected churn (an updater bumping its own plist version) should be
     called out as benign so the user isn't alarmed.

4. If the diff is clean, say so in one sentence. If there are changes the user
   confirms are legitimate (new software they installed), offer to re-save the
   baseline so future diffs stay quiet.

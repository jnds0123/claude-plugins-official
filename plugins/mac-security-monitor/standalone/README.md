# Mac Security Check — standalone install kit

A self-contained, **read-only** background-activity checker for macOS that runs
**without Claude Code**. It inspects the places unwanted software hides (startup
items, launch agents/daemons, login items, cron, running processes, network
listeners, and your built-in defenses), decides for itself what looks normal vs.
what deserves a look, and produces a plain-language, color-coded HTML report.

It never changes, deletes, or kills anything. It only reads.

There are two audiences for this folder:

- **End users** just run the tool (see *For end users*).
- **You, the distributor**, build a signed installer once with your Apple
  Developer ID (see *For the distributor*).

---

## For end users

Once you've installed the `.pkg` your distributor gave you, there's **nothing to
run and nothing to remember**. The monitor checks your Mac automatically:

- once right after install,
- every time you log in,
- and weekly.

It stays completely silent unless it finds something worth a look — then it
shows a notification and drops a **report on your Desktop** titled
`Mac-Security-ALERT-…`. Double-click that file to read it in your browser.

**Reading the report — the colors:**
- 🟢 **Green** — confirmed fine, nothing to do.
- 🟡 **Amber** — couldn't auto-confirm it. Usually harmless; if you recognize
  the name, you're set.
- 🔴 **Red** — look at this closely. A red flag is a *lead, not a verdict* —
  don't delete anything on a hunch. If unsure, ask someone technical or search
  the exact name shown.

**Permission prompts:** the first time it runs you may see macOS ask to allow
notifications or to control "System Events." Click **Allow** / **OK** so it can
check login items and alert you.

**To run a check yourself any time:** open
`~/Library/Application Support/MacSecurityCheck/`, or ask your distributor for
the double-click `mac-security-check.command`. It opens a full report every time.

**To uninstall:** double-click `uninstall.command` (from this kit). It asks for
your password once and removes the monitor; your saved reports are kept.

---

## For the distributor (building the signed installer)

You have an Apple Developer account, so users get a clean double-click install
with **no Gatekeeper warnings**. That requires code-signing and notarization —
`build-and-sign.sh` does all of it.

### One-time setup

1. Install both certificates (same team) into your login keychain:
   - `Developer ID Application: YOUR NAME (TEAMID)`
   - `Developer ID Installer:   YOUR NAME (TEAMID)`

   Confirm with:
   ```bash
   security find-identity -v
   ```

2. Store a notarization credential once (uses an app-specific password from
   [appleid.apple.com](https://appleid.apple.com) → Sign-In and Security):
   ```bash
   xcrun notarytool store-credentials "MSC_NOTARY" \
       --apple-id "you@example.com" \
       --team-id  "TEAMID" \
       --password "xxxx-xxxx-xxxx-xxxx"
   ```

### Build

```bash
cd plugins/mac-security-monitor/standalone
TEAM_ID=YOURTEAMID ./build-and-sign.sh
```

Useful overrides:

| Variable | Default | Purpose |
|---|---|---|
| `VERSION` | `1.0.0` | Installer version |
| `BUNDLE_ID` | `com.jnds0123.mac-security-check` | Identifier / LaunchAgent label — use your own reverse-domain id |
| `INSTALLER_IDENTITY` | auto-detected | Full `Developer ID Installer: …` string if you have more than one |
| `NOTARY_PROFILE` | `MSC_NOTARY` | The notarytool profile name from setup step 2 |
| `SKIP_NOTARIZE` | `0` | Set `1` to build+sign without notarizing (local testing only) |

The result is `dist/MacSecurityCheck-<version>.pkg` — signed, notarized, and
stapled. Hand that single file to your users.

> If you change `BUNDLE_ID`, update it in `resources/uninstall.command` too so
> uninstall targets the same LaunchAgent.

### What the installer places on each Mac

| Path | What |
|---|---|
| `/Library/Application Support/MacSecurityCheck/mac-security-check` | the read-only check engine |
| `/Library/LaunchAgents/<BUNDLE_ID>.plist` | schedule: at login + weekly, quiet mode |
| `~/Library/Application Support/MacSecurityCheck/reports/` | archived reports (last 12 kept) |

### What it deliberately does NOT do

- No kernel extension, no always-on interception — this is periodic auditing,
  not a resident antivirus. It complements macOS's built-in XProtect/Gatekeeper
  rather than replacing them.
- No network calls, no telemetry. Everything stays on the user's Mac.
- No changes to the system. Every check is read-only; remediation is left to a
  human who has reviewed the report.

---

## Files in this kit

```
standalone/
├── mac-security-check.command      # the check engine (interactive + --quiet)
├── build-and-sign.sh               # builds the signed, notarized .pkg
├── resources/
│   ├── LaunchAgent.plist.template  # schedule template (bundle id substituted)
│   ├── postinstall                 # pkg script that loads the agent
│   └── uninstall.command           # double-click uninstaller
└── README.md
```

# Central reporting to IT — Power Automate relay (no secret on the Macs)

This is the secure way to get findings to IT. Each Mac POSTs a JSON summary
(plus the full HTML report, base64-encoded) to a **Power Automate flow URL**.
The flow — running in your Microsoft 365 tenant — sends the email from your own
mailbox. **No email credential is stored on any Mac.** If the flow URL leaks,
the worst anyone can do is submit bogus reports (rate-limited, rotatable) — they
cannot send mail as your domain.

## What each Mac sends

`POST` with `Content-Type: application/json` and an optional `X-Report-Token`
header. Body shape:

```json
{
  "tool": "Nourison Home Mac Endpoint Security",
  "company": "Nourison Home",
  "computer": "Mike's MacBook Pro",
  "user": "j.mallari",
  "os": "15.5",
  "timestamp": "2026-08-12 10:00:00",
  "overall": "attention",
  "counts": { "attention": 2, "review": 4, "ok": 8 },
  "findings": [
    { "level": "warn", "title": "com.apple.softwareupdate",
      "detail": "File: /Library/LaunchDaemons/...  Program: /Users/Shared/.hidden/updater",
      "why": "Named like Apple software but Apple does not install here; runs from a shared folder." }
  ],
  "text": "Nourison Home Security — Mike's MacBook (j.mallari): 2 need attention, 4 to review [attention]",
  "report_html_b64": "PGh0bWw+ ... (full report, base64) ... "
}
```

By default a Mac only reports when it finds a needs-attention item. Build with
`REPORT_ALWAYS=1` to also report clean/heartbeat runs (uses more flow runs).

## Build the Power Automate flow

1. Go to **make.powerautomate.com** → **+ Create** → **Instant cloud flow** →
   **Skip** (don't pick a trigger yet).
2. Search the trigger **"When a HTTP request is received"** (Request connector)
   and add it.
   > Note: this trigger is a *premium* connector. Most M365 tenants have it; if
   > yours doesn't, use an **Azure Logic App** (same trigger, consumption plan)
   > or the Google Apps Script / Cloudflare Worker relay instead — ask and I'll
   > provide those.
3. In the trigger, click **"Use sample payload to generate schema"** and paste
   the JSON above (a short `report_html_b64` value is fine for the sample).
   Click **Done**.
4. **(Optional but recommended) token check.** Add a **Condition**:
   - Left value (expression): `triggerOutputs()?['headers']?['X-Report-Token']`
   - is equal to → your chosen token string (e.g. a long random value).
   - In the **If no** branch, add **Terminate** (status: Cancelled). Put the rest
     of the flow in **If yes**.
5. Add action **"Send an email (V2)"** (Office 365 Outlook):
   - **To:** `itsupport@nourison.com`
   - **Subject:** `[Nourison Security] ` then the dynamic `text` field
     (expression: `triggerBody()?['text']`).
   - **Body** (switch to code view `</>` and use these expressions):
     ```
     A security check flagged items on @{triggerBody()?['computer']} (user @{triggerBody()?['user']}, macOS @{triggerBody()?['os']}).
     Overall: @{triggerBody()?['overall']}.
     Needs attention: @{triggerBody()?['counts']?['attention']} | Review: @{triggerBody()?['counts']?['review']}.
     Checked: @{triggerBody()?['timestamp']}.
     See the attached report for full details.
     ```
   - **Advanced options → Attachments:**
     - **Attachments Name – 1:** `Mac-Security-Report.html`
     - **Attachments Content – 1** (expression): `base64ToBinary(triggerBody()?['report_html_b64'])`
6. **Save.** Re-open the trigger — it now shows the **HTTP POST URL**. Copy it.

## Point the Macs at the flow

Rebuild the installer with the flow URL (and token if you added one). No SMTP
values — the credential stays in your tenant.

```bash
COMPANY="Nourison Home" \
TEAM_ID=ZMR8Z89RC8 \
REPORT_WEBHOOK="https://prod-XX.westus.logic.azure.com:443/workflows/....&sig=...." \
REPORT_TOKEN="a-long-random-string-you-also-put-in-the-flow" \
./build-and-sign.sh
```

For a first test, add `REPORT_ALWAYS=1` so a clean Mac still reports and you can
confirm the email arrives; drop it for production so IT is emailed only on
findings.

## Notes

- The flow URL itself is the primary credential; the optional `X-Report-Token`
  adds a second check so random hits on the URL are rejected. Both live on the
  endpoint, but neither can send mail as your domain — that authority stays in
  the flow.
- Rotate the flow URL (regenerate the trigger) or the token if you suspect leak.
- Power Automate has per-plan run limits; reporting only on findings keeps usage
  low. Watch the flow's run history for volume.

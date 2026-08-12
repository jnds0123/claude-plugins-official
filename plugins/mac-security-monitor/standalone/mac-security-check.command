#!/bin/bash
#
#  Mac Security Check  —  standalone, read-only background-activity checker
#  ---------------------------------------------------------------------------
#  Double-click this file. It looks at what starts up and runs in the
#  background on your Mac, decides what looks normal vs. what deserves a
#  look, and writes an easy-to-read report to your Desktop, then opens it.
#
#  It ONLY READS. It never changes, deletes, quarantines, or kills anything.
#  It needs no installation and no download of extra tools.
#
#  Safe to run as often as you like.
#
set -u

# ---------------------------------------------------------------------------
# 0. Basics: mode, macOS check, and paths.
#    --quiet  : background/scheduled run. Stays silent unless something needs
#               attention, in which case it notifies and opens the report.
#    (default): interactive run. Writes the report to the Desktop and opens it.
# ---------------------------------------------------------------------------
QUIET=0
[ "${1:-}" = "--quiet" ] && QUIET=1

# Clear our own quarantine flag so re-runs don't nag. (Harmless if unset.)
xattr -d com.apple.quarantine "$0" >/dev/null 2>&1 || true

if [ "$(uname)" != "Darwin" ]; then
  echo "This tool is for macOS only."
  exit 1
fi

COMPUTER=$(scutil --get ComputerName 2>/dev/null || hostname)
NOW=$(date '+%Y-%m-%d %H:%M:%S')
STAMP=$(date '+%Y%m%d-%H%M%S')

# Archive every report quietly under the user's Library; surface it on the
# Desktop only when it's an interactive run or there's something to see.
ARCHIVE="$HOME/Library/Application Support/MacSecurityCheck/reports"
mkdir -p "$ARCHIVE" 2>/dev/null || true
if [ "$QUIET" -eq 1 ]; then
  REPORT="$ARCHIVE/Mac-Security-Report-$STAMP.html"
else
  OUTDIR="$HOME/Desktop"; [ -w "$OUTDIR" ] || OUTDIR="$HOME"
  REPORT="$OUTDIR/Mac-Security-Report-$STAMP.html"
fi

# Counters that drive the overall verdict.
WARN=0      # strong signals — look at these
REVIEW=0    # worth a glance
OKN=0       # things confirmed fine
CARDS=""    # accumulated HTML
FINDINGS_JSON=""              # structured warn/review findings for IT reporting
OSVER="$(sw_vers -productVersion 2>/dev/null || echo '?')"
WHO="$(id -un 2>/dev/null || echo user)"

# Optional site configuration written by the installer: COMPANY (branding shown
# in alerts) and WEBHOOK_URL (where to POST findings for central IT visibility).
# Absent on a plain double-click run, so reporting simply stays off.
COMPANY="Mac Security Check"
WEBHOOK_URL=""                    # optional: POST compact JSON summary every run
SMTP_HOST=""                      # e.g. smtp.mailgun.org
SMTP_PORT="587"                   # 587 = STARTTLS, 465 = implicit SSL
SMTP_USER=""                      # SMTP login (e.g. postmaster@mg.yourcompany.com)
SMTP_PASS=""                      # SMTP password (see security note in README)
SMTP_FROM=""                      # From: header, e.g. "Company Security <security@mg.yourcompany.com>"
REPORT_EMAIL=""                   # IT recipient, e.g. it-security@yourcompany.com
REPORT_ALWAYS=0                   # 1 = report every run (inventory); 0 = only on findings
REPORT_TOKEN=""                   # optional shared secret sent as X-Report-Token header
CONFIG="/Library/Application Support/MacSecurityCheck/config.sh"
[ -f "$CONFIG" ] && . "$CONFIG"

say() { [ "$QUIET" -eq 1 ] || echo "$1"; }

say ""
say "  Mac Security Check"
say "  Looking at startup items, background processes, and settings..."
say "  (This only reads. Nothing on your Mac is changed.)"
say ""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# HTML-escape a string.
esc() {
  local s="$1"
  s=${s//&/&amp;}
  s=${s//</&lt;}
  s=${s//>/&gt;}
  printf '%s' "$s"
}

# JSON-escape a string (for the IT reporting payload).
json_esc() {
  local s="$1"
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/ }
  s=${s//$'\r'/ }
  s=${s//$'\t'/ }
  printf '%s' "$s"
}

# add_card LEVEL "Title" "What it is" "Why / what to do"
#   LEVEL = warn | review | ok
add_card() {
  local level="$1" title="$2" what="$3" why="$4"
  case "$level" in
    warn)   WARN=$((WARN+1));   local badge="NEEDS ATTENTION"; local cls="warn" ;;
    review) REVIEW=$((REVIEW+1)); local badge="WORTH A LOOK";    local cls="review" ;;
    *)      OKN=$((OKN+1));      local badge="LOOKS FINE";       local cls="ok" ;;
  esac
  CARDS="$CARDS
  <div class=\"card $cls\">
    <div class=\"badge $cls\">$badge</div>
    <div class=\"card-title\">$(esc "$title")</div>
    <div class=\"card-what\">$(esc "$what")</div>
    <div class=\"card-why\">$(esc "$why")</div>
  </div>"
  # Record warn/review items as structured data for central IT reporting.
  if [ "$level" = "warn" ] || [ "$level" = "review" ]; then
    local sep=""; [ -n "$FINDINGS_JSON" ] && sep=","
    FINDINGS_JSON="$FINDINGS_JSON$sep{\"level\":\"$level\",\"title\":\"$(json_esc "$title")\",\"detail\":\"$(json_esc "$what")\",\"why\":\"$(json_esc "$why")\"}"
  fi
}

section() {
  CARDS="$CARDS
  <h2>$(esc "$1")</h2>
  <p class=\"section-note\">$(esc "$2")</p>"
}

# Known-legitimate vendor fingerprints (label or path fragments). Not
# exhaustive — a match means "almost certainly fine"; a non-match just means
# "we couldn't auto-confirm it," NOT "bad."
is_known_vendor() {
  echo "$1" | grep -qiE '(com\.apple\.|com\.google\.|keystone|com\.microsoft\.|com\.adobe\.|dropbox|com\.docker\.|us\.zoom\.|com\.spotify\.|1password|com\.agilebits|com\.logi|logitech|com\.parallels|com\.amazon|slack|webex|com\.teamviewer|com\.citrix|com\.vmware|com\.cisco|umbrella|com\.zscaler|zscaler|netskope|okta|com\.jamf|jamf|com\.crowdstrike|falcon|sentinelone|com\.fortinet|forticlient|fortimonitor|com\.microsoft\.wdav|defender|com\.kandji|kandji|mosyle|addigy|nomad|/Applications/)'
}

# Judge a launchd plist. Emits a card.
judge_plist() {
  local plist="$1" area="$2"
  local label program args exe runatload
  label=$(/usr/bin/plutil -extract Label raw "$plist" 2>/dev/null || echo "?")
  program=$(/usr/bin/plutil -extract Program raw "$plist" 2>/dev/null || true)
  args=$(/usr/bin/plutil -extract ProgramArguments.0 raw "$plist" 2>/dev/null || true)
  runatload=$(/usr/bin/plutil -extract RunAtLoad raw "$plist" 2>/dev/null || echo "false")
  exe="$program"; [ -z "$exe" ] && exe="$args"

  local reasons="" level="ok"

  # Strong signal: an Apple-looking name living where Apple never installs.
  if echo "$label" | grep -qi '^com\.apple\.' && echo "$plist" | grep -qvi '/System/'; then
    level="warn"
    reasons="It is named like Apple software (\"$label\") but Apple does not install items here. Malware often copies Apple's naming to hide. "
  fi

  # Executable missing from disk.
  if [ -n "$exe" ] && [ ! -e "$exe" ]; then
    level="warn"
    reasons="$reasons The program it points to ($exe) is not on disk — it may have moved or removed itself. "
  fi

  # Runs from a temporary/shared location.
  if echo "$exe" | grep -qE '^/(private/)?(tmp|var/tmp)/|^/Users/Shared/|/Downloads/'; then
    level="warn"
    reasons="$reasons It runs a program from a temporary or shared folder ($exe), which trustworthy software does not do. "
  fi

  # Unsigned binary that auto-runs.
  if [ -n "$exe" ] && [ -e "$exe" ]; then
    if ! /usr/bin/codesign -v "$exe" >/dev/null 2>&1; then
      if [ "$runatload" = "true" ] || [ "$runatload" = "1" ]; then
        [ "$level" = "ok" ] && level="review"
        reasons="$reasons Its program is not digitally signed and it is set to run automatically. Homemade scripts look like this too, so check whether you recognize it. "
      fi
    fi
  fi

  # Shell / downloader invocation.
  local fullargs
  fullargs=$(/usr/bin/plutil -extract ProgramArguments json -o - "$plist" 2>/dev/null || echo "$args")
  if echo "$fullargs" | grep -qiE '(curl|wget|base64|osascript|/bin/sh|/bin/bash|python).*(http|-c|-e|decode)'; then
    level="warn"
    reasons="$reasons It launches a script or downloads-and-runs code — a common way unwanted software hides. Review the exact command below. "
  fi

  # If nothing tripped, try to reassure by naming the vendor.
  if [ "$level" = "ok" ]; then
    if is_known_vendor "$label $exe"; then
      reasons="Matches known, legitimate software. No action needed."
    else
      level="review"
      reasons="We could not automatically match this to a known vendor. That does NOT mean it is bad — if you recognize the name below, it is almost certainly something you installed."
    fi
  fi

  local title="$label"
  [ "$title" = "?" ] && title="(unnamed startup item)"
  add_card "$level" "$title  [$area]" \
    "File: $plist${exe:+  |  Program: $exe}  |  Auto-runs: $runatload" \
    "$reasons"
}

scan_dir() {
  local dir="$1" area="$2"
  [ -d "$dir" ] || return
  local any=0
  for p in "$dir"/*.plist; do
    [ -e "$p" ] || continue
    any=1
    judge_plist "$p" "$area"
  done
  return 0
}

# ---------------------------------------------------------------------------
# 1. Built-in protection status
# ---------------------------------------------------------------------------
section "Your Mac's built-in defenses" \
  "These are Apple's own protections. You want them all ON. If any say OFF, turning them on is the single most valuable thing you can do."

sip=$(csrutil status 2>/dev/null | grep -qi enabled && echo on || echo off)
[ "$sip" = "on" ] \
  && add_card ok "System Integrity Protection (SIP)" "Apple's core tamper protection." "On. Good — leave it on." \
  || add_card warn "System Integrity Protection (SIP)" "Apple's core tamper protection." "It appears OFF. This is unusual and lowers your protection. Turn it back on unless a technician told you otherwise."

gk=$(spctl --status 2>/dev/null)
echo "$gk" | grep -qi 'assessments enabled' \
  && add_card ok "Gatekeeper" "Blocks unverified apps from opening." "On. Good." \
  || add_card warn "Gatekeeper" "Blocks unverified apps from opening." "It appears OFF, so unverified apps can open freely. Turn it on: System Settings > Privacy & Security."

fw=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
echo "$fw" | grep -qi 'enabled' \
  && add_card ok "Firewall" "Controls incoming network connections." "On. Good." \
  || add_card review "Firewall" "Controls incoming network connections." "It appears off. Turn it on: System Settings > Network > Firewall."

fv=$(fdesetup status 2>/dev/null)
echo "$fv" | grep -qi 'On' \
  && add_card ok "FileVault disk encryption" "Encrypts your disk so a lost/stolen Mac's data can't be read." "On. Good." \
  || add_card review "FileVault disk encryption" "Encrypts your disk so a lost/stolen Mac's data can't be read." "It appears off. Turn it on: System Settings > Privacy & Security > FileVault."

osv=$(sw_vers -productVersion 2>/dev/null)
autoupd=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null || echo "?")
if [ "$autoupd" = "1" ]; then
  add_card ok "Automatic updates (macOS $osv)" "Apple ships malware-blocking definitions inside system updates." "Automatic checking is on. Good — keep installing updates when offered."
else
  add_card review "Automatic updates (macOS $osv)" "Apple ships malware-blocking definitions inside system updates." "Automatic checking may be off. Turn it on: System Settings > General > Software Update > (i)."
fi

# ---------------------------------------------------------------------------
# 2. Things that start automatically (the main event)
# ---------------------------------------------------------------------------
section "Programs that start automatically in the background" \
  "This is where unwanted software usually hides so it runs every time you turn on your Mac. Each item below is judged for you."

scan_dir "/Library/LaunchDaemons" "system, runs as admin"
scan_dir "/Library/LaunchAgents" "system, at login"
scan_dir "$HOME/Library/LaunchAgents" "your account, at login"

# Login items
LI=$(osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null)
if [ -n "$LI" ]; then
  add_card review "Login items: $LI" "Apps set to open when you log in." "Look at the list. Anything you don't recognize can be removed in System Settings > General > Login Items & Extensions."
else
  add_card ok "Login items" "Apps set to open when you log in." "None found, or none that needed flagging."
fi

# Old-school persistence that should normally be empty
if defaults read com.apple.loginwindow LoginHook >/dev/null 2>&1; then
  add_card warn "Login hook is set" "An old mechanism that runs a script at every login." "This is rarely used by legitimate software today. Note what it points to and have it reviewed."
fi
CRON=$(crontab -l 2>/dev/null | grep -vE '^\s*#' | grep -c . )
if [ "${CRON:-0}" -gt 0 ]; then
  add_card review "Scheduled jobs (cron) found" "Timed background tasks scheduled under your account." "There are $CRON scheduled task line(s). If you didn't set up any scheduled scripts, have these reviewed."
fi

# Shell startup files with download-and-run patterns
for f in "$HOME/.zshrc" "$HOME/.zprofile" "$HOME/.bash_profile" "$HOME/.bashrc" "$HOME/.profile"; do
  [ -f "$f" ] || continue
  if grep -qEi '(curl|wget).*\|.*(sh|bash)|base64 (-d|--decode)|eval \$\(' "$f" 2>/dev/null; then
    add_card warn "Suspicious line in $f" "A hidden startup file for the Terminal." "It contains a command that downloads and runs code every time a Terminal opens — a common re-infection trick. Have this file reviewed."
  fi
done

# ---------------------------------------------------------------------------
# 3. Programs running from unusual places right now
# ---------------------------------------------------------------------------
section "Programs running right now from unusual places" \
  "Trustworthy software runs from your Applications folder or the system, never from temporary or shared folders."

SUSP=$(ps axo pid,comm | awk '$2 ~ /^\/(private\/)?(tmp|var\/tmp)\// || $2 ~ /^\/Users\/Shared\// || $2 ~ /\/Downloads\//' )
if [ -n "$SUSP" ]; then
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    add_card warn "Running from a suspicious location" "$line" "A program is running out of a temporary or shared folder. This is unusual and worth investigating."
  done <<< "$SUSP"
else
  add_card ok "Running programs" "Active background programs." "Nothing is running from a temporary or shared folder. Good."
fi

# ---------------------------------------------------------------------------
# 4. Network listeners (light touch)
# ---------------------------------------------------------------------------
section "Programs waiting for network connections" \
  "Some legitimate apps listen on the network (file sharing, dev tools). Unknown ones that listen can be a way in."
LISTEN=$(lsof -iTCP -sTCP:LISTEN -nP 2>/dev/null | awk 'NR>1 {print $1}' | sort -u | grep -viE '^(rapportd|ControlCe|sharingd|remoted|nsurlsess|apsd|launchd)$')
if [ -n "$LISTEN" ]; then
  namelist=$(echo "$LISTEN" | paste -sd ', ' -)
  add_card review "Apps listening on the network" "$namelist" "If you recognize these (e.g. Dropbox, a work app), fine. If a name looks random or unfamiliar, investigate it. (Some system listeners aren't shown without admin rights.)"
else
  add_card ok "Network listeners" "Programs accepting incoming connections." "Nothing unusual visible."
fi

# ---------------------------------------------------------------------------
# Build the report
# ---------------------------------------------------------------------------
if   [ "$WARN"   -gt 0 ]; then OVERALL="attention"; HEAD="Some items need your attention"; SUB="We found $WARN item(s) worth looking at closely and $REVIEW to glance over. This does not confirm an infection — these are leads to check."
elif [ "$REVIEW" -gt 0 ]; then OVERALL="review";    HEAD="Looks mostly fine — a few things to glance at"; SUB="Nothing alarming. $REVIEW item(s) are just things we couldn't auto-confirm. If you recognize them, you're all set."
else                          OVERALL="clean";     HEAD="Looks clean"; SUB="Nothing suspicious found in the places checked. Keep your Mac updated and run this again now and then."
fi

cat > "$REPORT" <<HTMLHEAD
<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mac Security Report</title>
<style>
  *{box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;background:#f5f6f8;color:#1d1d1f;line-height:1.5}
  .wrap{max-width:820px;margin:0 auto;padding:24px}
  .hero{border-radius:16px;padding:28px;color:#fff;margin-bottom:8px}
  .hero.clean{background:#1f9d55}.hero.review{background:#c98a00}.hero.attention{background:#c0392b}
  .hero h1{margin:0 0 6px;font-size:26px}.hero p{margin:0;opacity:.95}
  .meta{color:#6b7280;font-size:13px;margin:10px 2px 22px}
  h2{font-size:18px;margin:30px 0 4px}
  .section-note{color:#6b7280;margin:0 0 12px;font-size:14px}
  .card{background:#fff;border-radius:12px;padding:14px 16px;margin:10px 0;border-left:5px solid #ccc;box-shadow:0 1px 2px rgba(0,0,0,.05)}
  .card.ok{border-left-color:#1f9d55}.card.review{border-left-color:#c98a00}.card.warn{border-left-color:#c0392b}
  .badge{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;margin-bottom:6px}
  .badge.ok{background:#1f9d55}.badge.review{background:#c98a00}.badge.warn{background:#c0392b}
  .card-title{font-weight:600;font-size:15px}
  .card-what{color:#374151;font-size:13px;font-family:ui-monospace,Menlo,monospace;word-break:break-all;margin:4px 0}
  .card-why{color:#1d1d1f;font-size:14px;margin-top:6px}
  .foot{color:#6b7280;font-size:13px;margin:30px 0 10px;border-top:1px solid #e5e7eb;padding-top:16px}
  @media (prefers-color-scheme: dark){
    body{background:#111;color:#eee}.card{background:#1c1c1e;box-shadow:none}
    .card-why{color:#eee}.card-what{color:#bbb}.meta,.section-note,.foot{color:#9aa0a6}
  }
</style></head><body><div class="wrap">
<div class="hero $OVERALL"><h1>$(esc "$HEAD")</h1><p>$(esc "$SUB")</p></div>
<div class="meta">Computer: $(esc "$COMPUTER") &nbsp;•&nbsp; Checked: $NOW &nbsp;•&nbsp; This report only read your Mac; nothing was changed.</div>
HTMLHEAD

printf '%s\n' "$CARDS" >> "$REPORT"

cat >> "$REPORT" <<HTMLFOOT
<div class="foot">
<b>What the colors mean:</b> <span style="color:#c0392b">Red = look at this closely</span>,
<span style="color:#c98a00">Amber = we couldn't auto-confirm it (often harmless)</span>,
<span style="color:#1f9d55">Green = confirmed fine</span>.<br><br>
A red flag is a <b>lead, not a verdict</b> — recognizable software you installed can still show amber, and nothing here should be deleted on a hunch.
If you're unsure about a red item, ask someone technical, or search the exact name shown.
Some deeper checks need administrator rights and were skipped in this quick run.<br><br>
This tool is read-only and made no changes. Run it again any time.
</div>
</div></body></html>
HTMLFOOT

# Keep the archive tidy: retain only the 12 most recent stored reports.
ls -1t "$ARCHIVE"/Mac-Security-Report-*.html 2>/dev/null | tail -n +13 | while read -r old; do rm -f "$old"; done

# ---------------------------------------------------------------------------
# Central reporting to IT (only if configured by the installer's config.sh).
# Sends a compact summary of flagged software — never personal file content.
# ---------------------------------------------------------------------------
summary_line="$COMPANY Security — $COMPUTER ($WHO): $WARN need attention, $REVIEW to review [$OVERALL]"

# (a) Optional JSON webhook — e.g. a Power Automate / relay endpoint that emails
#     IT. Sent when something needs attention (or every run if REPORT_ALWAYS=1).
#     Includes the full HTML report (base64) so the relay can attach it.
#     No email credential lives on the Mac — only this endpoint URL.
if [ -n "$WEBHOOK_URL" ] && { [ "$WARN" -gt 0 ] || [ "$REPORT_ALWAYS" = "1" ]; }; then
  html_b64=$(base64 < "$REPORT" 2>/dev/null | tr -d '\n')
  PAYLOAD=$(mktemp 2>/dev/null || echo "/tmp/msc-payload.$$")
  cat > "$PAYLOAD" <<JSON
{"tool":"$(json_esc "$COMPANY") Mac Endpoint Security","company":"$(json_esc "$COMPANY")","token":"$(json_esc "$REPORT_TOKEN")","computer":"$(json_esc "$COMPUTER")","user":"$(json_esc "$WHO")","os":"$(json_esc "$OSVER")","timestamp":"$(json_esc "$NOW")","overall":"$OVERALL","counts":{"attention":$WARN,"review":$REVIEW,"ok":$OKN},"findings":[$FINDINGS_JSON],"text":"$(json_esc "$summary_line")","report_html_b64":"$html_b64"}
JSON
  if [ -n "$REPORT_TOKEN" ]; then
    curl -sS -m 30 -X POST -H 'Content-Type: application/json' -H "X-Report-Token: $REPORT_TOKEN" --data @"$PAYLOAD" "$WEBHOOK_URL" >/dev/null 2>&1 || true
  else
    curl -sS -m 30 -X POST -H 'Content-Type: application/json' --data @"$PAYLOAD" "$WEBHOOK_URL" >/dev/null 2>&1 || true
  fi
  rm -f "$PAYLOAD" 2>/dev/null || true
fi

# (b) Optional email with the full HTML report attached, via SMTP (Mailgun,
#     Microsoft 365, Gmail, etc.). Sent when something needs attention, or
#     every run if REPORT_ALWAYS=1.
if [ -n "$SMTP_HOST" ] && [ -n "$SMTP_USER" ] && [ -n "$SMTP_PASS" ] && [ -n "$REPORT_EMAIL" ]; then
  if [ "$WARN" -gt 0 ] || [ "$REPORT_ALWAYS" = "1" ]; then
    if [ "$WARN" -gt 0 ]; then subj="[$COMPANY Security] ACTION: $WARN item(s) need attention on $COMPUTER ($WHO)"
    else                       subj="[$COMPANY Security] Check OK on $COMPUTER ($WHO) — $REVIEW to review"; fi
    from="${SMTP_FROM:-$SMTP_USER}"
    bnd="MSC${STAMP}$$"
    findings_txt=$(printf '%s' "$FINDINGS_JSON" | sed 's/},{/}\
{/g')
    RAW=$(mktemp 2>/dev/null || echo "/tmp/msc-raw.$$")
    EML=$(mktemp 2>/dev/null || echo "/tmp/msc-eml.$$")
    {
      echo "From: $from"
      echo "To: $REPORT_EMAIL"
      echo "Subject: $subj"
      echo "MIME-Version: 1.0"
      echo "Content-Type: multipart/mixed; boundary=\"$bnd\""
      echo
      echo "--$bnd"
      echo "Content-Type: text/plain; charset=\"utf-8\""
      echo
      echo "$summary_line"
      echo
      echo "Automated message from $COMPANY Mac Endpoint Security. Full report attached."
      echo
      echo "Flagged items:"
      echo "$findings_txt"
      echo
      echo "--$bnd"
      echo "Content-Type: text/html; charset=\"utf-8\"; name=\"Mac-Security-Report.html\""
      echo "Content-Transfer-Encoding: base64"
      echo "Content-Disposition: attachment; filename=\"Mac-Security-Report.html\""
      echo
      base64 < "$REPORT"
      echo "--$bnd--"
    } > "$RAW"
    # SMTP wants CRLF line endings.
    awk '{ printf "%s\r\n", $0 }' "$RAW" > "$EML"
    url="smtp://$SMTP_HOST:$SMTP_PORT"
    [ "$SMTP_PORT" = "465" ] && url="smtps://$SMTP_HOST:465"
    curl -s -m 40 --ssl-reqd --url "$url" \
      --user "$SMTP_USER:$SMTP_PASS" \
      --mail-from "$SMTP_USER" \
      --mail-rcpt "$REPORT_EMAIL" \
      --upload-file "$EML" >/dev/null 2>&1 || true
    rm -f "$RAW" "$EML" 2>/dev/null || true
  fi
fi

# ---------------------------------------------------------------------------
# Done. Behavior depends on mode.
# ---------------------------------------------------------------------------
if [ "$QUIET" -eq 1 ]; then
  # Background run: stay silent unless something needs attention.
  if [ "$WARN" -gt 0 ]; then
    # Surface a copy on the Desktop and open it.
    DESKTOP="$HOME/Desktop"; [ -w "$DESKTOP" ] || DESKTOP="$HOME"
    ALERT="$DESKTOP/Mac-Security-ALERT-$STAMP.html"
    cp "$REPORT" "$ALERT" 2>/dev/null && REPORT="$ALERT"
    open "$REPORT" >/dev/null 2>&1 || true
    # Unmissable modal alert the user must click to dismiss.
    amsg="$COMPANY Endpoint Security found $WARN item(s) on this Mac that need attention"
    [ "$REVIEW" -gt 0 ] && amsg="$amsg (and $REVIEW more to review)"
    amsg="$amsg. A detailed report has opened and was saved to your Desktop. Please review it and contact the IT Department if you did not expect this."
    osascript -e "display dialog \"$amsg\" with title \"$COMPANY — Security Alert\" buttons {\"View Report\"} default button \"View Report\" with icon caution" >/dev/null 2>&1 || true
    open "$REPORT" >/dev/null 2>&1 || true
  fi
  # Clean or review-only weeks: no user interruption; report stays archived
  # quietly (and IT still gets the webhook/email per the config above).
  exit 0
fi

# Interactive run: always show and open.
echo "  ------------------------------------------------------------"
echo "  Result: $HEAD"
echo "  Needs attention: $WARN   Worth a look: $REVIEW   Confirmed fine: $OKN"
echo ""
echo "  Report saved to:"
echo "    $REPORT"
echo "  Opening it now..."
echo "  ------------------------------------------------------------"
open "$REPORT" 2>/dev/null || echo "  (Open the file above manually if it didn't pop up.)"
echo ""
echo "  You can close this window."

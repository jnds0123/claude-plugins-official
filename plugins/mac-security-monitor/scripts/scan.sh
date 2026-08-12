#!/bin/bash
# mac-security-monitor: read-only audit of macOS background activity and
# persistence locations. Prints findings for Claude to interpret.
#
# Usage: scan.sh [persistence|processes|network|protection|full]
#
# This script only READS system state. It never modifies, kills, or deletes
# anything. Some checks show more detail when run with sudo; the script
# notes where that applies rather than requiring it.

set -u

SECTION="${1:-full}"

if [[ "$(uname)" != "Darwin" ]]; then
  echo "ERROR: this script audits macOS and must run on a Mac (uname reported: $(uname))."
  exit 1
fi

header() {
  echo
  echo "================================================================"
  echo "## $1"
  echo "================================================================"
}

# Print details for a launchd plist: label, program, and trigger keys.
describe_plist() {
  local plist="$1"
  local label program args runatload keepalive
  label=$(defaults read "$plist" Label 2>/dev/null || plutil -extract Label raw "$plist" 2>/dev/null || echo "?")
  program=$(plutil -extract Program raw "$plist" 2>/dev/null || true)
  args=$(plutil -extract ProgramArguments json -o - "$plist" 2>/dev/null || true)
  runatload=$(plutil -extract RunAtLoad raw "$plist" 2>/dev/null || echo "false")
  keepalive=$(plutil -extract KeepAlive raw "$plist" 2>/dev/null || echo "false")
  echo "  plist:      $plist"
  echo "  label:      $label"
  [[ -n "$program" ]] && echo "  program:    $program"
  [[ -n "$args" ]] && echo "  arguments:  $args"
  echo "  runs:       RunAtLoad=$runatload KeepAlive=$keepalive"
  ls -l "$plist" 2>/dev/null | awk '{print "  modified:   " $6, $7, $8, "owner=" $3}'

  # Resolve the executable and check its code signature.
  local exe=""
  if [[ -n "$program" ]]; then
    exe="$program"
  elif [[ -n "$args" ]]; then
    exe=$(plutil -extract ProgramArguments.0 raw "$plist" 2>/dev/null || true)
  fi
  if [[ -n "$exe" ]]; then
    if [[ ! -e "$exe" ]]; then
      echo "  [!] executable does not exist on disk: $exe"
    else
      local sig
      sig=$(codesign -dv "$exe" 2>&1 | grep -E '^(Authority|TeamIdentifier)=' | head -3 | tr '\n' '; ')
      if codesign -v "$exe" 2>/dev/null; then
        echo "  signature:  valid ${sig:+($sig)}"
      else
        echo "  [!] signature: UNSIGNED or invalid — $exe"
      fi
      case "$exe" in
        /tmp/*|/private/tmp/*|/var/tmp/*|/Users/Shared/*|*/Downloads/*)
          echo "  [!] executable runs from a suspicious location: $exe" ;;
      esac
    fi
  fi
  # Interpreter-based jobs deserve a closer look at what they execute.
  if [[ -n "$args" ]] && echo "$args" | grep -qEi '(bash|zsh|sh|osascript|python|curl|base64|nohup)'; then
    echo "  [!] job invokes a shell/interpreter or downloader — review arguments above"
  fi
  echo
}

scan_launchd_dir() {
  local dir="$1" scope="$2"
  [[ -d "$dir" ]] || { echo "(none: $dir does not exist)"; return; }
  local found=0
  for plist in "$dir"/*.plist; do
    [[ -e "$plist" ]] || continue
    found=1
    describe_plist "$plist"
  done
  [[ $found -eq 0 ]] && echo "(none in $dir)"
}

persistence() {
  header "LaunchDaemons (system-wide, run as root) — /Library/LaunchDaemons"
  echo "Note: /System/Library/* is SIP-protected Apple software and is not listed."
  scan_launchd_dir /Library/LaunchDaemons system

  header "LaunchAgents (system-wide, run at login) — /Library/LaunchAgents"
  scan_launchd_dir /Library/LaunchAgents system

  header "LaunchAgents (this user) — ~/Library/LaunchAgents"
  scan_launchd_dir "$HOME/Library/LaunchAgents" user

  header "Loaded third-party launchd jobs (launchctl list)"
  launchctl list 2>/dev/null | grep -v 'com\.apple\.' | head -60 || echo "(launchctl list unavailable)"

  header "Login items"
  osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null \
    || echo "(could not read login items via System Events — may require Automation permission)"
  echo
  echo "Background Task Management (launch items registered with macOS 13+):"
  if sfltool dumpbtm >/dev/null 2>&1; then
    sfltool dumpbtm 2>/dev/null | grep -E 'Name:|Type:|Identifier:|URL:' | head -80
  else
    echo "(sfltool dumpbtm requires sudo on this macOS version — run 'sudo sfltool dumpbtm' for the full registry)"
  fi

  header "Cron jobs"
  echo "-- crontab for $USER:"
  crontab -l 2>/dev/null || echo "(no user crontab)"
  echo "-- /etc/crontab:"
  cat /etc/crontab 2>/dev/null || echo "(no /etc/crontab)"
  echo "-- /usr/lib/cron/tabs (all users, needs sudo to read):"
  ls -l /usr/lib/cron/tabs 2>/dev/null || echo "(not readable without sudo)"

  header "Legacy & scripted persistence points"
  echo "-- /Library/StartupItems (legacy, should normally be empty):"
  ls -l /Library/StartupItems 2>/dev/null || echo "(none)"
  echo "-- Login/Logout hooks (should normally be unset):"
  defaults read com.apple.loginwindow LoginHook 2>/dev/null && echo "[!] LoginHook is set — this is rarely legitimate" || echo "(no LoginHook)"
  defaults read com.apple.loginwindow LogoutHook 2>/dev/null && echo "[!] LogoutHook is set — this is rarely legitimate" || echo "(no LogoutHook)"
  echo "-- emond rules (abused for persistence, normally only Apple's sample):"
  ls -l /etc/emond.d/rules 2>/dev/null || echo "(none)"

  header "Shell startup files (recently modified or containing download/exec patterns)"
  for f in "$HOME/.zshrc" "$HOME/.zprofile" "$HOME/.zshenv" "$HOME/.bash_profile" "$HOME/.bashrc" "$HOME/.profile" /etc/zshenv /etc/zprofile /etc/zshrc; do
    [[ -f "$f" ]] || continue
    local_mod=$(stat -f '%Sm' "$f" 2>/dev/null)
    echo "-- $f (modified: $local_mod)"
    grep -nEi '(curl|wget).*\|\s*(ba|z)?sh|base64\s+(-d|--decode)|nohup |eval \$\(|/tmp/[a-z0-9_.-]+' "$f" 2>/dev/null \
      | sed 's/^/  [!] suspicious line /' || true
  done

  header "Configuration profiles"
  profiles list 2>/dev/null || echo "(profiles list requires sudo for system profiles; run 'sudo profiles list' for full output)"
}

processes() {
  header "Running processes (non-Apple binaries, sorted by CPU)"
  echo "Columns: PID USER PPID %CPU %MEM ELAPSED COMMAND"
  ps axo pid,user,ppid,%cpu,%mem,etime,comm | awk 'NR==1 || ($7 !~ /^\/System\// && $7 !~ /^\/usr\/libexec\// && $7 !~ /^\/usr\/sbin\// && $7 !~ /^\/usr\/bin\//)' | sort -k4 -rn | head -50

  header "Processes running from suspicious locations"
  ps axo pid,user,comm | awk '$3 ~ /^\/(private\/)?(tmp|var\/tmp)\// || $3 ~ /^\/Users\/Shared\// || $3 ~ /\/Downloads\//' \
    | sed 's/^/  [!] /'
  ps axo pid,user,comm | awk '$3 ~ /^\/(private\/)?(tmp|var\/tmp)\// || $3 ~ /^\/Users\/Shared\// || $3 ~ /\/Downloads\//' | grep -q . \
    || echo "(none found)"

  header "Executable files sitting in temp/shared locations"
  find /tmp /private/tmp /var/tmp /Users/Shared -maxdepth 2 -type f -perm +111 2>/dev/null | head -30 || true
  find /tmp /private/tmp /var/tmp /Users/Shared -maxdepth 2 -type f -perm +111 2>/dev/null | grep -q . || echo "(none found)"

  header "Kernel extensions (non-Apple)"
  kextstat 2>/dev/null | grep -v com.apple | grep -v '^Index' | head -20
  kextstat 2>/dev/null | grep -v com.apple | grep -vq '^Index' || echo "(none — expected on modern macOS)"

  header "System extensions"
  systemextensionsctl list 2>/dev/null || echo "(systemextensionsctl unavailable)"
}

network() {
  header "Listening TCP ports (process, port)"
  lsof -iTCP -sTCP:LISTEN -nP 2>/dev/null | head -40 || echo "(lsof unavailable; run with sudo to see all processes)"
  echo
  echo "Note: without sudo only this user's processes are shown. Re-run with sudo for root daemons."

  header "Established connections by non-Apple processes"
  lsof -iTCP -sTCP:ESTABLISHED -nP 2>/dev/null | grep -vE '^(COMMAND|trustd|nsurlsess|apsd|cloudd|rapportd|identitys|assistant|Safari|com\.apple)' | head -40 \
    || echo "(none visible without sudo)"
}

protection() {
  header "Built-in protection status"
  echo "-- System Integrity Protection: $(csrutil status 2>/dev/null || echo unknown)"
  echo "-- Gatekeeper: $(spctl --status 2>&1)"
  fw_state=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null || echo unknown)
  echo "-- Application firewall: $fw_state"
  echo "-- FileVault: $(fdesetup status 2>/dev/null || echo unknown)"
  xp_ver=$(defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist CFBundleShortVersionString 2>/dev/null || echo unknown)
  echo "-- XProtect (Apple's built-in malware definitions) version: $xp_ver"
  echo "-- macOS: $(sw_vers -productVersion 2>/dev/null) (build $(sw_vers -buildVersion 2>/dev/null))"
  echo
  echo "Software update status (Apple security updates):"
  defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null \
    | sed 's/^/  automatic check enabled: /' || echo "  (unknown)"
}

case "$SECTION" in
  persistence) persistence ;;
  processes)   processes ;;
  network)     network ;;
  protection)  protection ;;
  full)
    echo "mac-security-monitor scan — $(date '+%Y-%m-%d %H:%M:%S') — host: $(scutil --get ComputerName 2>/dev/null || hostname)"
    echo "Read-only audit. Lines marked [!] deserve review; they are not automatically malicious."
    protection
    persistence
    processes
    network
    ;;
  *)
    echo "Usage: scan.sh [persistence|processes|network|protection|full]"
    exit 2
    ;;
esac

echo
echo "Scan complete. Reminder: [!] flags are leads, not verdicts — verify signatures and vendors before removing anything."

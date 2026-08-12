#!/bin/bash
# mac-security-monitor: snapshot the Mac's persistence inventory and diff
# later runs against it, so new background items stand out immediately.
#
# Usage: baseline.sh save    # record the current state
#        baseline.sh diff    # compare current state against the saved baseline
#        baseline.sh show    # print the saved baseline
#
# Snapshots are stored in ~/.mac-security-monitor/ and contain only an
# inventory of persistence items (paths, labels, hashes) — no personal data.

set -u

if [[ "$(uname)" != "Darwin" ]]; then
  echo "ERROR: this script audits macOS and must run on a Mac."
  exit 1
fi

MODE="${1:-diff}"
STORE="$HOME/.mac-security-monitor"
BASELINE="$STORE/baseline.txt"

snapshot() {
  echo "### launchd plists (path, sha256, label)"
  for dir in /Library/LaunchDaemons /Library/LaunchAgents "$HOME/Library/LaunchAgents"; do
    [[ -d "$dir" ]] || continue
    for plist in "$dir"/*.plist; do
      [[ -e "$plist" ]] || continue
      hash=$(shasum -a 256 "$plist" 2>/dev/null | awk '{print $1}')
      label=$(plutil -extract Label raw "$plist" 2>/dev/null || echo "?")
      echo "$plist  $hash  $label"
    done
  done

  echo "### login items"
  osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null || echo "(unreadable)"

  echo "### user crontab"
  crontab -l 2>/dev/null || echo "(none)"

  echo "### kernel extensions (non-Apple)"
  kextstat 2>/dev/null | grep -v com.apple | grep -v '^Index' | awk '{print $6}' | sort

  echo "### system extensions"
  systemextensionsctl list 2>/dev/null | tail -n +2

  echo "### listening ports"
  lsof -iTCP -sTCP:LISTEN -nP 2>/dev/null | tail -n +2 | awk '{print $1, $9}' | sort -u

  echo "### shell startup file hashes"
  for f in "$HOME/.zshrc" "$HOME/.zprofile" "$HOME/.zshenv" "$HOME/.bash_profile" "$HOME/.bashrc" "$HOME/.profile"; do
    [[ -f "$f" ]] && shasum -a 256 "$f" 2>/dev/null
  done
}

case "$MODE" in
  save)
    mkdir -p "$STORE"
    if [[ -f "$BASELINE" ]]; then
      cp "$BASELINE" "$STORE/baseline-previous.txt"
      echo "Previous baseline kept at $STORE/baseline-previous.txt"
    fi
    snapshot > "$BASELINE"
    echo "Baseline saved to $BASELINE ($(date '+%Y-%m-%d %H:%M:%S'))"
    echo "Items recorded: $(grep -c . "$BASELINE")"
    ;;
  diff)
    if [[ ! -f "$BASELINE" ]]; then
      echo "No baseline found at $BASELINE — run 'baseline.sh save' first."
      exit 2
    fi
    echo "Comparing current state against baseline saved $(stat -f '%Sm' "$BASELINE")"
    echo "Lines starting with '>' are NEW since the baseline; '<' were REMOVED."
    echo
    CURRENT=$(mktemp)
    trap 'rm -f "$CURRENT"' EXIT
    snapshot > "$CURRENT"
    if diff "$BASELINE" "$CURRENT"; then
      echo "No changes — persistence inventory matches the baseline."
    fi
    ;;
  show)
    if [[ -f "$BASELINE" ]]; then
      echo "Baseline saved $(stat -f '%Sm' "$BASELINE"):"
      cat "$BASELINE"
    else
      echo "No baseline found at $BASELINE — run 'baseline.sh save' first."
      exit 2
    fi
    ;;
  *)
    echo "Usage: baseline.sh [save|diff|show]"
    exit 2
    ;;
esac

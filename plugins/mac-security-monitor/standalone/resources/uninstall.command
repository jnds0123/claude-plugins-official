#!/bin/bash
#
#  Uninstall Mac Security Check. Double-click to remove the background
#  monitor. It will ask for your password once (to remove system files).
#
BUNDLE_ID="com.jnds0123.mac-security-check"   # match your build's BUNDLE_ID
PLIST="/Library/LaunchAgents/${BUNDLE_ID}.plist"

echo "This will remove Mac Security Check from your Mac."
echo "Your saved reports in ~/Library/Application Support/MacSecurityCheck are kept."
echo

UID_NUM=$(id -u)
launchctl bootout "gui/${UID_NUM}" "$PLIST" 2>/dev/null || launchctl unload "$PLIST" 2>/dev/null || true

sudo rm -f "$PLIST"
sudo rm -rf "/Library/Application Support/MacSecurityCheck"
pkgutil --forget "$BUNDLE_ID" >/dev/null 2>&1 || true

echo "Removed. You can close this window."

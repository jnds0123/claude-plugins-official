#!/bin/bash
#
#  build-and-sign.sh  —  builds a SIGNED, NOTARIZED .pkg installer for the
#  Mac Security Check background monitor. Run this on a Mac that has your
#  Apple Developer ID certificates installed.
#
#  What it produces:  dist/MacSecurityCheck-<version>.pkg
#    - installs the check engine to /Library/Application Support/MacSecurityCheck/
#    - installs a LaunchAgent that runs it at login and weekly, in quiet mode
#    - notifies the user only when something needs attention
#
#  One-time setup you need before running this
#  -------------------------------------------------------------------------
#  1. In Xcode / developer.apple.com, have these two certificates in your
#     login keychain (from the SAME team):
#         "Developer ID Application: YOUR NAME (TEAMID)"
#         "Developer ID Installer:   YOUR NAME (TEAMID)"
#     List what you have with:   security find-identity -v
#
#  2. Create a notarization keychain profile once (stores an app-specific
#     password so you don't type it every build):
#         xcrun notarytool store-credentials "MSC_NOTARY" \
#              --apple-id "you@example.com" \
#              --team-id  "TEAMID" \
#              --password "app-specific-password"   # from appleid.apple.com
#
#  Then run:   ./build-and-sign.sh
#  Override any value inline, e.g.:
#      TEAM_ID=ABCDE12345 NOTARY_PROFILE=MSC_NOTARY ./build-and-sign.sh
#
set -euo pipefail

# ----------------------------- configuration --------------------------------
VERSION="${VERSION:-1.0.0}"
BUNDLE_ID="${BUNDLE_ID:-com.jnds0123.mac-security-check}"
TEAM_ID="${TEAM_ID:-}"                       # e.g. ABCDE12345 (required)
INSTALLER_IDENTITY="${INSTALLER_IDENTITY:-}" # full "Developer ID Installer: ..." string; auto-detected if blank
NOTARY_PROFILE="${NOTARY_PROFILE:-MSC_NOTARY}"
SKIP_NOTARIZE="${SKIP_NOTARIZE:-0}"          # set to 1 to build+sign but not notarize (testing only)

HERE="$(cd "$(dirname "$0")" && pwd)"
ENGINE="$HERE/mac-security-check.command"
RES="$HERE/resources"
BUILD="$HERE/.build"
DIST="$HERE/dist"
PKG="$DIST/MacSecurityCheck-$VERSION.pkg"

red(){ printf '\033[31m%s\033[0m\n' "$1"; }
grn(){ printf '\033[32m%s\033[0m\n' "$1"; }
inf(){ printf '  %s\n' "$1"; }

[ "$(uname)" = "Darwin" ] || { red "Run this on macOS."; exit 1; }
[ -f "$ENGINE" ] || { red "Missing engine script: $ENGINE"; exit 1; }

echo "== Mac Security Check — build & sign =="
inf "version:    $VERSION"
inf "bundle id:  $BUNDLE_ID"

# ----------------------- auto-detect installer identity ---------------------
if [ -z "$INSTALLER_IDENTITY" ]; then
  INSTALLER_IDENTITY="$(security find-identity -v 2>/dev/null | grep 'Developer ID Installer' | head -1 | sed -E 's/^.*"(.*)"$/\1/')"
fi
if [ -z "$INSTALLER_IDENTITY" ]; then
  red "No 'Developer ID Installer' certificate found in your keychain."
  red "Install it from developer.apple.com, or check with: security find-identity -v"
  exit 1
fi
inf "signing as: $INSTALLER_IDENTITY"

# ----------------------------- assemble payload -----------------------------
rm -rf "$BUILD"; mkdir -p "$BUILD/payload" "$BUILD/scripts" "$DIST"

APPSUP="$BUILD/payload/Library/Application Support/MacSecurityCheck"
LAUNCH="$BUILD/payload/Library/LaunchAgents"
mkdir -p "$APPSUP" "$LAUNCH"

# Engine (installed without the .command extension; it's launched by launchd).
install -m 755 "$ENGINE" "$APPSUP/mac-security-check"

# LaunchAgent + postinstall, with the bundle id substituted in.
sed "s/__BUNDLE_ID__/$BUNDLE_ID/g" "$RES/LaunchAgent.plist.template" > "$LAUNCH/$BUNDLE_ID.plist"
sed "s/__BUNDLE_ID__/$BUNDLE_ID/g" "$RES/postinstall" > "$BUILD/scripts/postinstall"
chmod 755 "$BUILD/scripts/postinstall"

# Sanity-check the generated plist.
plutil -lint "$LAUNCH/$BUNDLE_ID.plist" >/dev/null

# ------------------------------- build pkg ----------------------------------
grn "Building component package..."
COMPONENT="$BUILD/component.pkg"
pkgbuild \
  --root "$BUILD/payload" \
  --scripts "$BUILD/scripts" \
  --identifier "$BUNDLE_ID" \
  --version "$VERSION" \
  --install-location "/" \
  "$COMPONENT"

grn "Building signed product installer..."
productbuild \
  --identifier "$BUNDLE_ID" \
  --version "$VERSION" \
  --package "$COMPONENT" \
  --sign "$INSTALLER_IDENTITY" \
  "$PKG"

grn "Signed: $PKG"
pkgutil --check-signature "$PKG" | sed 's/^/  /' || true

# ------------------------------- notarize -----------------------------------
if [ "$SKIP_NOTARIZE" = "1" ]; then
  red "SKIP_NOTARIZE=1 — not notarized. This build will trigger Gatekeeper warnings; use for local testing only."
  exit 0
fi

grn "Submitting to Apple for notarization (this can take a few minutes)..."
if ! xcrun notarytool submit "$PKG" --keychain-profile "$NOTARY_PROFILE" --wait; then
  red "Notarization failed. Check the profile name ('$NOTARY_PROFILE') and that your"
  red "app-specific password is valid. See the setup notes at the top of this script."
  exit 1
fi

grn "Stapling the notarization ticket..."
xcrun stapler staple "$PKG"
xcrun stapler validate "$PKG" | sed 's/^/  /'

grn "Done."
echo
echo "  Distributable installer ready:"
echo "    $PKG"
echo
echo "  Hand this .pkg to your users. They double-click it, click through the"
echo "  standard installer, and the background monitor is set up — no warnings."

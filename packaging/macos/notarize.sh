#!/bin/bash
# 用法: notarize.sh aarch64|x86_64   产物写到 $SP/out
set -euo pipefail
SP="$(cd "$(dirname "$0")" && pwd)"
case "$1" in aarch64) TAG=arm64 ;; x86_64) TAG=x64 ;; esac
IDENT="Developer ID Application: Yixiao Wang (5CS6HUB4P2)"
PROFILE=OctoDesk-Notary
VER=1.1.0
APP="$SP/dist-$1/zcode-leak-check.app"
OUT="$SP/out"; mkdir -p "$OUT"
W="$SP/notary-$1"; rm -rf "$W"; mkdir -p "$W"
BASE="zcode-leak-check-$VER-macos-$TAG"

echo "== [$TAG] notarize .app"
ditto -c -k --keepParent "$APP" "$W/app-submit.zip"
xcrun notarytool submit "$W/app-submit.zip" --keychain-profile "$PROFILE" --wait --output-format json | tee "$W/app-submit.json"
ID=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['id'])" "$W/app-submit.json")
xcrun notarytool log "$ID" --keychain-profile "$PROFILE" "$W/app-notary-log.json" || true
grep -q '"status": *"Accepted"' "$W/app-submit.json"
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"

echo "== [$TAG] zip stapled .app"
rm -f "$OUT/$BASE-app.zip"
ditto -c -k --keepParent "$APP" "$OUT/$BASE-app.zip"

echo "== [$TAG] build dmg"
STAGE="$W/dmg"; mkdir -p "$STAGE"
ditto "$APP" "$STAGE/zcode-leak-check.app"
ln -s /Applications "$STAGE/Applications"
rm -f "$OUT/$BASE.dmg"
hdiutil create -volname "zcode-leak-check $VER ($TAG)" -srcfolder "$STAGE" -fs HFS+ -format UDZO -imagekey zlib-level=9 -ov "$OUT/$BASE.dmg"
codesign --force --sign "$IDENT" --timestamp "$OUT/$BASE.dmg"

echo "== [$TAG] notarize dmg"
xcrun notarytool submit "$OUT/$BASE.dmg" --keychain-profile "$PROFILE" --wait --output-format json | tee "$W/dmg-submit.json"
ID=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['id'])" "$W/dmg-submit.json")
xcrun notarytool log "$ID" --keychain-profile "$PROFILE" "$W/dmg-notary-log.json" || true
grep -q '"status": *"Accepted"' "$W/dmg-submit.json"
xcrun stapler staple "$OUT/$BASE.dmg"
xcrun stapler validate "$OUT/$BASE.dmg"
echo "== [$TAG] DONE"

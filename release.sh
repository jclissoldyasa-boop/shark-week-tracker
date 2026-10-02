#!/bin/bash
# Publishes a new version everywhere:  ./release.sh "What changed"
#   1. builds the APK (new version code)   2. deploys the site + API + APK + version.json
#   3. commits and pushes to GitHub         4. creates a GitHub release with the APK attached
# Installed apps see the new version in /version.json and offer the update.
set -euo pipefail
cd "$(dirname "$0")"
NOTES=${1:?Usage: ./release.sh "What changed"}
RELEASE_NOTES="$NOTES" ./android/build.sh
NAME=$(node -e 'console.log(require("./android/release.json").name)')
(cd server && npm run deploy)
git add -A
git commit -q -m "Release $NAME: $NOTES" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" || true
git push -q origin HEAD
gh release create "v$NAME" android/SharkWeek.apk --title "Shark Week Tracker $NAME" --notes "$NOTES

Install: download **SharkWeek.apk** on your Android phone and open it. Or get it from https://$(node -e 'console.log(require("./site.json").host)')/"
echo "Released $NAME"

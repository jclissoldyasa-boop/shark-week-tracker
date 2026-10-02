#!/bin/bash
# Builds SharkWeek.apk from ../app.html + this Android shell. No Gradle needed.
set -euo pipefail
cd "$(dirname "$0")"
SDK=${ANDROID_HOME:-$HOME/android-sdk}
BT=$SDK/build-tools/35.0.0
JAR=$SDK/platforms/android-34/android.jar
VERSION_CODE=${VERSION_CODE:-$(( $(date +%s) / 60 ))}  # minutes since 1970: always increases
VERSION_NAME=${VERSION_NAME:-1.0.$VERSION_CODE}
node ../server/build.mjs   # pages, CSP, Site.java (host from ../site.json), keystore
rm -rf build && mkdir -p build/classes build/dex build/gen
$BT/aapt2 compile --dir res -o build/res.zip
$BT/aapt2 link -I "$JAR" --manifest AndroidManifest.xml -A assets build/res.zip --java build/gen \
  --min-sdk-version 29 --target-sdk-version 34 --version-code "$VERSION_CODE" --version-name "$VERSION_NAME" -o build/unsigned.apk
javac -nowarn -Xlint:-options --release 11 -cp "$JAR" -d build/classes $(find src gen build/gen -name '*.java')
$BT/d8 --min-api 29 --lib "$JAR" --output build/dex $(find build/classes -name '*.class')
(cd build/dex && zip -qj ../unsigned.apk classes.dex)
$BT/zipalign -f 4 build/unsigned.apk build/aligned.apk
# Keep sharkweek.keystore: Android only installs updates signed with the same key.
$BT/apksigner sign --ks sharkweek.keystore --ks-pass pass:sharkweek --out SharkWeek.apk build/aligned.apk
$BT/apksigner verify SharkWeek.apk && ls -lh SharkWeek.apk
# What the server publishes in /version.json so installed apps can offer this update.
printf '{"code":%s,"name":"%s","notes":%s}\n' "$VERSION_CODE" "$VERSION_NAME" "$(node -e 'console.log(JSON.stringify(process.argv[1]||""))' "${RELEASE_NOTES:-}")" > release.json

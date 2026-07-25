#!/bin/bash
# CI Manual Code Signing Script for iOS
# Usage: bash ios/scripts/configure_ci_signing.sh

set -euo pipefail

# ── Required environment variables ──
: "${TEAM_ID:?Must set TEAM_ID}"
: "${APP_PROFILE_PATH:?Must set APP_PROFILE_PATH}"
: "${EXT_PROFILE_PATH:?Must set EXT_PROFILE_PATH}"
: "${EXPORT_METHOD:?Must set EXPORT_METHOD (app-store or ad-hoc)}"

PROFILE_DIR="$HOME/Library/MobileDevice/Provisioning Profiles"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Configuring iOS Code Signing (CI)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── Step 1: Decode and install provisioning profiles ──
mkdir -p "$PROFILE_DIR"

APP_PROFILE=$(basename "$APP_PROFILE_PATH")
EXT_PROFILE=$(basename "$EXT_PROFILE_PATH")

if [[ -f "$APP_PROFILE_PATH" ]]; then
  cp "$APP_PROFILE_PATH" "$PROFILE_DIR/$APP_PROFILE"
  echo "[OK] App profile copied"
fi

if [[ -f "$EXT_PROFILE_PATH" ]]; then
  cp "$EXT_PROFILE_PATH" "$PROFILE_DIR/$EXT_PROFILE"
  echo "[OK] Extension profile copied"
fi

# ── Step 2: Extract Profile UUIDs and Names (cms + PlistBuddy) ──
extract_profile_field() {
  local profile_path="$1"
  local key="$2"
  local decoded
  decoded=$(mktemp)
  security cms -D -i "$profile_path" > "$decoded" 2>/dev/null
  /usr/libexec/PlistBuddy -c "Print :${key}" "$decoded" 2>/dev/null || true
  rm -f "$decoded"
}

APP_UUID=$(extract_profile_field "$PROFILE_DIR/$APP_PROFILE" "UUID")
EXT_UUID=$(extract_profile_field "$PROFILE_DIR/$EXT_PROFILE" "UUID")
APP_PROFILE_NAME=$(extract_profile_field "$PROFILE_DIR/$APP_PROFILE" "Name")
EXT_PROFILE_NAME=$(extract_profile_field "$PROFILE_DIR/$EXT_PROFILE" "Name")

# If empty, fallback to filename
APP_PROFILE_NAME=${APP_PROFILE_NAME:-$APP_PROFILE}
EXT_PROFILE_NAME=${EXT_PROFILE_NAME:-$EXT_PROFILE}

# Must export — Ruby reads ENV['APP_PROFILE_NAME'] / ENV['EXT_PROFILE_NAME']
export APP_PROFILE_NAME EXT_PROFILE_NAME

echo "App  Profile: $APP_PROFILE_NAME ($APP_UUID)"
echo "Ext  Profile: $EXT_PROFILE_NAME ($EXT_UUID)"

if [[ -z "$APP_PROFILE_NAME" || -z "$EXT_PROFILE_NAME" ]]; then
  echo "::error::Failed to resolve provisioning profile names"
  exit 1
fi

# Install with correct UUID filenames
if [[ -n "$APP_UUID" ]]; then
  cp "$PROFILE_DIR/$APP_PROFILE" "$PROFILE_DIR/${APP_UUID}.mobileprovision"
  echo "[OK] App profile installed as ${APP_UUID}.mobileprovision"
fi
if [[ -n "$EXT_UUID" ]]; then
  cp "$PROFILE_DIR/$EXT_PROFILE" "$PROFILE_DIR/${EXT_UUID}.mobileprovision"
  echo "[OK] Ext profile installed as ${EXT_UUID}.mobileprovision"
fi

# ── Step 3: Generate ExportOptions.plist ──
EXPORT_PLIST="ios/ExportOptions.plist"

cat > "$EXPORT_PLIST" << PLISTEND
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>method</key>
	<string>${EXPORT_METHOD}</string>
	<key>teamID</key>
	<string>${TEAM_ID}</string>
	<key>signingStyle</key>
	<string>manual</string>
	<key>provisioningProfiles</key>
	<dict>
		<key>com.netsignory.app</key>
		<string>${APP_PROFILE_NAME}</string>
		<key>com.netsignory.app.VPNTunnel</key>
		<string>${EXT_PROFILE_NAME}</string>
	</dict>
	<key>stripSwiftSymbols</key>
	<true/>
	<key>uploadSymbols</key>
	<true/>
	<key>manageAppVersionAndBuildNumber</key>
	<false/>
</dict>
</plist>
PLISTEND

echo "[OK] Generated $EXPORT_PLIST"

# ── Step 4: Configure Runner.xcodeproj signing ──
ruby << 'RUBY'
require 'xcodeproj'

project_path = 'ios/Runner.xcodeproj'
project = Xcodeproj::Project.open(project_path)
team_id = ENV['TEAM_ID']

app_profile = ENV['APP_PROFILE_NAME'] || ''
ext_profile = ENV['EXT_PROFILE_NAME'] || ''

if app_profile.empty? || ext_profile.empty?
  abort "[ERROR] APP_PROFILE_NAME / EXT_PROFILE_NAME empty — did you forget to export them?"
end

# TargetAttributes → Manual provisioning
attrs = project.root_object.attributes['TargetAttributes'] ||= {}
project.targets.each do |target|
  next unless %w[Runner VPNTunnel].include?(target.name)
  ta = attrs[target.uuid] ||= {}
  ta['ProvisioningStyle'] = 'Manual'
end

project.targets.each do |target|
  target.build_configurations.each do |config|
    config.build_settings['DEVELOPMENT_TEAM'] = team_id
    config.build_settings['CODE_SIGN_STYLE'] = 'Manual'
    config.build_settings['CODE_SIGN_IDENTITY[sdk=iphoneos*]'] = 'Apple Distribution'

    if target.name == 'Runner'
      config.build_settings['PROVISIONING_PROFILE_SPECIFIER'] = app_profile
      config.build_settings['CODE_SIGN_ENTITLEMENTS'] = 'Runner/Runner.entitlements'
    elsif target.name == 'VPNTunnel'
      config.build_settings['PROVISIONING_PROFILE_SPECIFIER'] = ext_profile
      config.build_settings['CODE_SIGN_ENTITLEMENTS'] = 'VPNTunnel/VPNTunnel.entitlements'
    end
  end
end

project.save
puts "[OK] Updated project.pbxproj signing settings"
puts "  Runner  PROVISIONING_PROFILE_SPECIFIER=#{app_profile}"
puts "  VPNTunnel PROVISIONING_PROFILE_SPECIFIER=#{ext_profile}"
RUBY

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Code Signing Configuration Complete"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

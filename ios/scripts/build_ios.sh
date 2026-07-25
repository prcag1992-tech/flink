#!/bin/bash
# iOS 构建脚本 —— Flutter + CocoaPods + WireGuardKit SPM
# 用法: bash ios/scripts/build_ios.sh [debug|release]

set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo ".")"

CONFIG="${1:-debug}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Building iOS ($CONFIG)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 1. Flutter 依赖
echo ""
echo "→ flutter pub get"
flutter pub get

# 2. CocoaPods
echo ""
echo "→ pod install (ios/)"
cd ios
pod install --repo-update
cd ..

# 3. 接线 WireGuardKit（本地包 + go 桥构建阶段，幂等）
echo ""
echo "→ Wiring WireGuardKit into VPNTunnel..."
if ! command -v go >/dev/null 2>&1; then
  echo "[ERROR] 未找到 Go 工具链（编译 wireguard-go 需要）。请先安装: brew install go" >&2
  exit 1
fi
ruby ios/scripts/add_wireguard_kit.rb

# 4. 确保 WireGuardKit SPM 已解析（需要 Xcode）
echo ""
echo "→ Resolving SPM packages..."
xcodebuild -resolvePackageDependencies \
  -project ios/Runner.xcodeproj \
  -scheme Runner \
  -configuration "$(echo $CONFIG | tr '[:lower:]' '[:upper:]')" 2>&1 | tail -3

# 5. 编译
echo ""
echo "→ flutter build ios ($CONFIG)"
if [ "$CONFIG" = "release" ]; then
  flutter build ios --release --no-codesign
else
  flutter build ios --debug --no-codesign
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Build complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

#!/usr/bin/env ruby
# 将本地 vendored 的 WireGuardKit（ios/WireGuardSource）接入 VPNTunnel target。
#
# 做四件事（全部幂等，可重复运行）：
#   1. 给工程添加本地 Swift Package 引用（ios/WireGuardSource）
#   2. 把 WireGuardKit 产品挂到 VPNTunnel 的依赖 + Frameworks 链接
#   3. 给 VPNTunnel 添加 "Build wireguard-go bridge" Run Script 构建阶段：
#      调用 WireGuardKitGo/Makefile 编译 libwg-go.a 到 CONFIGURATION_BUILD_DIR，
#      SPM 侧的 linkedLibrary("wg-go") 即可链接成功。需要构建机安装 Go 工具链。
#   4. 关闭 VPNTunnel 的 ENABLE_USER_SCRIPT_SANDBOXING（Makefile 要写构建目录）
#
# 用法: ruby ios/scripts/add_wireguard_kit.rb   （任意目录均可）

require 'xcodeproj'

project_path = File.expand_path('../Runner.xcodeproj', __dir__)
project = Xcodeproj::Project.open(project_path)

target = project.targets.find { |t| t.name == 'VPNTunnel' }
unless target
  puts '[ERROR] VPNTunnel target not found. Run add_vpn_extension.rb first.'
  exit 1
end

changed = false

# ── 1. 本地 Swift Package 引用 ──────────────────────────────────
local_ref = project.root_object.package_references.find do |ref|
  ref.isa == 'XCLocalSwiftPackageReference' && ref.relative_path == 'WireGuardSource'
end
unless local_ref
  local_ref = project.new(Xcodeproj::Project::Object::XCLocalSwiftPackageReference)
  local_ref.relative_path = 'WireGuardSource'
  project.root_object.package_references << local_ref
  changed = true
  puts '[OK] 添加本地包引用: WireGuardSource'
end

# ── 2. WireGuardKit 产品依赖 + Frameworks 链接 ──────────────────
dep = target.package_product_dependencies.find { |d| d.product_name == 'WireGuardKit' }
unless dep
  # 本地包的产品依赖不设置 package 属性，Xcode 按产品名从本地包解析
  dep = project.new(Xcodeproj::Project::Object::XCSwiftPackageProductDependency)
  dep.product_name = 'WireGuardKit'
  target.package_product_dependencies << dep
  changed = true
  puts '[OK] 添加产品依赖: WireGuardKit'
end

linked = target.frameworks_build_phase.files.any? { |f| f.product_ref == dep }
unless linked
  build_file = project.new(Xcodeproj::Project::Object::PBXBuildFile)
  build_file.product_ref = dep
  target.frameworks_build_phase.files << build_file
  changed = true
  puts '[OK] Frameworks 阶段链接 WireGuardKit'
end

# ── 3. wireguard-go 桥编译阶段（必须在编译/链接之前） ──────────
PHASE_NAME = 'Build wireguard-go bridge'.freeze
phase = target.shell_script_build_phases.find { |p| p.name == PHASE_NAME }
unless phase
  phase = project.new(Xcodeproj::Project::Object::PBXShellScriptBuildPhase)
  phase.name = PHASE_NAME
  phase.shell_path = '/bin/sh'
  phase.shell_script = <<~'SH'
    set -e
    export PATH="$PATH:/usr/local/bin:/opt/homebrew/bin:$HOME/go/bin"
    if ! command -v go >/dev/null 2>&1; then
      echo "error: Go toolchain not found (required to build wireguard-go). Install: brew install go"
      exit 1
    fi
    make -C "$SRCROOT/WireGuardSource/Sources/WireGuardKitGo" build
  SH
  # 声明产物用于排序；always_out_of_date 让 make 自己做增量判断
  phase.output_paths = ['$(CONFIGURATION_BUILD_DIR)/libwg-go.a']
  phase.always_out_of_date = '1'
  target.build_phases.insert(0, phase)
  changed = true
  puts '[OK] 添加构建阶段: Build wireguard-go bridge'
end

# ── 4. 关闭用户脚本沙盒（Makefile 需写 TEMP/BUILD 目录） ────────
target.build_configurations.each do |config|
  next if config.build_settings['ENABLE_USER_SCRIPT_SANDBOXING'] == 'NO'

  config.build_settings['ENABLE_USER_SCRIPT_SANDBOXING'] = 'NO'
  changed = true
  puts "[OK] #{config.name}: ENABLE_USER_SCRIPT_SANDBOXING = NO"
end

if changed
  project.save
  puts '[DONE] WireGuardKit 已接入 VPNTunnel（本地包 WireGuardSource）'
else
  puts '[SKIP] WireGuardKit 已全部接线，无需改动'
end

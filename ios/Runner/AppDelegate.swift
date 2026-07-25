import Flutter
import UIKit
import os.log
import CryptoKit
import NetworkExtension
import SystemConfiguration

@main
@objc class AppDelegate: FlutterAppDelegate {

    private let vpnMethodChannel = "com.vpnclient/vpn"
    private let vpnEventChannel = "com.vpnclient/vpn_status"
    fileprivate var statusSink: FlutterEventSink?
    private var vpnManager: NETunnelProviderManager?
    private var connectedSince: Date?

    /// 连接意图窗口：从调用 startVPNTunnel 起到隧道真正 connected 之前，
    /// 系统状态会短暂停留在 disconnected/invalid（保存/加载配置、隧道拉起过程）。
    /// 期间对 Dart 侧统一上报 "connecting"，避免上层把瞬时 disconnected 误判为连接失败
    /// 而提前 disconnect（与安卓端 getStatus 立即返回 connecting 行为对齐）。
    private var connectIntent = false
    private var connectIntentSince: Date?
    /// 启动宽限期：期间 disconnected/invalid 视为 connecting。给足 TLS + CSTP 握手时间，
    /// 又短于 Dart 侧 30s 等待，真实失败仍能在宽限期后被上报。
    private let connectGrace: TimeInterval = 15

    override func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
        // 浼犵粺 Flutter 鎻掍欢娉ㄥ唽锛圴PN 搴旂敤涓嶄娇鐢?ImplicitEngine锛?
        GeneratedPluginRegistrant.register(with: self)

        guard let controller = window?.rootViewController as? FlutterViewController else {
            return super.application(application, didFinishLaunchingWithOptions: launchOptions)
        }

        let messenger = controller.binaryMessenger

        // MethodChannel 鈥?鎺ユ敹 Flutter 鐨?VPN 鎸囦护
        let method = FlutterMethodChannel(name: vpnMethodChannel, binaryMessenger: messenger)
        method.setMethodCallHandler { [weak self] call, result in
            self?.handleMethodCall(call, result: result)
        }

        // EventChannel 鈥?鍚?Flutter 鎺ㄩ€?VPN 鐘舵€佸彉鍖?
        let event = FlutterEventChannel(name: vpnEventChannel, binaryMessenger: messenger)
        event.setStreamHandler(VpnStatusStreamHandler(appDelegate: self))

        // 鐩戝惉绯荤粺 VPN 鐘舵€佸彉鍖?
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(vpnStatusDidChange(_:)),
            name: .NEVPNStatusDidChange,
            object: nil
        )

        loadVpnManager()
        return super.application(application, didFinishLaunchingWithOptions: launchOptions)
    }

    // MARK: - VPN Manager 绠＄悊

    private func loadVpnManager() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            if let manager = managers?.first {
                self?.vpnManager = manager
            }
        }
    }

    /// 扩展 Bundle ID：必须与 pbxproj 中 VPNTunnel target 的 PRODUCT_BUNDLE_IDENTIFIER 完全一致
    /// （当前工程为 com.ava.vpnclient.vpntunnel，全小写）。
    private var tunnelBundleId: String {
        (Bundle.main.bundleIdentifier ?? "com.ava.vpnclient") + ".vpntunnel"
    }

    /// 返回一个可用的 Manager（复用已有，否则加载首个，都没有则新建）。
    /// 不在此处写入连接参数——参数由 `handleConnect` 每次连接时刷新。
    private func resolveManager(completion: @escaping (NETunnelProviderManager) -> Void) {
        if let existing = vpnManager {
            completion(existing)
            return
        }
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, _ in
            let manager = managers?.first ?? NETunnelProviderManager()
            self?.vpnManager = manager
            completion(manager)
        }
    }

    // MARK: - MethodChannel 鎸囦护鍒嗗彂

    private func handleMethodCall(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "connect":
            guard let args = call.arguments as? [String: Any] else {
                result(FlutterError(code: "INVALID_ARGS", message: "Args required", details: nil))
                return
            }
            handleConnect(args: args, result: result)
        case "disconnect":
            handleDisconnect(result: result)
        case "getStatus":
            result(connectionStatusString())
        case "applyNetworkConfig":
            guard let args = call.arguments as? [String: Any] else {
                result(nil)
                return
            }
            handleApplyNetworkConfig(args: args, result: result)
        case "applyDefaultRoute":
            handleApplyDefaultRoute(result: result)
        case "getTunnelStats":
            handleGetTunnelStats(result: result)
        case "getLastError":
            handleGetLastError(result: result)
        case "pingGateway":
            guard let args = call.arguments as? [String: Any],
                  let ip = args["gatewayIp"] as? String else {
                result(false)
                return
            }
            pingGateway(ip: ip, result: result)
        case "generateKeyPair":
            handleGenerateKeyPair(result: result)
        case "isElevated":
            // iOS 不需要管理员权限
            result(true)
        case "restartElevated":
            // iOS 不需要重启提权
            result(false)
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    // MARK: - 杩炴帴

    private func handleConnect(args: [String: Any], result: @escaping FlutterResult) {
        let proto = (args["protocol"] as? String) ?? "wireguard"
        os_log("🟢 handleConnect proto=%{public}@ server=%{public}@", type: .info,
               proto, (args["server"] as? String) ?? "")

        // 进入连接意图窗口：从此刻起 getStatus 上报 connecting，
        // 覆盖 save/load 异步窗口与隧道拉起初期的瞬时 disconnected。
        connectIntent = true
        connectIntentSince = Date()

        // 与安卓端对齐：每次连接都写入最新参数（协议 / 服务器 / 密钥 / 路由），
        // 避免切换节点或服务后仍使用旧的 providerConfiguration。
        resolveManager { [weak self] manager in
            guard let self = self else { return }
            let tunnelProto = (manager.protocolConfiguration as? NETunnelProviderProtocol)
                ?? NETunnelProviderProtocol()
            tunnelProto.providerBundleIdentifier = self.tunnelBundleId
            tunnelProto.providerConfiguration = self.buildProviderConfig(args)
            tunnelProto.serverAddress = (args["server"] as? String) ?? "vpn"

            manager.protocolConfiguration = tunnelProto
            manager.localizedDescription = "Netsignory VPN"
            manager.isEnabled = true
            manager.isOnDemandEnabled = false

            manager.saveToPreferences { saveError in
                if let saveError = saveError {
                    os_log("saveToPreferences failed: %{public}@", type: .error, saveError.localizedDescription)
                    result(FlutterError(code: "SAVE_FAILED", message: saveError.localizedDescription, details: nil))
                    return
                }
                // 必须重新加载，否则 connection 仍指向旧配置
                manager.loadFromPreferences { loadError in
                    if let loadError = loadError {
                        result(FlutterError(code: "LOAD_FAILED", message: loadError.localizedDescription, details: nil))
                        return
                    }
                    do {
                        try manager.connection.startVPNTunnel()
                        self.connectedSince = Date()
                        result("connected")
                    } catch {
                        result(FlutterError(code: "START_FAILED", message: error.localizedDescription, details: nil))
                    }
                }
            }
        }
    }

    /// 构建 providerConfiguration。
    ///
    /// iOS 对 `NETunnelProviderProtocol.providerConfiguration` 有 512KB 硬限制。
    /// 大体积的分流路由表（可达数百 KB）不写入此处，而是在连接成功后通过
    /// `applyNetworkConfig` 经 IPC (`sendProviderMessage`) 下发（扩展端已支持）。
    /// 因此这里剔除 `routes`，只保留启动隧道所需的小字段；同时只接受 plist 可序列化类型。
    private func buildProviderConfig(_ args: [String: Any]) -> [String: Any] {
        let dropKeys: Set<String> = ["routes"]
        var out: [String: Any] = [:]
        for (k, v) in args where !dropKeys.contains(k) {
            switch v {
            case is String, is NSNumber, is Bool, is Int, is Double:
                out[k] = v
            case let arr as [String]:
                out[k] = arr
            case let arr as [Any]:
                out[k] = arr.compactMap { $0 as? String }
            default:
                break
            }
        }
        return out
    }

    // MARK: - 鏂紑

    private func handleDisconnect(result: @escaping FlutterResult) {
        os_log("🔴🔴🔴 handleDisconnect CALLED", type: .fault)
        // 用户/上层主动断开：立即退出连接意图窗口，后续 getStatus 如实上报
        connectIntent = false
        connectIntentSince = nil
        vpnManager?.connection.stopVPNTunnel()
        self.connectedSince = nil
        result("disconnected")
    }

    // MARK: - 闅ч亾缁熻锛圛PC 閫氫俊锛?

    private func handleGetTunnelStats(result: @escaping FlutterResult) {
        guard let manager = vpnManager,
              let session = manager.connection as? NETunnelProviderSession else {
            result(nil)
            return
        }
        do {
            try session.sendProviderMessage("stats".data(using: .utf8)!) { data in
                if let data = data, let json = try? JSONSerialization.jsonObject(with: data) {
                    result(json)
                } else {
                    result(nil)
                }
            }
        } catch {
            result(nil)
        }
    }

    // MARK: - IPC 转发到 VPN Tunnel Extension

    /// 通用 IPC 转发：向 VPNTunnel Extension 发送消息并返回响应
    private func sendToTunnel(message: String, timeout: TimeInterval = 5, completion: @escaping (Data?) -> Void) {
        guard let manager = vpnManager,
              let session = manager.connection as? NETunnelProviderSession else {
            completion(nil)
            return
        }
        do {
            try session.sendProviderMessage(message.data(using: .utf8)!) { data in
                completion(data)
            }
        } catch {
            completion(nil)
        }
    }

    private func handleApplyNetworkConfig(args: [String: Any], result: @escaping FlutterResult) {
        // 构建 JSON IPC 消息
        var jsonCmd: [String: Any] = ["action": "network_config"]
        if let dns = args["dnsServers"] as? [String] { jsonCmd["dnsServers"] = dns }
        if let routes = args["routes"] as? [String] { jsonCmd["routes"] = routes }
        if let mtu = args["mtu"] as? Int { jsonCmd["mtu"] = mtu }

        guard let jsonData = try? JSONSerialization.data(withJSONObject: jsonCmd),
              let jsonString = String(data: jsonData, encoding: .utf8) else {
            result(nil)
            return
        }

        sendToTunnel(message: jsonString) { data in
            if let data = data, String(data: data, encoding: .utf8) == "ok" {
                result(nil)
            } else {
                result(nil)
            }
        }
    }

    private func handleApplyDefaultRoute(result: @escaping FlutterResult) {
        sendToTunnel(message: "default_route") { data in
            if let data = data, String(data: data, encoding: .utf8) == "ok" {
                result(nil)
            } else {
                result(nil)
            }
        }
    }

    private func handleGetLastError(result: @escaping FlutterResult) {
        sendToTunnel(message: "get_last_error") { data in
            if let data = data, let err = String(data: data, encoding: .utf8), !err.isEmpty {
                result(err)
            } else {
                result(nil)
            }
        }
    }

    // MARK: - Ping 缃戝叧

    private func pingGateway(ip: String, result: @escaping FlutterResult) {
        result(isHostReachable(ip))
    }

    // MARK: - 鐢熸垚 WireGuard 瀵嗛挜瀵?

    private func handleGenerateKeyPair(result: @escaping FlutterResult) {
        // WireGuard 使用 Curve25519 (X25519) 密钥对
        let wgPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let privData = wgPrivateKey.rawRepresentation
        let pubData = wgPrivateKey.publicKey.rawRepresentation
        guard !privData.isEmpty, !pubData.isEmpty else {
            result(FlutterError(code: "KEY_FAILED", message: "Key generation failed", details: nil))
            return
        }
        result([
            "privateKey": privData.base64EncodedString(),
            "publicKey": pubData.base64EncodedString()
        ])
    }

    // MARK: - VPN 鐘舵€佺洃鍚?

    @objc private func vpnStatusDidChange(_ notification: Notification) {
        guard let connection = notification.object as? NEVPNConnection else { return }
        if connection.status == .connected {
            connectedSince = connectedSince ?? Date()
        }
        let status = applyConnectGrace(connectionStatusString(from: connection.status))
        os_log("📢 NEVPNStatusDidChange: %{public}@", type: .fault, status)
        statusSink?(status)
    }

    // MARK: - 缃戠粶鍙揪鎬ф娴?

    private func isHostReachable(_ host: String) -> Bool {
        guard let ref = SCNetworkReachabilityCreateWithName(nil, host) else { return false }
        var flags: SCNetworkReachabilityFlags = []
        guard SCNetworkReachabilityGetFlags(ref, &flags) else { return false }
        return flags.contains(.reachable) && !flags.contains(.connectionRequired)
    }

    func connectionStatusString() -> String {
        guard let status = vpnManager?.connection.status else {
            return connectIntent ? "connecting" : "disconnected"
        }
        return applyConnectGrace(connectionStatusString(from: status))
    }

    /// 在连接意图窗口内，把瞬时的 disconnected/invalid 归一化为 connecting，
    /// 防止上层将隧道拉起过程中的短暂 disconnected 误判为失败并提前断开。
    /// 一旦真正 connected 即退出意图窗口；超过宽限期则如实上报（真实失败得以暴露）。
    private func applyConnectGrace(_ raw: String) -> String {
        if raw == "connected" {
            connectIntent = false
            connectIntentSince = nil
            return raw
        }
        guard connectIntent, let since = connectIntentSince else { return raw }
        if Date().timeIntervalSince(since) > connectGrace {
            connectIntent = false
            connectIntentSince = nil
            return raw
        }
        if raw == "disconnected" || raw == "invalid" {
            return "connecting"
        }
        return raw
    }

    private func connectionStatusString(from status: NEVPNStatus) -> String {
        switch status {
        case .invalid: return "invalid"
        case .disconnected: return "disconnected"
        case .connecting: return "connecting"
        case .connected: return "connected"
        case .reasserting: return "reconnecting"
        case .disconnecting: return "disconnecting"
        @unknown default: return "unknown"
        }
    }
}

// MARK: - EventChannel Stream Handler

class VpnStatusStreamHandler: NSObject, FlutterStreamHandler {
    private weak var appDelegate: AppDelegate?

    init(appDelegate: AppDelegate) {
        self.appDelegate = appDelegate
    }

    func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
        appDelegate?.statusSink = events
        events(appDelegate?.connectionStatusString() ?? "disconnected")
        return nil
    }

    func onCancel(withArguments arguments: Any?) -> FlutterError? {
        appDelegate?.statusSink = nil
        return nil
    }
}

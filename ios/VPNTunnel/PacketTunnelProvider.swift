import NetworkExtension
import Network
import Security
import os.log

#if canImport(WireGuardKit)
import WireGuardKit
#endif

/// iOS Packet Tunnel Provider —— 运行在 Network Extension 进程内。
///
/// 与安卓端 (`MainActivity` + `VpnTunnelService`) 功能对齐：
/// - WireGuard：使用 WireGuardKit (`WireGuardAdapter`) 建立隧道（等价安卓 GoBackend）。
/// - SSL：实现 Cisco AnyConnect / CSTP 协议（等价安卓 `VpnTunnelService`）：
///     TCP → TLS → `CONNECT /CSCOSSLC/tunnel`（携带 session cookie）→ 解析 `X-CSTP-*`
///     → STF 帧双向转发 + DPD/Keepalive。
/// - 两阶段路由：`applyNetworkConfig`（DNS + 非默认路由）/ `applyDefaultRoute`（0.0.0.0/0）。
/// - 通过 `handleAppMessage` 接收主 App 的 IPC 指令，并回传 stats / lastError。
///
/// CSTP 帧格式：'S''T''F' 0x01 + lenHi + lenLo + type + 0x00 + [payload]
///   type: 0x00=DATA, 0x03=DPD-REQ, 0x04=DPD-RESP, 0x05=DISCONNECT, 0x07=KEEPALIVE
class PacketTunnelProvider: NEPacketTunnelProvider {

    private let log = OSLog(subsystem: "com.netsignory.app.tunnel", category: "tunnel")

    // MARK: - 通用状态

    private var lastError: String?
    private var proto: String = "wireguard"
    private var serverHost: String = ""
    private var serverIp: String = ""
    private var serverPort: Int = 443

    // 隧道网络配置（SSL 由 CSTP 协商，WireGuard 由下发参数决定）
    private var tunnelIp: String = "10.0.0.2"
    private var tunnelPrefix: Int = 32
    private var cstpMtu: Int = 1399
    private var keepaliveInterval: Int = 20
    private var dpdInterval: Int = 30

    // 生效的 DNS / 路由（两阶段路由复用）
    private var effectiveDns: [String] = []
    private var effectiveRoutes: [String] = []
    private var fullTunnel: Bool = false   // = !splitRouting

    // MARK: - SSL / CSTP 状态

    private var connection: NWConnection?
    private let connQueue = DispatchQueue(label: "com.netsignory.cstp")
    private var inBuffer = Data()
    private var running = false
    private var keepaliveTimer: DispatchSourceTimer?

    private var txBytes: Int64 = 0
    private var rxBytes: Int64 = 0

    private static let cstpMagic: [UInt8] = [0x53, 0x54, 0x46, 0x01] // 'S''T''F' 0x01

    // MARK: - WireGuard 状态

    #if canImport(WireGuardKit)
    private lazy var wgAdapter: WireGuardAdapter = {
        WireGuardAdapter(with: self) { [weak self] level, message in
            guard let self = self else { return }
            os_log("WG[%d]: %{public}@", log: self.log, type: .info, level.rawValue, message)
        }
    }()
    private var wgStarted = false
    #endif

    // ─────────────────────────────────────────────────────────────
    // MARK: - 启动
    // ─────────────────────────────────────────────────────────────

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        guard let config = protocolConfiguration as? NETunnelProviderProtocol,
              let params = config.providerConfiguration else {
            fail(&lastError, "缺少连接参数")
            completionHandler(NSError(domain: "VPN", code: -1,
                                      userInfo: [NSLocalizedDescriptionKey: "缺少连接参数"]))
            return
        }

        lastError = nil
        proto = (params["protocol"] as? String) ?? "wireguard"
        serverHost = (params["server"] as? String) ?? ""
        serverPort = (params["port"] as? Int) ?? ((params["port"] as? NSNumber)?.intValue ?? 443)
        serverIp = resolveIPv4(serverHost) ?? serverHost

        let dns = (params["dnsServers"] as? [String]) ?? []
        let routes = (params["routes"] as? [String]) ?? []
        // NSNumber / Bool 兼容；默认全隧道（分流关闭）
        let splitRouting: Bool = {
            if let b = params["splitRouting"] as? Bool { return b }
            if let n = params["splitRouting"] as? NSNumber { return n.boolValue }
            return false
        }()
        fullTunnel = !splitRouting
        effectiveDns = dns
        effectiveRoutes = routes

        os_log("startTunnel proto=%{public}@ server=%{public}@(%{public}@):%d split=%d fullTunnel=%d routes=%d",
               log: log, type: .info, proto, serverHost, serverIp, serverPort,
               splitRouting ? 1 : 0, fullTunnel ? 1 : 0, routes.count)

        if proto == "wireguard" {
            startWireGuard(params: params, completionHandler: completionHandler)
        } else {
            startSsl(params: params, completionHandler: completionHandler)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        os_log("stopTunnel reason=%d", log: log, type: .info, reason.rawValue)
        running = false
        stopKeepalive()
        sendCstpControl(type: 0x05) // DISCONNECT（尽力而为）
        connection?.cancel()
        connection = nil

        #if canImport(WireGuardKit)
        if wgStarted {
            wgStarted = false
            wgAdapter.stop { _ in completionHandler() }
            return
        }
        #endif
        completionHandler()
    }

    // ─────────────────────────────────────────────────────────────
    // MARK: - WireGuard（等价安卓 GoBackend 路径）
    // ─────────────────────────────────────────────────────────────

    private func startWireGuard(
        params: [String: Any],
        completionHandler: @escaping (Error?) -> Void
    ) {
        #if canImport(WireGuardKit)
        let serverPublicKey = (params["serverPublicKey"] as? String) ?? ""
        let clientPrivateKey = (params["clientPrivateKey"] as? String) ?? ""
        let clientIpAddress = (params["clientIpAddress"] as? String) ?? "10.0.0.2"

        guard !serverIp.isEmpty, !serverPublicKey.isEmpty, !clientPrivateKey.isEmpty else {
            fail(&lastError, "WireGuard 需要 server / serverPublicKey / clientPrivateKey")
            completionHandler(NSError(domain: "VPN", code: -10,
                                      userInfo: [NSLocalizedDescriptionKey: lastError!]))
            return
        }

        guard let tunnelConfig = buildWgConfig(
            server: serverIp, port: serverPort,
            serverPublicKey: serverPublicKey, clientPrivateKey: clientPrivateKey,
            dnsServers: effectiveDns, clientIpAddress: clientIpAddress,
            routes: effectiveRoutes, fullTunnel: fullTunnel
        ) else {
            fail(&lastError, "WireGuard 配置解析失败（密钥格式错误）")
            completionHandler(NSError(domain: "VPN", code: -11,
                                      userInfo: [NSLocalizedDescriptionKey: lastError!]))
            return
        }

        wgAdapter.start(tunnelConfiguration: tunnelConfig) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                self.fail(&self.lastError, "WireGuard 启动失败: \(error)")
                completionHandler(error)
            } else {
                self.wgStarted = true
                os_log("WireGuard 隧道已建立", log: self.log, type: .info)
                completionHandler(nil)
            }
        }
        #else
        fail(&lastError, "WireGuardKit 未链接，无法建立 WireGuard 隧道")
        completionHandler(NSError(domain: "VPN", code: -12,
                                  userInfo: [NSLocalizedDescriptionKey: lastError!]))
        #endif
    }

    #if canImport(WireGuardKit)
    /// 构建 WireGuard 隧道配置（对齐安卓 `buildWgConfig`）。
    private func buildWgConfig(
        server: String, port: Int,
        serverPublicKey: String, clientPrivateKey: String,
        dnsServers: [String], clientIpAddress: String,
        routes: [String],
        fullTunnel: Bool
    ) -> TunnelConfiguration? {
        guard let privateKey = PrivateKey(base64Key: clientPrivateKey),
              let publicKey = PublicKey(base64Key: serverPublicKey) else {
            return nil
        }

        var interface = InterfaceConfiguration(privateKey: privateKey)
        let addr = clientIpAddress.contains("/") ? clientIpAddress : "\(clientIpAddress)/32"
        if let range = IPAddressRange(from: addr) {
            interface.addresses = [range]
        }

        // 节点 DNS + 公共回退（对齐安卓 8.8.8.8 / 223.5.5.5）
        var dnsList: [DNSServer] = []
        for d in dnsServers {
            if let s = DNSServer(from: d) { dnsList.append(s) }
        }
        for d in ["8.8.8.8", "223.5.5.5"] where !dnsServers.contains(d) {
            if let s = DNSServer(from: d) { dnsList.append(s) }
        }
        interface.dns = dnsList

        var peer = PeerConfiguration(publicKey: publicKey)
        peer.endpoint = Endpoint(from: "\(server):\(port)")
        peer.persistentKeepAlive = 25

        // AllowedIPs：全隧道固定 0.0.0.0/0；分流才用路由表（空路由时不要误装默认路由再缩回）
        var allowed: [IPAddressRange] = []
        if fullTunnel {
            if let v4 = IPAddressRange(from: "0.0.0.0/0") { allowed.append(v4) }
        } else {
            for r in routes {
                if let range = IPAddressRange(from: normalizeCidr(r)) { allowed.append(range) }
            }
            for d in dnsServers {
                if let range = IPAddressRange(from: "\(d)/32") { allowed.append(range) }
            }
        }
        peer.allowedIPs = allowed

        return TunnelConfiguration(name: "netsignory", interface: interface, peers: [peer])
    }
    #endif

    // ─────────────────────────────────────────────────────────────
    // MARK: - SSL / CSTP（等价安卓 VpnTunnelService）
    // ─────────────────────────────────────────────────────────────

    private func startSsl(
        params: [String: Any],
        completionHandler: @escaping (Error?) -> Void
    ) {
        let sessionCookie = (params["sessionCookie"] as? String) ?? ""
        guard !serverHost.isEmpty else {
            fail(&lastError, "SSL_INVALID_SERVER")
            completionHandler(NSError(domain: "VPN", code: -20,
                                      userInfo: [NSLocalizedDescriptionKey: lastError!]))
            return
        }
        guard !sessionCookie.isEmpty else {
            fail(&lastError, "CSTP_NO_SESSION_COOKIE")
            completionHandler(NSError(domain: "VPN", code: -21,
                                      userInfo: [NSLocalizedDescriptionKey: lastError!]))
            return
        }

        // TLS（信任所有证书，VPN 网关常用自签名，对齐安卓 trustAll）
        let tlsOptions = NWProtocolTLS.Options()
        sec_protocol_options_set_verify_block(
            tlsOptions.securityProtocolOptions,
            { _, _, complete in complete(true) },
            connQueue
        )
        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.connectionTimeout = 10
        tcpOptions.noDelay = true

        let nwParams = NWParameters(tls: tlsOptions, tcp: tcpOptions)
        // 全隧道默认路由生效后，未固定路径的 NWConnection 可能迁移进自身
        // Packet Tunnel，造成 CSTP 传输自环并表现为“已连接但国内外都断网”。
        // NEProvider.defaultPath 在部分 Xcode SDK 中是旧版 NWPath，没有
        // usesInterfaceType；用 isExpensive 兼容判断蜂窝/非蜂窝网络。
        if let path = defaultPath {
            nwParams.requiredInterfaceType =
                path.isExpensive ? .cellular : .wifi
        }
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(serverHost),
            port: NWEndpoint.Port(integerLiteral: UInt16(serverPort))
        )
        let conn = NWConnection(to: endpoint, using: nwParams)
        connection = conn

        var handshakeDone = false
        conn.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            switch state {
            case .ready:
                os_log("TLS 就绪，发送 CSTP CONNECT", log: self.log, type: .info)
                self.sendCstpConnect(cookie: sessionCookie) { ok in
                    handshakeDone = true
                    if ok {
                        completionHandler(nil)
                    } else {
                        completionHandler(NSError(domain: "VPN", code: -22,
                            userInfo: [NSLocalizedDescriptionKey: self.lastError ?? "CSTP_FAILED"]))
                    }
                }
            case .failed(let error):
                os_log("NWConnection 失败: %{public}@", log: self.log, type: .error, "\(error)")
                self.fail(&self.lastError, "SSL_TLS_HANDSHAKE_FAILED: \(error)")
                if !handshakeDone {
                    handshakeDone = true
                    completionHandler(error)
                }
            case .cancelled:
                self.running = false
            default:
                break
            }
        }
        conn.start(queue: connQueue)
    }

    /// 发送 CSTP CONNECT 请求并解析响应头（对齐安卓 `performCstpConnect`）。
    private func sendCstpConnect(cookie: String, completion: @escaping (Bool) -> Void) {
        guard let conn = connection else { completion(false); return }
        let hostname = ProcessInfo.processInfo.hostName

        var req = ""
        req += "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n"
        req += "Host: \(serverHost)\r\n"
        req += "User-Agent: Cisco AnyConnect VPN Agent for Windows\r\n"
        req += "Cookie: \(cookie)\r\n"
        req += "X-CSTP-Version: 1\r\n"
        req += "X-CSTP-Hostname: \(hostname)\r\n"
        req += "X-CSTP-MTU: 1399\r\n"
        req += "X-CSTP-Address-Type: IPv4\r\n"
        req += "X-CSTP-Base-MTU: 1500\r\n"
        req += "X-CSTP-Full-IPv6-Capability: false\r\n"
        req += "\r\n"

        conn.send(content: req.data(using: .utf8), completion: .contentProcessed { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                self.fail(&self.lastError, "CSTP_SEND_FAILED: \(error)")
                completion(false)
                return
            }
            self.readCstpResponse(accumulated: Data(), completion: completion)
        })
    }

    /// 逐块读取 HTTP 响应，直到 `\r\n\r\n`；余下字节作为首批 CSTP 帧数据。
    private func readCstpResponse(accumulated: Data, completion: @escaping (Bool) -> Void) {
        guard let conn = connection else { completion(false); return }
        conn.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] data, _, isComplete, error in
            guard let self = self else { return }
            var buf = accumulated
            if let d = data, !d.isEmpty { buf.append(d) }

            let delimiter = Data([13, 10, 13, 10]) // \r\n\r\n
            if let range = buf.range(of: delimiter) {
                let headerData = buf.subdata(in: buf.startIndex..<range.lowerBound)
                let leftover = buf.subdata(in: range.upperBound..<buf.endIndex)
                let ok = self.parseCstpHeaders(headerData)
                if ok {
                    self.applySslNetworkSettings { settingsErr in
                        if let settingsErr = settingsErr {
                            self.fail(&self.lastError, "SET_SETTINGS_FAILED: \(settingsErr)")
                            completion(false)
                            return
                        }
                        // 隧道就绪：启动转发，首批 leftover 数据先入缓冲
                        self.running = true
                        self.txBytes = 0
                        self.rxBytes = 0
                        if !leftover.isEmpty { self.inBuffer.append(leftover); self.processInboundFrames() }
                        self.startForwarding()
                        completion(true)
                    }
                } else {
                    completion(false)
                }
                return
            }

            if error != nil || isComplete {
                self.fail(&self.lastError, "CSTP_CONNECT_CLOSED")
                completion(false)
                return
            }
            if buf.count < 16384 {
                self.readCstpResponse(accumulated: buf, completion: completion)
            } else {
                self.fail(&self.lastError, "CSTP_HEADER_TOO_LARGE")
                completion(false)
            }
        }
    }

    /// 解析 X-CSTP-* 响应头，提取隧道 IP / DNS / MTU / 路由等。
    private func parseCstpHeaders(_ headerData: Data) -> Bool {
        guard let text = String(data: headerData, encoding: .utf8) else {
            fail(&lastError, "CSTP_HEADER_DECODE_FAILED")
            return false
        }
        let lines = text.components(separatedBy: "\r\n")
        guard let statusLine = lines.first, statusLine.contains("200") else {
            fail(&lastError, "SSL_CSTP_CONNECT_REJECTED: \(lines.first ?? "")")
            return false
        }

        tunnelIp = "10.0.0.2"
        var netmask = "255.255.255.255"
        cstpMtu = 1399
        dpdInterval = 30
        keepaliveInterval = 20
        var dnsList: [String] = []
        var routeList: [String] = []

        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let key = String(line[line.startIndex..<colon]).trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            switch key {
            case "X-CSTP-Address": tunnelIp = value
            case "X-CSTP-Netmask": netmask = value
            case "X-CSTP-MTU": cstpMtu = Int(value) ?? 1399
            case "X-CSTP-DPD": dpdInterval = Int(value) ?? 30
            case "X-CSTP-Keepalive": keepaliveInterval = Int(value) ?? 20
            case "X-CSTP-DNS": dnsList.append(value)
            case "X-CSTP-Split-Include", "X-CSTP-Split-Exclude": routeList.append(value)
            default: break
            }
        }

        tunnelPrefix = netmaskToPrefix(netmask)
        // CSTP 下发优先，否则回退连接参数下发的 DNS / 路由
        if !dnsList.isEmpty { effectiveDns = dnsList }
        if !routeList.isEmpty { effectiveRoutes = mergeRoutes(effectiveRoutes, routeList) }

        os_log("CSTP tunnel ip=%{public}@/%d mtu=%d dns=%d routes=%d",
               log: log, type: .info, tunnelIp, tunnelPrefix, cstpMtu, effectiveDns.count, effectiveRoutes.count)
        return true
    }

    // MARK: - SSL 双向转发

    private func startForwarding() {
        readOutbound()
        receiveInbound()
        startKeepalive()
    }

    /// 出站：packetFlow → CSTP DATA 帧 → NWConnection。
    /// 关键优化：把一次 readPackets 回调里的所有 IP 包合并到单个缓冲区、一次性 send，
    /// 避免每包一条小 TLS 记录带来的加密/封装/系统调用开销（对上行吞吐影响很大）。
    private func readOutbound() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self = self, self.running, let conn = self.connection else { return }
            var batch = Data()
            batch.reserveCapacity(packets.reduce(0) { $0 + $1.count + 8 })
            var total = 0
            for packet in packets {
                let len = packet.count
                if len == 0 || len > 65535 { continue }
                batch.append(0x53); batch.append(0x54); batch.append(0x46); batch.append(0x01)
                batch.append(UInt8((len >> 8) & 0xFF)); batch.append(UInt8(len & 0xFF))
                batch.append(0x00); batch.append(0x00)
                batch.append(packet)
                total += len
            }

            if batch.isEmpty {
                if self.running { self.readOutbound() }
                return
            }

            // 所有 NWConnection 写入都在 connQueue 串行执行，并在发送完成后
            // 再读取下一批，避免浏览网页时大量并发 send 堆积或乱序。
            let outboundBatch = batch
            let outboundBytes = total
            self.connQueue.async {
                conn.send(content: outboundBatch, completion: .contentProcessed { [weak self] error in
                    guard let self = self else { return }
                    if let error = error {
                        self.fail(&self.lastError, "CSTP_DATA_SEND_FAILED: \(error)")
                        self.running = false
                        conn.cancel()
                        self.cancelTunnelWithError(NSError(
                            domain: "VPN",
                            code: -24,
                            userInfo: [NSLocalizedDescriptionKey: self.lastError ?? "CSTP data send failed"]
                        ))
                        return
                    }
                    self.txBytes += Int64(outboundBytes)
                    if self.running { self.readOutbound() }
                })
            }
        }
    }

    /// 入站：NWConnection → 累积缓冲 → 解析 CSTP 帧。
    private func receiveInbound() {
        guard let conn = connection else { return }
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self = self else { return }
            if let d = data, !d.isEmpty {
                self.inBuffer.append(d)
                self.processInboundFrames()
            }
            if isComplete || error != nil {
                let detail = error.map { String(describing: $0) } ?? "EOF"
                let message = "CSTP_INBOUND_CLOSED: \(detail)"
                os_log("%{public}@", log: self.log, type: .error, message)
                self.lastError = message
                let wasRunning = self.running
                self.running = false
                if wasRunning {
                    self.cancelTunnelWithError(NSError(
                        domain: "VPN",
                        code: -23,
                        userInfo: [NSLocalizedDescriptionKey: message]
                    ))
                }
                return
            }
            if self.running { self.receiveInbound() }
        }
    }

    /// 从累积缓冲中解析完整 CSTP 帧。
    /// 关键优化：
    /// 1. 一次回调内解析出所有完整帧，DATA 帧的 IP 包收集成批，最后一次性
    ///    `writePackets` 写入 TUN（减少跨进程写调用）。
    /// 2. 只在最后对 `inBuffer` 做一次 `removeSubrange` 丢弃已消费前缀，
    ///    避免每帧一次前缀删除（Data 前缀删除是 O(n) 拷贝，逐帧删除会退化为 O(n²)）。
    private func processInboundFrames() {
        let count = inBuffer.count
        if count < 8 { return }

        var consumed = 0
        var packets: [Data] = []
        var protos: [NSNumber] = []
        var invalid = false
        var disconnected = false
        var needDpd = false

        inBuffer.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            let b = raw.bindMemory(to: UInt8.self)
            while count - consumed >= 8 {
                let o = consumed
                if b[o] != 0x53 || b[o + 1] != 0x54 || b[o + 2] != 0x46 || b[o + 3] != 0x01 {
                    invalid = true
                    return
                }
                let payloadLen = (Int(b[o + 4]) << 8) | Int(b[o + 5])
                let frameType = Int(b[o + 6])
                let frameTotal = 8 + payloadLen
                if count - consumed < frameTotal { break } // 半包，等待更多数据

                switch frameType {
                case 0x00: // DATA
                    if payloadLen > 0 {
                        let start = o + 8
                        let pkt = Data(bytes: b.baseAddress!.advanced(by: start), count: payloadLen)
                        // 依据 IP 版本位选择协议族，IPv6 也能正确回注 TUN
                        let family = (b[start] >> 4) == 6 ? AF_INET6 : AF_INET
                        packets.append(pkt)
                        protos.append(NSNumber(value: family))
                        rxBytes += Int64(payloadLen)
                    }
                case 0x03: // DPD-REQ
                    needDpd = true
                case 0x05: // DISCONNECT
                    disconnected = true
                    consumed += frameTotal
                    return
                default:
                    break // DPD-RESP(0x04) / KEEPALIVE(0x07) / 其他：忽略
                }
                consumed += frameTotal
            }
        }

        if consumed > 0 {
            inBuffer.removeSubrange(inBuffer.startIndex..<inBuffer.index(inBuffer.startIndex, offsetBy: consumed))
        }
        if !packets.isEmpty {
            packetFlow.writePackets(packets, withProtocols: protos)
        }
        if needDpd {
            sendCstpControl(type: 0x04)
        }
        if invalid {
            os_log("无效 CSTP 帧头，断开", log: log, type: .error)
            running = false
            connection?.cancel()
            return
        }
        if disconnected {
            os_log("服务器发送 DISCONNECT", log: log, type: .info)
            running = false
            connection?.cancel()
        }
    }

    private func sendCstpControl(type: UInt8) {
        guard let conn = connection else { return }
        let frame = Data([0x53, 0x54, 0x46, 0x01, 0x00, 0x00, type, 0x00])
        conn.send(content: frame, completion: .contentProcessed { _ in })
    }

    private func startKeepalive() {
        guard keepaliveInterval > 0 else { return }
        let timer = DispatchSource.makeTimerSource(queue: connQueue)
        timer.schedule(deadline: .now() + .seconds(keepaliveInterval),
                       repeating: .seconds(keepaliveInterval))
        timer.setEventHandler { [weak self] in
            guard let self = self, self.running else { self?.keepaliveTimer?.cancel(); return }
            self.sendCstpControl(type: 0x07) // KEEPALIVE
        }
        timer.resume()
        keepaliveTimer = timer
    }

    private func stopKeepalive() {
        keepaliveTimer?.cancel()
        keepaliveTimer = nil
    }

    // ─────────────────────────────────────────────────────────────
    // MARK: - 两阶段路由 / 网络配置写入
    // ─────────────────────────────────────────────────────────────

    /// 应用 SSL 隧道网络配置（首次握手 + applyNetworkConfig 复用）。
    private func applySslNetworkSettings(completion: @escaping (Error?) -> Void) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: serverIp.isEmpty ? serverHost : serverIp)
        settings.mtu = NSNumber(value: cstpMtu.clamped(1280, 1500))

        let ipv4 = NEIPv4Settings(addresses: [tunnelIp], subnetMasks: [maskString(tunnelPrefix)])
        var included: [NEIPv4Route] = []
        if fullTunnel {
            included.append(NEIPv4Route.default())
        } else {
            for r in effectiveRoutes {
                if r == "0.0.0.0/0" || r == "::/0" { continue }
                if let route = ipv4Route(r) { included.append(route) }
            }
            // DNS 走隧道（/32 主机路由）
            for d in effectiveDns {
                if isIPv4(d) { included.append(NEIPv4Route(destinationAddress: d, subnetMask: "255.255.255.255")) }
            }
        }
        ipv4.includedRoutes = included
        // 排除 VPN 服务器 IP，避免隧道 socket 流量环路（等价安卓 protect()）
        if isIPv4(serverIp) {
            ipv4.excludedRoutes = [NEIPv4Route(destinationAddress: serverIp, subnetMask: "255.255.255.255")]
        }
        settings.ipv4Settings = ipv4

        var dns = effectiveDns
        for d in ["8.8.8.8", "223.5.5.5"] where !dns.contains(d) { dns.append(d) }
        if !dns.isEmpty {
            let dnsSettings = NEDNSSettings(servers: dns)
            dnsSettings.matchDomains = [""] // 捕获所有 DNS 查询
            settings.dnsSettings = dnsSettings
        }

        setTunnelNetworkSettings(settings, completionHandler: completion)
    }

    /// 第一阶段：写入 DNS + 非默认路由（对齐安卓 `applyNetworkConfig`）。
    private func handleApplyNetworkConfig(
        dns: [String],
        routes: [String],
        mtu: Int,
        completion: @escaping (Error?) -> Void
    ) {
        if !dns.isEmpty { effectiveDns = dns }
        if !routes.isEmpty { effectiveRoutes = routes }
        // 不要用主 App 的默认值放大服务端协商 MTU，否则大包可能被 ASA 丢弃。
        if mtu > 0 { cstpMtu = min(cstpMtu, mtu) }

        #if canImport(WireGuardKit)
        if wgStarted {
            updateWireGuardRoutes()
            completion(nil)
            return
        }
        #endif
        applySslNetworkSettings { [weak self] error in
            if let error = error {
                os_log("applyNetworkConfig 失败: %{public}@", log: self?.log ?? .default, type: .error, "\(error)")
            }
            completion(error)
        }
    }

    /// 第二阶段：追加默认路由，全流量走隧道（对齐安卓 `applyDefaultRoute`）。
    private func handleApplyDefaultRoute(completion: @escaping (Error?) -> Void) {
        fullTunnel = true
        #if canImport(WireGuardKit)
        if wgStarted {
            updateWireGuardRoutes()
            completion(nil)
            return
        }
        #endif
        applySslNetworkSettings { [weak self] error in
            if let error = error {
                os_log("applyDefaultRoute 失败: %{public}@", log: self?.log ?? .default, type: .error, "\(error)")
            }
            completion(error)
        }
    }

    #if canImport(WireGuardKit)
    /// WireGuard 两阶段路由：重建配置并热更新 AllowedIPs / DNS。
    private func updateWireGuardRoutes() {
        guard let config = protocolConfiguration as? NETunnelProviderProtocol,
              let params = config.providerConfiguration else { return }
        let serverPublicKey = (params["serverPublicKey"] as? String) ?? ""
        let clientPrivateKey = (params["clientPrivateKey"] as? String) ?? ""
        let clientIpAddress = (params["clientIpAddress"] as? String) ?? "10.0.0.2"
        let routes = fullTunnel ? [] : effectiveRoutes
        guard let tunnelConfig = buildWgConfig(
            server: serverIp, port: serverPort,
            serverPublicKey: serverPublicKey, clientPrivateKey: clientPrivateKey,
            dnsServers: effectiveDns, clientIpAddress: clientIpAddress,
            routes: routes, fullTunnel: fullTunnel
        ) else { return }
        wgAdapter.update(tunnelConfiguration: tunnelConfig) { [weak self] error in
            if let error = error {
                os_log("WG update 失败: %{public}@", log: self?.log ?? .default, type: .error, "\(error)")
            }
        }
    }
    #endif

    // ─────────────────────────────────────────────────────────────
    // MARK: - IPC（主 App → 扩展）
    // ─────────────────────────────────────────────────────────────

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        let cmd = String(data: messageData, encoding: .utf8) ?? ""

        switch cmd {
        case "stats":
            #if canImport(WireGuardKit)
            if wgStarted {
                // 从 wg-go 运行时配置（UAPI 文本）解析各 peer 的累计流量
                wgAdapter.getRuntimeConfiguration { config in
                    var tx: Int64 = 0
                    var rx: Int64 = 0
                    if let config = config {
                        for line in config.split(separator: "\n") {
                            if line.hasPrefix("tx_bytes=") {
                                tx += Int64(line.dropFirst("tx_bytes=".count)) ?? 0
                            } else if line.hasPrefix("rx_bytes=") {
                                rx += Int64(line.dropFirst("rx_bytes=".count)) ?? 0
                            }
                        }
                    }
                    let stats: [String: Any] = ["txBytes": tx, "rxBytes": rx, "status": "connected"]
                    completionHandler?(try? JSONSerialization.data(withJSONObject: stats))
                }
                return
            }
            #endif
            completionHandler?(statsJson())
            return
        case "get_last_error":
            completionHandler?((lastError ?? "").data(using: .utf8))
            return
        case "default_route":
            handleApplyDefaultRoute { [weak self] error in
                if let error = error {
                    self?.lastError = "applyDefaultRoute failed: \(error)"
                    completionHandler?("error".data(using: .utf8))
                } else {
                    completionHandler?("ok".data(using: .utf8))
                }
            }
            return
        default:
            break
        }

        // JSON 指令：{ action: "network_config", dnsServers, routes, mtu }
        if let json = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any],
           let action = json["action"] as? String {
            switch action {
            case "network_config":
                let dns = (json["dnsServers"] as? [String]) ?? []
                let routes = (json["routes"] as? [String]) ?? []
                let mtu = (json["mtu"] as? Int) ?? ((json["mtu"] as? NSNumber)?.intValue ?? 0)
                handleApplyNetworkConfig(dns: dns, routes: routes, mtu: mtu) { [weak self] error in
                    if let error = error {
                        self?.lastError = "applyNetworkConfig failed: \(error)"
                        completionHandler?("error".data(using: .utf8))
                    } else {
                        completionHandler?("ok".data(using: .utf8))
                    }
                }
                return
            default:
                break
            }
        }
        completionHandler?(nil)
    }

    private func statsJson() -> Data? {
        let stats: [String: Any] = ["txBytes": txBytes, "rxBytes": rxBytes,
                                    "status": running ? "connected" : "disconnected"]
        return try? JSONSerialization.data(withJSONObject: stats)
    }

    // ─────────────────────────────────────────────────────────────
    // MARK: - 工具
    // ─────────────────────────────────────────────────────────────

    private func fail(_ slot: inout String?, _ message: String) {
        slot = message
        os_log("ERROR: %{public}@", log: log, type: .error, message)
    }

    /// 同步解析主机名为 IPv4（用于 excludedRoutes / tunnelRemoteAddress）。
    private func resolveIPv4(_ host: String) -> String? {
        if isIPv4(host) { return host }
        if host.isEmpty { return nil }
        var hints = addrinfo(ai_flags: 0, ai_family: AF_INET, ai_socktype: SOCK_STREAM,
                             ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var result: UnsafeMutablePointer<addrinfo>?
        defer { if result != nil { freeaddrinfo(result) } }
        guard getaddrinfo(host, nil, &hints, &result) == 0 else { return nil }
        var ptr = result
        while let addr = ptr {
            if addr.pointee.ai_family == AF_INET, let sa = addr.pointee.ai_addr {
                var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                    var a = sin.pointee.sin_addr
                    inet_ntop(AF_INET, &a, &buf, socklen_t(INET_ADDRSTRLEN))
                }
                return String(cString: buf)
            }
            ptr = addr.pointee.ai_next
        }
        return nil
    }

    private func isIPv4(_ s: String) -> Bool {
        let parts = s.split(separator: ".")
        if parts.count != 4 { return false }
        return parts.allSatisfy { Int($0).map { $0 >= 0 && $0 <= 255 } ?? false }
    }

    /// "ip/prefix" 或 "ip/netmask" → NEIPv4Route。
    private func ipv4Route(_ cidr: String) -> NEIPv4Route? {
        let parts = cidr.split(separator: "/", maxSplits: 1).map(String.init)
        guard let ip = parts.first, isIPv4(ip) else { return nil }
        let mask: String
        if parts.count == 2 {
            if let prefix = Int(parts[1]) {
                mask = maskString(prefix)
            } else if isIPv4(parts[1]) {
                mask = parts[1]
            } else {
                mask = "255.255.255.255"
            }
        } else {
            mask = "255.255.255.255"
        }
        return NEIPv4Route(destinationAddress: ip, subnetMask: mask)
    }

    private func normalizeCidr(_ s: String) -> String {
        if s.contains("/") { return s }
        return "\(s)/32"
    }

    private func maskString(_ prefix: Int) -> String {
        let p = prefix.clamped(0, 32)
        let mask: UInt32 = p == 0 ? 0 : (0xFFFFFFFF << (32 - p)) & 0xFFFFFFFF
        return "\((mask >> 24) & 0xFF).\((mask >> 16) & 0xFF).\((mask >> 8) & 0xFF).\(mask & 0xFF)"
    }

    private func netmaskToPrefix(_ mask: String) -> Int {
        let parts = mask.split(separator: ".")
        guard parts.count == 4 else { return 32 }
        var bits: UInt32 = 0
        for p in parts { bits = (bits << 8) | (UInt32(p) ?? 0) }
        var count = 0
        var v = bits
        while v & 0x80000000 != 0 { count += 1; v <<= 1 }
        return count
    }

    private func mergeRoutes(_ a: [String], _ b: [String]) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for r in a + b where !seen.contains(r) { seen.insert(r); out.append(r) }
        return out
    }
}

private extension Int {
    func clamped(_ lo: Int, _ hi: Int) -> Int { Swift.max(lo, Swift.min(hi, self)) }
}

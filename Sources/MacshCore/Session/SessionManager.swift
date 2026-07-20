import Foundation
import Combine
import Darwin

@MainActor
public final class SessionManager: ObservableObject {
    @Published public private(set) var sessions: [RemoteSession] = []

    private let store: RemoteStore
    private let keychain: KeychainService
    private let mounter: Mounter
    private let logsDir: URL
    private let rcloneBinary: URL
    private let hostKeyVerifier: HostKeyVerifier?

    private var retryTasks: [UUID: Task<Void, Never>] = [:]
    private var healthTasks: [UUID: Task<Void, Never>] = [:]
    private var sessionCancellables: [UUID: AnyCancellable] = [:]
    /// Consecutive health-poll failures per remote before declaring death.
    private var healthFailStreak: [UUID: Int] = [:]

    private static let healthPollIntervalSeconds: UInt64 = 20
    private static let healthFailThreshold = 2

    public init(
        store: RemoteStore,
        keychain: KeychainService,
        mounter: Mounter,
        logsDir: URL,
        rcloneBinary: URL,
        hostKeyVerifier: HostKeyVerifier? = nil
    ) {
        self.store = store
        self.keychain = keychain
        self.mounter = mounter
        self.logsDir = logsDir
        self.rcloneBinary = rcloneBinary
        self.hostKeyVerifier = hostKeyVerifier
        try? FileManager.default.createDirectory(at: logsDir, withIntermediateDirectories: true)
    }

    public func reload() throws {
        let remotes = try store.load()
        let existingByID = Dictionary(uniqueKeysWithValues: sessions.map { ($0.id, $0) })
        let newSessions = remotes.map { existingByID[$0.id] ?? RemoteSession(remote: $0) }
        sessions = newSessions
        // Re-subscribe each session's status changes so the menu (which subscribes to
        // $sessions) rebuilds when a status flips. Without this, mount → unmount label
        // never updates because the array's reference doesn't change on transition.
        sessionCancellables.removeAll()
        for s in newSessions {
            sessionCancellables[s.id] = s.$status
                .dropFirst()
                .sink { [weak self] _ in
                    guard let self else { return }
                    // Re-publish the same array so subscribers of $sessions wake up.
                    self.sessions = self.sessions
                }
        }
    }

    /// Called once at app launch after `reload()` to mount every remote with autoMount=true.
    /// First reconciles stale mounts left behind by a prior instance that died via
    /// SIGKILL/crash — without this, every relaunch would pile up `<name>-1`,
    /// `<name>-2`, … entries in /Volumes since NetFS auto-numbers collisions.
    public func autoMountAll() {
        for session in sessions {
            let volname = mounter.volumeName(from: session.remote.name)
            mounter.reconcileStaleMount(volumeName: volname)
        }
        for session in sessions where session.remote.autoMount {
            session.wantsMounted = true
            scheduleMount(remoteID: session.id, attempt: 0)
        }
    }

    private func scheduleMount(remoteID: UUID, attempt: Int) {
        retryTasks[remoteID]?.cancel()
        retryTasks[remoteID] = Task { @MainActor [weak self] in
            guard let self else { return }
            guard let session = self.sessions.first(where: { $0.id == remoteID }) else { return }
            guard session.wantsMounted else { return }
            if attempt > 0 {
                session.transition(to: .reconnecting(attempt: attempt, reason: "retrying mount"))
            }
            do {
                // cancelRetries: false so this task is not cancelled by mount() itself.
                try await self.mount(remoteID: remoteID, cancelRetries: false)
                self.retryTasks[remoteID] = nil
            } catch {
                guard session.wantsMounted, !Task.isCancelled else { return }
                let nextAttempt = attempt + 1
                let delay = Self.backoffDelay(attempt: nextAttempt)
                guard delay > 0 else { return }
                session.transition(to: .reconnecting(attempt: nextAttempt, reason: String(describing: error)))
                try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
                if !Task.isCancelled, session.wantsMounted {
                    self.scheduleMount(remoteID: remoteID, attempt: nextAttempt)
                }
            }
        }
    }

    /// Exponential backoff: 1s, 5s, 30s, then 5min cap.
    nonisolated public static func backoffDelay(attempt: Int) -> TimeInterval {
        switch attempt {
        case 1: return 1
        case 2: return 5
        case 3: return 30
        case 4...: return 300
        default: return 0
        }
    }

    public func add(_ remote: Remote, sftpSecrets: SFTPSecrets? = nil, s3Secrets: S3Secrets? = nil, ftpSecrets: FTPSecrets? = nil) throws {
        if let s = sftpSecrets {
            if let pwd = s.password { try keychain.set(remoteID: remote.id, kind: .password, value: pwd) }
            if let pp = s.keyPassphrase { try keychain.set(remoteID: remote.id, kind: .keyPassphrase, value: pp) }
            if let keyPath = s.privateKeyPath { try keychain.set(remoteID: remote.id, kind: .privateKey, value: keyPath) }
        }
        if let s = s3Secrets {
            try keychain.set(remoteID: remote.id, kind: .s3AccessKeyID, value: s.accessKeyID)
            try keychain.set(remoteID: remote.id, kind: .s3SecretAccessKey, value: s.secretAccessKey)
        }
        if let s = ftpSecrets {
            try keychain.set(remoteID: remote.id, kind: .password, value: s.password)
        }
        var all = try store.load()
        all.append(remote)
        try store.save(all)
        try reload()
    }

    /// Updates an existing remote in `remotes.json`. Backend type cannot change.
    /// Secret fields (`SFTPSecrets.password`, `S3Secrets.accessKeyID`/`secretAccessKey`,
    /// `FTPSecrets.password`) are interpreted as "blank means keep existing": only
    /// non-nil and non-empty values overwrite the keychain. The session reference
    /// is preserved so an in-flight `.starting` status survives the update.
    public func update(_ remote: Remote, sftpSecrets: SFTPSecrets? = nil, s3Secrets: S3Secrets? = nil, ftpSecrets: FTPSecrets? = nil) throws {
        if let s = sftpSecrets {
            if let pwd = s.password, !pwd.isEmpty { try keychain.set(remoteID: remote.id, kind: .password, value: pwd) }
            if let pp = s.keyPassphrase, !pp.isEmpty { try keychain.set(remoteID: remote.id, kind: .keyPassphrase, value: pp) }
            if let keyPath = s.privateKeyPath, !keyPath.isEmpty { try keychain.set(remoteID: remote.id, kind: .privateKey, value: keyPath) }
        }
        if let s = s3Secrets {
            if !s.accessKeyID.isEmpty { try keychain.set(remoteID: remote.id, kind: .s3AccessKeyID, value: s.accessKeyID) }
            if !s.secretAccessKey.isEmpty { try keychain.set(remoteID: remote.id, kind: .s3SecretAccessKey, value: s.secretAccessKey) }
        }
        if let s = ftpSecrets, !s.password.isEmpty {
            try keychain.set(remoteID: remote.id, kind: .password, value: s.password)
        }
        var all = try store.load()
        guard let idx = all.firstIndex(where: { $0.id == remote.id }) else {
            throw NSError(domain: "macsh", code: 2, userInfo: [NSLocalizedDescriptionKey: "Remote not found"])
        }
        all[idx] = remote
        try store.save(all)
        // Mutate the existing RemoteSession's `remote` in place rather than recreating
        // it, so any subscribers (and the session's status) are preserved. Then re-emit.
        if let s = sessions.first(where: { $0.id == remote.id }) {
            s.remote = remote
            sessions = sessions
        } else {
            try reload()
        }
    }

    public func delete(_ remoteID: UUID) throws {
        retryTasks[remoteID]?.cancel()
        retryTasks[remoteID] = nil
        if let session = sessions.first(where: { $0.id == remoteID }) {
            switch session.status {
            case .mounted, .starting, .reconnecting:
                try? unmount(remoteID: remoteID)
            default:
                break
            }
        }
        try? keychain.delete(remoteID: remoteID, kind: .password)
        try? keychain.delete(remoteID: remoteID, kind: .keyPassphrase)
        try? keychain.delete(remoteID: remoteID, kind: .privateKey)
        try? keychain.delete(remoteID: remoteID, kind: .localServePassword)
        var all = try store.load()
        all.removeAll { $0.id == remoteID }
        try store.save(all)
        try reload()
    }

    /// Mount a remote. Prefer this async entry so callers can leave the main thread free.
    /// - Parameter cancelRetries: When true (default, manual Mount), cancel any silent remount task first.
    public func mount(remoteID: UUID, cancelRetries: Bool = true) async throws {
        guard let session = sessions.first(where: { $0.id == remoteID }) else { return }
        // Cancel an in-flight silent retry so manual Mount is the sole owner.
        if cancelRetries {
            retryTasks[remoteID]?.cancel()
            retryTasks[remoteID] = nil
        }
        stopHealthPoll(remoteID: remoteID)

        if case .mounted = session.status {
            return
        }

        session.wantsMounted = true
        session.transition(to: .starting)

        let remote = session.remote
        var ephemeralKeyURL: URL? = nil
        var spawnedProcess: Process? = nil
        var configDirURL: URL? = nil
        var envOverrides: [String: String] = [:]
        var bundle = BackendSecrets()
        var remotePath: String

        do {
            switch remote.backend {
            case .sftp(let sftp):
                let password = try keychain.get(remoteID: remote.id, kind: .password)
                var resolvedKeyPath: String? = nil
                switch sftp.authKind {
                case .password: break
                case .keyFile:
                    resolvedKeyPath = try keychain.get(remoteID: remote.id, kind: .privateKey)
                case .generatedKey:
                    if let pem = try keychain.get(remoteID: remote.id, kind: .privateKey) {
                        let url = FileManager.default.temporaryDirectory
                            .appendingPathComponent("macsh-key-\(remote.id.uuidString)")
                        try pem.write(to: url, atomically: true, encoding: .utf8)
                        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
                        ephemeralKeyURL = url
                        resolvedKeyPath = url.path
                    }
                }
                let keyPassphrase = try keychain.get(remoteID: remote.id, kind: .keyPassphrase)
                bundle.sftp = SFTPSecrets(
                    password: password,
                    privateKeyPath: resolvedKeyPath,
                    keyPassphrase: keyPassphrase
                )
                if sftp.authKind == .password, let p = password {
                    envOverrides[RcloneConfigBuilder.passwordEnvVar(remoteID: remote.id)] =
                        try RcloneProcess.obscure(plaintext: p, binary: rcloneBinary)
                }
                if let pp = keyPassphrase, !pp.isEmpty {
                    envOverrides[RcloneConfigBuilder.keyFilePassEnvVar(remoteID: remote.id)] =
                        try RcloneProcess.obscure(plaintext: pp, binary: rcloneBinary)
                }
                if let verifier = hostKeyVerifier {
                    try verifier.ensureKnown(host: sftp.host, port: sftp.port)
                }
                remotePath = sftp.remotePath

            case .s3(let s3):
                guard let access = try keychain.get(remoteID: remote.id, kind: .s3AccessKeyID),
                      let secret = try keychain.get(remoteID: remote.id, kind: .s3SecretAccessKey) else {
                    throw RcloneConfigError.missingS3Credentials
                }
                bundle.s3 = S3Secrets(accessKeyID: access, secretAccessKey: secret)
                envOverrides[RcloneConfigBuilder.s3SecretEnvVar(remoteID: remote.id)] = secret
                remotePath = s3.prefix.isEmpty ? s3.bucket : "\(s3.bucket)/\(s3.prefix)"

            case .ftp(let ftp):
                guard let password = try keychain.get(remoteID: remote.id, kind: .password) else {
                    throw RcloneConfigError.missingFTPPassword
                }
                bundle.ftp = FTPSecrets(password: password)
                envOverrides[RcloneConfigBuilder.passwordEnvVar(remoteID: remote.id)] =
                    try RcloneProcess.obscure(plaintext: password, binary: rcloneBinary)
                remotePath = ftp.remotePath
            }

            let configText = try RcloneConfigBuilder.build(
                remote: remote,
                secrets: bundle,
                knownHostsPath: hostKeyVerifier?.knownHostsPath
            )
            let logURL = logsDir.appendingPathComponent("\(remote.id.uuidString).log")
            let runner = RcloneProcess(binary: rcloneBinary, logFile: logURL)
            let volname = mounter.volumeName(from: remote.name)
            let spawned: RcloneProcess.Spawned
            switch remote.mountProtocol {
            case .webdav:
                spawned = try runner.spawnWebDAVServe(
                    remoteName: RcloneConfigBuilder.sectionName,
                    remotePath: remotePath,
                    configText: configText,
                    baseurl: "/\(volname)",
                    liveUpdates: remote.liveUpdates,
                    envOverrides: envOverrides
                )
            case .nfs:
                spawned = try runner.spawnNFSServe(
                    remoteName: RcloneConfigBuilder.sectionName,
                    remotePath: remotePath,
                    configText: configText,
                    liveUpdates: remote.liveUpdates,
                    envOverrides: envOverrides
                )
            }
            spawnedProcess = spawned.process
            configDirURL = spawned.configDirURL

            // Blocking port wait + NetFS off the main actor so the menu stays responsive.
            let port = spawned.port
            let user = spawned.user
            let password = spawned.password
            let mountProtocol = remote.mountProtocol
            let remoteName = remote.name
            let mountpoint: String = try await Task.detached(priority: .userInitiated) { [mounter] in
                try Self.waitForPort(port, timeout: 5.0)
                switch mountProtocol {
                case .webdav:
                    return try mounter.mountWebDAV(
                        host: "127.0.0.1",
                        port: port,
                        baseurl: "/\(volname)",
                        user: user,
                        password: password
                    )
                case .nfs:
                    let mp = try mounter.resolveMountpoint(name: remoteName)
                    try mounter.mountNFS(host: "127.0.0.1", port: port, exportPath: "/", name: remoteName, mountpoint: mp)
                    return mp
                }
            }.value

            session.rcloneProcess = spawned.process
            session.mountpoint = mountpoint
            session.servePort = spawned.port
            session.configDirURL = spawned.configDirURL
            session.ephemeralKeyURL = ephemeralKeyURL
            session.wantsMounted = true
            session.transition(to: .mounted(at: mountpoint))

            attachTerminationHandler(remoteID: remoteID, process: spawned.process)
            startHealthPoll(remoteID: remoteID)
        } catch {
            // P0-4: always kill rclone if spawn already succeeded.
            // Clear handler first so a late termination callback cannot start a remount.
            if let proc = spawnedProcess {
                proc.terminationHandler = nil
                if proc.isRunning { proc.terminate() }
            }
            if let dir = configDirURL {
                try? FileManager.default.removeItem(at: dir)
            }
            if let url = ephemeralKeyURL { try? FileManager.default.removeItem(at: url) }
            session.rcloneProcess = nil
            session.mountpoint = nil
            session.servePort = nil
            session.configDirURL = nil
            session.ephemeralKeyURL = nil
            session.transition(to: .failed(reason: String(describing: error)))
            throw error
        }
    }

    public func unmount(remoteID: UUID) throws {
        guard let session = sessions.first(where: { $0.id == remoteID }) else { return }
        session.wantsMounted = false
        retryTasks[remoteID]?.cancel()
        retryTasks[remoteID] = nil
        stopHealthPoll(remoteID: remoteID)
        healthFailStreak[remoteID] = nil

        teardownBackend(session: session, unmountVolume: true)
        session.transition(to: .idle)
    }

    public func shutdownAll() {
        for (_, task) in retryTasks { task.cancel() }
        retryTasks.removeAll()
        for id in healthTasks.keys { stopHealthPoll(remoteID: id) }
        for session in sessions {
            session.wantsMounted = false
            switch session.status {
            case .mounted, .starting, .reconnecting:
                try? unmount(remoteID: session.id)
            default:
                break
            }
        }
    }

    public func logURL(for remoteID: UUID) -> URL {
        logsDir.appendingPathComponent("\(remoteID.uuidString).log")
    }

    // MARK: - Health + death recovery

    private func attachTerminationHandler(remoteID: UUID, process: Process) {
        process.terminationHandler = { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self else { return }
                // Intentional stops nil the handler before terminate(); any fire here is unexpected death.
                self.handleBackendDeath(remoteID: remoteID, reason: "rclone exited")
            }
        }
    }

    private func startHealthPoll(remoteID: UUID) {
        stopHealthPoll(remoteID: remoteID)
        healthFailStreak[remoteID] = 0
        healthTasks[remoteID] = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: Self.healthPollIntervalSeconds * 1_000_000_000)
                guard !Task.isCancelled, let self else { return }
                guard let session = self.sessions.first(where: { $0.id == remoteID }) else { return }
                guard case .mounted = session.status else { return }
                if self.isHealthy(session) {
                    self.healthFailStreak[remoteID] = 0
                } else {
                    let streak = (self.healthFailStreak[remoteID] ?? 0) + 1
                    self.healthFailStreak[remoteID] = streak
                    if streak >= Self.healthFailThreshold {
                        self.handleBackendDeath(remoteID: remoteID, reason: "health check failed")
                        return
                    }
                }
            }
        }
    }

    private func stopHealthPoll(remoteID: UUID) {
        healthTasks[remoteID]?.cancel()
        healthTasks[remoteID] = nil
    }

    private func isHealthy(_ session: RemoteSession) -> Bool {
        guard let proc = session.rcloneProcess, proc.isRunning else { return false }
        guard let port = session.servePort else { return false }
        if !Self.tcpConnects(host: "127.0.0.1", port: port) { return false }
        if let mp = session.mountpoint {
            // Volume must still be present; if Finder already ejected it, recover.
            var isDir: ObjCBool = false
            if !FileManager.default.fileExists(atPath: mp, isDirectory: &isDir) {
                return false
            }
        }
        return true
    }

    private func handleBackendDeath(remoteID: UUID, reason: String) {
        guard let session = sessions.first(where: { $0.id == remoteID }) else { return }
        // Ignore after user unmount, or when a remount is already in flight without a live process.
        switch session.status {
        case .idle:
            return
        case .reconnecting where session.rcloneProcess == nil:
            // scheduleMount already owns recovery; avoid stacked scheduleMount calls.
            return
        case .starting where session.rcloneProcess == nil:
            // Mount attempt still running; let its catch path handle failure.
            return
        default:
            break
        }

        stopHealthPoll(remoteID: remoteID)
        healthFailStreak[remoteID] = nil
        teardownBackend(session: session, unmountVolume: true)

        if session.wantsMounted {
            session.transition(to: .reconnecting(attempt: 0, reason: reason))
            scheduleMount(remoteID: remoteID, attempt: 0)
        } else {
            // Explicit unmount already transitions to .idle; only use .failed for unexpected death.
            session.transition(to: .failed(reason: reason))
        }
    }

    private func teardownBackend(session: RemoteSession, unmountVolume: Bool) {
        if unmountVolume, let mp = session.mountpoint {
            try? mounter.unmount(mountpoint: mp)
        }
        if let proc = session.rcloneProcess {
            // Detach handler before SIGTERM so intentional stops do not re-enter handleBackendDeath.
            proc.terminationHandler = nil
            if proc.isRunning {
                proc.terminate()
            }
        }
        if let dir = session.configDirURL {
            try? FileManager.default.removeItem(at: dir)
        }
        if let url = session.ephemeralKeyURL {
            try? FileManager.default.removeItem(at: url)
        }
        session.rcloneProcess = nil
        session.mountpoint = nil
        session.servePort = nil
        session.configDirURL = nil
        session.ephemeralKeyURL = nil
    }

    // MARK: - Networking helpers

    nonisolated private static func waitForPort(_ port: Int, timeout: TimeInterval) throws {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if tcpConnects(host: "127.0.0.1", port: port) { return }
            Thread.sleep(forTimeInterval: 0.1)
        }
        throw NSError(domain: "macsh", code: 1, userInfo: [NSLocalizedDescriptionKey: "rclone serve did not open port \(port) within \(timeout)s"])
    }

    nonisolated private static func tcpConnects(host: String, port: Int) -> Bool {
        let sock = socket(AF_INET, SOCK_STREAM, 0)
        if sock < 0 { return false }
        defer { close(sock) }

        // Non-blocking connect with short timeout so health checks don't hang.
        let flags = fcntl(sock, F_GETFL, 0)
        _ = fcntl(sock, F_SETFL, flags | O_NONBLOCK)

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(port).bigEndian
        addr.sin_addr.s_addr = inet_addr(host)

        let result = withUnsafePointer(to: &addr) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.connect(sock, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if result == 0 { return true }
        if errno != EINPROGRESS { return false }

        var pfd = pollfd(fd: sock, events: Int16(POLLOUT), revents: 0)
        let pr = poll(&pfd, 1, 500)
        guard pr > 0 else { return false }
        var soError: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &soError, &len)
        return soError == 0
    }
}

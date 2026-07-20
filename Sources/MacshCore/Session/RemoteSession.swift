import Foundation
import Combine

public final class RemoteSession: ObservableObject, Identifiable {
    public internal(set) var remote: Remote
    @Published public private(set) var status: SessionStatus = .idle

    /// Populated while in `.mounted` or `.starting`. Set by SessionManager.
    public internal(set) var rcloneProcess: Process?
    public internal(set) var mountpoint: String?
    /// Local port of `rclone serve` while active.
    public internal(set) var servePort: Int?
    /// Local WebDAV basic-auth creds for health PROPFIND (not the remote SFTP password).
    public internal(set) var webDAVUser: String?
    public internal(set) var webDAVPassword: String?
    /// Temp dir holding the per-mount rclone.conf; deleted on unmount/death.
    public internal(set) var configDirURL: URL?
    /// For generated-key remotes, the temp file containing the decrypted private key
    /// while the mount is active. Cleaned up on unmount.
    public internal(set) var ephemeralKeyURL: URL?
    /// User/auto wants the volume up. Cleared only on explicit Unmount (not on death).
    public internal(set) var wantsMounted: Bool = false
    /// Bumped on each mount attempt / unmount so in-flight mounts can detect cancellation.
    public internal(set) var mountGeneration: UInt64 = 0

    public var id: UUID { remote.id }

    public init(remote: Remote) {
        self.remote = remote
    }

    public func transition(to newStatus: SessionStatus) {
        if Thread.isMainThread {
            self.status = newStatus
        } else {
            DispatchQueue.main.async { [weak self] in
                self?.status = newStatus
            }
        }
    }
}

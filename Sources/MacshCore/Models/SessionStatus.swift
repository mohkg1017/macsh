import Foundation

public enum SessionStatus: Equatable {
    case idle
    case starting
    case mounted(at: String)
    /// Backend died or health poll failed; silent remount in progress.
    case reconnecting(attempt: Int, reason: String)
    case failed(reason: String)
}

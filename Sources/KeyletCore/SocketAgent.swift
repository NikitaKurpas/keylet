import Darwin
import Dispatch
import Foundation

/// Enforces the path and directory permissions required for a private Unix socket.
public enum SocketSafety {
  public static func validate(path: String) throws {
    guard path.hasPrefix("/"), !path.utf8.contains(0),
      path.utf8.count < MemoryLayout.size(ofValue: sockaddr_un().sun_path)
    else { throw AgentError.invalidPath }
  }

  /// Rejects symlinks and directories not owned by this user with mode 0700.
  public static func directory(_ path: String) throws {
    var info = stat()
    guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR, info.st_uid == geteuid(),
      (info.st_mode & 0o777) == 0o700
    else { throw AgentError.invalidPath }
  }
}

private final class StopFlag: @unchecked Sendable {
  private let lock = NSLock()
  private var stopped = false
  func stop() {
    lock.withLock { stopped = true }
  }
  var isStopped: Bool {
    lock.withLock { stopped }
  }
}

public enum SocketAgent {
  public static var defaultSocket: String {
    (getpwuid(geteuid()).map { String(cString: $0.pointee.pw_dir) } ?? NSHomeDirectory())
      + "/Library/Containers/me.kurpas.keylet/Data/agent/socket.ssh"
  }

  /// Serves available keys until SIGINT/SIGTERM, optionally restricted to one UUID.
  public static func run(path: String, store: KeyStore, id: UUID? = nil) throws {
    let audit = try AuditStore()
    try prepareEndpoint(path)
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { throw AgentError.io(errno) }
    defer { close(fd) }
    try bind(fd, to: path)
    var owned = stat()
    guard lstat(path, &owned) == 0 else { throw AgentError.io(errno) }
    defer { removeEndpoint(path, owned: owned) }
    guard chmod(path, 0o600) == 0, listen(fd, 8) == 0, fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else {
      throw AgentError.io(errno)
    }
    let stop = StopFlag()
    let signals = installSignalHandlers(listener: fd, stop: stop)
    defer { for source in signals { source.cancel() } }
    try serve(listener: fd, stop: stop) { request, peer in
      let keys = store.inventory().agentKeys(id: id)
      return AuditedAgentProtocol.reply(to: request, keys: keys, peer: peer, audit: audit) {
        data, record in
        return try store.sign(data, key: record)
      }
    }
  }

  /// Creates only the immediate socket directory and refuses existing endpoints.
  private static func prepareEndpoint(_ path: String) throws {
    try SocketSafety.validate(path: path)
    let directory = URL(fileURLWithPath: path).deletingLastPathComponent().path
    if !FileManager.default.fileExists(atPath: directory) {
      guard mkdir(directory, 0o700) == 0 else { throw AgentError.io(errno) }
    }
    try SocketSafety.directory(directory)
    var existing = stat()
    guard lstat(path, &existing) != 0 && errno == ENOENT else { throw AgentError.invalidPath }
  }

  private static func bind(_ fd: Int32, to path: String) throws {
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    path.withCString { source in
      withUnsafeMutablePointer(to: &address.sun_path) { pointer in
        pointer.withMemoryRebound(to: CChar.self, capacity: 104) { destination in
          _ = strncpy(destination, source, path.utf8.count + 1)
        }
      }
    }
    let bound = withUnsafePointer(to: &address) {
      $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
      }
    }
    guard bound == 0 else { throw AgentError.io(errno) }
  }

  private static func removeEndpoint(_ path: String, owned: stat) {
    var current = stat()
    guard lstat(path, &current) == 0,
      current.st_dev == owned.st_dev, current.st_ino == owned.st_ino
    else { return }
    _ = unlink(path)
  }

  private static func installSignalHandlers(
    listener fd: Int32, stop: StopFlag
  ) -> [DispatchSourceSignal] {
    signal(SIGINT, SIG_IGN)
    signal(SIGTERM, SIG_IGN)
    return [SIGINT, SIGTERM].map { number -> DispatchSourceSignal in
      let source = DispatchSource.makeSignalSource(signal: number, queue: DispatchQueue.global())
      source.setEventHandler {
        stop.stop()
        _ = shutdown(fd, SHUT_RDWR)
      }
      source.resume()
      return source
    }
  }

  private static func serve(
    listener fd: Int32, stop: StopFlag, reply: (Data, AuditPeer) -> Data
  ) throws {
    let sessions = SocketSessions()
    defer { sessions.closeAll() }
    while !stop.isStopped {
      var listener = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
      let ready = poll(&listener, 1, 0)
      if stop.isStopped { break }
      if ready < 0 && errno != EINTR { throw AgentError.io(errno) }
      if ready > 0 && listener.revents & Int16(POLLIN) != 0 {
        let client = accept(fd, nil, nil)
        if client >= 0 {
          do { try sessions.add(client) } catch { close(client) }
        } else if errno != EINTR && errno != EAGAIN {
          throw AgentError.io(errno)
        }
      }
      try sessions.stepWithPeer(reply: reply)
    }
  }
}

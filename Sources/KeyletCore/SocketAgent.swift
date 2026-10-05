import Darwin
import Dispatch
import Foundation

public enum SocketSafety {
  public static func validate(path: String) throws {
    guard path.hasPrefix("/"), !path.utf8.contains(0),
      path.utf8.count < MemoryLayout.size(ofValue: sockaddr_un().sun_path)
    else { throw AgentError.invalidPath }
  }
  public static func directory(_ path: String) throws {
    var info = stat()
    guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR, info.st_uid == geteuid(),
      (info.st_mode & 0o777) == 0o700
    else { throw AgentError.invalidPath }
  }
}
private final class StopFlag: @unchecked Sendable {
  let lock = NSLock()
  private var stopped = false
  func stop() {
    lock.lock()
    stopped = true
    lock.unlock()
  }
  var value: Bool {
    lock.lock()
    defer { lock.unlock() }
    return stopped
  }
}
public enum SocketAgent {
  public static var defaultSocket: String {
    (getpwuid(geteuid()).map { String(cString: $0.pointee.pw_dir) } ?? NSHomeDirectory())
      + "/Library/Containers/me.kurpas.keylet/Data/agent/socket.ssh"
  }
  public static func run(path: String, store: KeyStore, id: UUID) throws {
    let audit = try AuditStore()
    try SocketSafety.validate(path: path)
    let directory = URL(fileURLWithPath: path).deletingLastPathComponent().path
    // Only the immediate private directory is created. Its parent must already exist.
    if !FileManager.default.fileExists(atPath: directory) {
      guard mkdir(directory, 0o700) == 0 else { throw AgentError.io(errno) }
    }
    try SocketSafety.directory(directory)
    var existing = stat()
    guard lstat(path, &existing) != 0 && errno == ENOENT else { throw AgentError.invalidPath }
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { throw AgentError.io(errno) }
    defer { close(fd) }
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
    var owned = stat()
    guard lstat(path, &owned) == 0 else { throw AgentError.io(errno) }
    defer {
      var now = stat()
      if lstat(path, &now) == 0, now.st_dev == owned.st_dev, now.st_ino == owned.st_ino {
        _ = unlink(path)
      }
    }
    guard chmod(path, 0o600) == 0, listen(fd, 8) == 0, fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else {
      throw AgentError.io(errno)
    }
    let stop = StopFlag()
    signal(SIGINT, SIG_IGN)
    signal(SIGTERM, SIG_IGN)
    let signals = [SIGINT, SIGTERM].map { number -> DispatchSourceSignal in
      let source = DispatchSource.makeSignalSource(signal: number, queue: DispatchQueue.global())
      source.setEventHandler {
        stop.stop()
        _ = shutdown(fd, SHUT_RDWR)
      }
      source.resume()
      return source
    }
    defer { for source in signals { source.cancel() } }
    // ponytail: bounded nonblocking sessions; idle retained OpenSSH FDs stay usable.
    let sessions = SocketSessions()
    defer { sessions.closeAll() }
    while !stop.value {
      var listener = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
      let ready = poll(&listener, 1, 0)
      if stop.value { break }
      if ready < 0 && errno != EINTR { throw AgentError.io(errno) }
      if ready > 0 && listener.revents & Int16(POLLIN) != 0 {
        let client = accept(fd, nil, nil)
        if client >= 0 {
          do { try sessions.add(client) } catch { close(client) }
        } else if errno != EINTR && errno != EAGAIN {
          throw AgentError.io(errno)
        }
      }
      try sessions.stepWithPeer { request, peer in
        let inventory = store.inventory()
        let record = inventory.keys.first { $0.id == id }
        return AuditedAgentProtocol.reply(to: request, key: record, peer: peer, audit: audit) {
          data in
          guard let record, record.policy != .userPresence else { throw AgentError.unavailable }
          return try store.sign(data, key: record)
        }
      }
    }
  }

}

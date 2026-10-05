import Darwin
import Foundation

// One event loop owns all descriptors. Idle clients occupy bounded slots, never block others,
// and acquire a fresh absolute deadline only when the first byte of a request arrives.
final class SocketSessions {
  private struct Connection {
    var peer = AuditPeer()
    var input = Data()
    var expected: Int?
    var output = Data()
    var sent = 0
    var deadline: TimeInterval?
    var capacity: Int { (expected ?? 4) - input.count }
    var events: Int16 { Int16(output.isEmpty ? POLLIN : POLLOUT) }
  }
  private var connections: [Int32: Connection] = [:]
  let maximumConnections: Int
  let frameTimeout: TimeInterval
  init(maximumConnections: Int = 16, frameTimeout: TimeInterval = 8) {
    self.maximumConnections = maximumConnections
    self.frameTimeout = frameTimeout
  }
  var count: Int { connections.count }
  func add(_ fd: Int32) throws {
    guard connections.count < maximumConnections, connections[fd] == nil else {
      throw AgentError.unavailable
    }
    var uid: uid_t = 0
    var gid: gid_t = 0
    var one: Int32 = 1
    guard getpeereid(fd, &uid, &gid) == 0, uid == geteuid(),
      fcntl(fd, F_SETFL, O_NONBLOCK) == 0,
      setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size)) == 0
    else { throw AgentError.unavailable }
    var pid: Int32 = 0
    var size = socklen_t(MemoryLayout<Int32>.size)
    let hasPID =
      getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &size) == 0
      && size == socklen_t(MemoryLayout<Int32>.size) && pid > 0
    connections[fd] = Connection(peer: AuditPeer(uid: uid, gid: gid, pid: hasPID ? pid : nil))
  }
  func closeAll() {
    for fd in connections.keys { close(fd) }
    connections.removeAll()
  }
  deinit { closeAll() }
  private func remove(_ fd: Int32) {
    close(fd)
    connections.removeValue(forKey: fd)
  }
  func step(waitMilliseconds: Int32 = 100, reply: (Data) -> Data) throws {
    try stepWithPeer(waitMilliseconds: waitMilliseconds) { payload, _ in reply(payload) }
  }
  func stepWithPeer(waitMilliseconds: Int32 = 100, reply: (Data, AuditPeer) -> Data) throws {
    var descriptors = connections.map { pollfd(fd: $0.key, events: $0.value.events, revents: 0) }
    let result = descriptors.withUnsafeMutableBufferPointer {
      poll($0.baseAddress, nfds_t($0.count), waitMilliseconds)
    }
    if result < 0 {
      if errno == EINTR { return }
      throw AgentError.io(errno)
    }
    for descriptor in descriptors {
      let fd = descriptor.fd
      guard var connection = connections[fd] else { continue }
      let now = ProcessInfo.processInfo.systemUptime
      if let deadline = connection.deadline, now >= deadline {
        remove(fd)
        continue
      }
      guard descriptor.revents != 0 else { continue }
      if descriptor.revents & Int16(POLLERR | POLLNVAL) != 0 {
        remove(fd)
        continue
      }
      do {
        if !connection.output.isEmpty {
          guard descriptor.revents & Int16(POLLOUT) != 0 else {
            remove(fd)
            continue
          }
          let n = connection.output.withUnsafeBytes {
            Darwin.write(
              fd, $0.baseAddress!.advanced(by: connection.sent),
              connection.output.count - connection.sent)
          }
          if n < 0 && (errno == EINTR || errno == EAGAIN) { continue }
          guard n > 0 else { throw AgentError.unavailable }
          connection.sent += n
          if connection.sent == connection.output.count {
            // Response complete: no idle deadline or request-count cutoff.
            connection = Connection(peer: connection.peer)
          }
        } else {
          var bytes = [UInt8](repeating: 0, count: min(8192, connection.capacity))
          let n = bytes.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!, $0.count) }
          if n < 0 && (errno == EINTR || errno == EAGAIN) { continue }
          guard n > 0 else { throw AgentError.unavailable }
          if connection.deadline == nil { connection.deadline = now + frameTimeout }
          connection.input.append(contentsOf: bytes.prefix(n))
          if connection.expected == nil && connection.input.count == 4 {
            var reader = SSHReader(connection.input)
            let size = Int(try reader.uint32())
            guard size > 0, size <= SSHWire.maximumFrame else { throw AgentError.invalidRequest }
            connection.expected = size
            connection.input.removeAll(keepingCapacity: true)
          } else if let expected = connection.expected, connection.input.count == expected {
            connection.output = SSHWire.string(reply(connection.input, connection.peer))
            guard connection.output.count <= SSHWire.maximumFrame + 4 else {
              throw AgentError.invalidRequest
            }
            connection.input.removeAll(keepingCapacity: false)
          }
        }
        connections[fd] = connection
      } catch { remove(fd) }
    }
  }
}

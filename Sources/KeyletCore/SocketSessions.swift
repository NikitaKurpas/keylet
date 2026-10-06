import Darwin
import Foundation

/// Owns bounded client connections; request deadlines start at the first received byte.
final class SocketSessions {
  private struct Connection {
    var receivedData = Data()
    var payloadLength: Int?
    var response = Data()
    var bytesSent = 0
    var deadline: TimeInterval?
    var remainingReadBytes: Int { (payloadLength ?? 4) - receivedData.count }
    var pollEvents: Int16 { Int16(response.isEmpty ? POLLIN : POLLOUT) }

    mutating func writeResponse(to fd: Int32) throws {
      let bytesWritten = response.withUnsafeBytes {
        Darwin.write(fd, $0.baseAddress!.advanced(by: bytesSent), response.count - bytesSent)
      }
      if bytesWritten < 0 && (errno == EINTR || errno == EAGAIN) { return }
      guard bytesWritten > 0 else { throw AgentError.unavailable }
      bytesSent += bytesWritten
      if bytesSent == response.count {
        // Response complete: no idle deadline or request-count cutoff.
        self = Connection()
      }
    }

    mutating func readRequest(
      from fd: Int32, now: TimeInterval, timeout: TimeInterval,
      reply: (Data) -> Data
    ) throws {
      var bytes = [UInt8](repeating: 0, count: min(8192, remainingReadBytes))
      let bytesRead = bytes.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!, $0.count) }
      if bytesRead < 0 && (errno == EINTR || errno == EAGAIN) { return }
      guard bytesRead > 0 else { throw AgentError.unavailable }
      if deadline == nil { deadline = now + timeout }
      receivedData.append(contentsOf: bytes.prefix(bytesRead))
      if payloadLength == nil && receivedData.count == 4 {
        var reader = SSHReader(receivedData)
        let payloadSize = Int(try reader.uint32())
        guard payloadSize > 0, payloadSize <= SSHWire.maximumFrame else {
          throw AgentError.invalidRequest
        }
        payloadLength = payloadSize
        receivedData.removeAll(keepingCapacity: true)
      } else if let payloadLength, receivedData.count == payloadLength {
        response = SSHWire.string(reply(receivedData))
        guard response.count <= SSHWire.maximumFrame + 4 else {
          throw AgentError.invalidRequest
        }
        receivedData.removeAll(keepingCapacity: false)
      }
    }
  }
  private var connections: [Int32: Connection] = [:]
  let maximumConnections: Int
  let frameTimeout: TimeInterval
  init(maximumConnections: Int = 16, frameTimeout: TimeInterval = 8) {
    self.maximumConnections = maximumConnections
    self.frameTimeout = frameTimeout
  }
  var count: Int { connections.count }
  /// Takes ownership after successful admission; the caller closes rejected descriptors.
  func add(_ fd: Int32) throws {
    guard connections.count < maximumConnections, connections[fd] == nil else {
      throw AgentError.unavailable
    }
    try prepareClient(fd)
    connections[fd] = Connection()
  }

  private func prepareClient(_ fd: Int32) throws {
    var uid: uid_t = 0
    var gid: gid_t = 0
    var one: Int32 = 1
    guard getpeereid(fd, &uid, &gid) == 0, uid == geteuid(),
      fcntl(fd, F_SETFL, O_NONBLOCK) == 0,
      setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size)) == 0
    else { throw AgentError.unavailable }
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

  /// Polls once, advances ready clients, and closes expired or failed connections.
  func step(waitMilliseconds: Int32 = 100, reply: (Data) -> Data) throws {
    var descriptors = connections.map {
      pollfd(fd: $0.key, events: $0.value.pollEvents, revents: 0)
    }
    let result = descriptors.withUnsafeMutableBufferPointer {
      poll($0.baseAddress, nfds_t($0.count), waitMilliseconds)
    }
    if result < 0 {
      if errno == EINTR { return }
      throw AgentError.io(errno)
    }
    for descriptor in descriptors { service(descriptor, reply: reply) }
  }

  private func service(_ descriptor: pollfd, reply: (Data) -> Data) {
    let fd = descriptor.fd
    guard var connection = connections[fd] else { return }
    let now = ProcessInfo.processInfo.systemUptime
    if let deadline = connection.deadline, now >= deadline {
      remove(fd)
      return
    }
    guard descriptor.revents != 0 else { return }
    if descriptor.revents & Int16(POLLERR | POLLNVAL) != 0 {
      remove(fd)
      return
    }
    do {
      if !connection.response.isEmpty {
        guard descriptor.revents & Int16(POLLOUT) != 0 else {
          remove(fd)
          return
        }
        try connection.writeResponse(to: fd)
      } else {
        try connection.readRequest(from: fd, now: now, timeout: frameTimeout, reply: reply)
      }
      connections[fd] = connection
    } catch { remove(fd) }
  }
}

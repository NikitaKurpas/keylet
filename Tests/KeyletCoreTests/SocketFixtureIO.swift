import Darwin
import Foundation

@testable import KeyletCore

// Test-side client transport helper; production framing lives in SocketSessions.
enum SocketIO {
  static func readFrame(_ fd: Int32, deadline: TimeInterval) throws -> Data? {
    let header = try read(fd, count: 4, deadline: deadline)
    if header.isEmpty { return nil }
    var reader = SSHReader(header)
    let size = Int(try reader.uint32())
    guard size > 0, size <= SSHWire.maximumFrame else { throw AgentError.invalidRequest }
    let payload = try read(fd, count: size, deadline: deadline)
    guard payload.count == size else { throw AgentError.invalidRequest }
    return payload
  }
  private static func wait(_ fd: Int32, event: Int16, deadline: TimeInterval) throws {
    while true {
      let remaining = deadline - ProcessInfo.processInfo.systemUptime
      guard remaining > 0 else { throw AgentError.unavailable }
      var descriptor = pollfd(fd: fd, events: event, revents: 0)
      let result = poll(&descriptor, 1, Int32(ceil(remaining * 1000)))
      if result < 0 && errno == EINTR { continue }
      guard result > 0, descriptor.revents & event != 0 else { throw AgentError.unavailable }
      return
    }
  }
  private static func read(_ fd: Int32, count: Int, deadline: TimeInterval) throws -> Data {
    var bytes = [UInt8](repeating: 0, count: count)
    var offset = 0
    while offset < count {
      try wait(fd, event: Int16(POLLIN), deadline: deadline)
      let n = bytes.withUnsafeMutableBytes {
        Darwin.read(fd, $0.baseAddress!.advanced(by: offset), count - offset)
      }
      if n == 0 {
        if offset == 0 { return Data() }
        throw AgentError.invalidRequest
      }
      if n < 0 {
        if errno == EINTR || errno == EAGAIN { continue }
        throw AgentError.io(errno)
      }
      offset += n
    }
    return Data(bytes)
  }
  static func write(_ fd: Int32, data: Data, deadline: TimeInterval) throws {
    var offset = 0
    while offset < data.count {
      try wait(fd, event: Int16(POLLOUT), deadline: deadline)
      let n = data.withUnsafeBytes {
        Darwin.write(fd, $0.baseAddress!.advanced(by: offset), data.count - offset)
      }
      if n < 0 && (errno == EINTR || errno == EAGAIN) { continue }
      guard n > 0 else { throw AgentError.io(errno) }
      offset += n
    }
  }
}

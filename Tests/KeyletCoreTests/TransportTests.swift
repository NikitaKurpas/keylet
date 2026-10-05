import Darwin
import Dispatch
import Foundation
import Testing

@testable import KeyletCore

// Kernel-local socketpairs only. No listening agent, key store or credentials.
final class Pair: @unchecked Sendable {
  let reader: Int32
  let writer: Int32
  init() throws {
    var fds: [Int32] = [0, 0]
    guard socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else { throw AgentError.io(errno) }
    reader = fds[0]
    writer = fds[1]
    guard fcntl(reader, F_SETFL, O_NONBLOCK) == 0 else { throw AgentError.io(errno) }
  }
  deinit {
    close(reader)
    close(writer)
  }
  func send(_ data: Data) throws {
    let n = data.withUnsafeBytes { Darwin.write(writer, $0.baseAddress!, data.count) }
    guard n == data.count else { throw AgentError.io(errno) }
  }
}
@Test func coalescedFramesRemainDistinct() throws {
  let pair = try Pair()
  try pair.send(SSHWire.string(Data([11])) + SSHWire.string(Data([17])))
  let deadline = ProcessInfo.processInfo.systemUptime + 1
  #expect(try SocketIO.readFrame(pair.reader, deadline: deadline) == Data([11]))
  #expect(try SocketIO.readFrame(pair.reader, deadline: deadline) == Data([17]))
}
@Test func fragmentedHeaderAndPayload() throws {
  let pair = try Pair()
  let frame = SSHWire.string(Data([11, 1, 2, 3]))
  let done = DispatchSemaphore(value: 0)
  DispatchQueue.global().async {
    defer { done.signal() }
    for byte in frame {
      try? pair.send(Data([byte]))
      usleep(1000)
    }
  }
  #expect(
    try SocketIO.readFrame(pair.reader, deadline: ProcessInfo.processInfo.systemUptime + 1)
      == Data([11, 1, 2, 3]))
  #expect(done.wait(timeout: .now() + 1) == .success)
}
@Test func zeroAndOversizedFramesRejected() throws {
  for size in [UInt32(0), UInt32(SSHWire.maximumFrame + 1), UInt32.max] {
    let pair = try Pair()
    try pair.send(SSHWire.uint32(size))
    #expect(throws: (any Error).self) {
      try SocketIO.readFrame(pair.reader, deadline: ProcessInfo.processInfo.systemUptime + 1)
    }
  }
}
@Test func disconnectAndTruncation() throws {
  let empty = try Pair()
  shutdown(empty.writer, SHUT_WR)
  #expect(
    try SocketIO.readFrame(empty.reader, deadline: ProcessInfo.processInfo.systemUptime + 1) == nil)
  let partial = try Pair()
  try partial.send(Data([0, 0]))
  shutdown(partial.writer, SHUT_WR)
  #expect(throws: (any Error).self) {
    try SocketIO.readFrame(partial.reader, deadline: ProcessInfo.processInfo.systemUptime + 1)
  }
  let payload = try Pair()
  try payload.send(SSHWire.uint32(2) + Data([11]))
  shutdown(payload.writer, SHUT_WR)
  #expect(throws: (any Error).self) {
    try SocketIO.readFrame(payload.reader, deadline: ProcessInfo.processInfo.systemUptime + 1)
  }
}
@Test func incompleteFrameExpiresWithoutMoreBytes() throws {
  let pair = try Pair()
  try pair.send(Data([0]))
  let start = ProcessInfo.processInfo.systemUptime
  #expect(throws: (any Error).self) { try SocketIO.readFrame(pair.reader, deadline: start + 0.02) }
  #expect(ProcessInfo.processInfo.systemUptime - start < 1)
}
@Test func privateDirectoryRejectsSymlinkAndPermissions() throws {
  let dir = FileManager.default.temporaryDirectory.appendingPathComponent(
    "keylet-test-" + UUID().uuidString)
  try FileManager.default.createDirectory(
    at: dir, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
  defer { try? FileManager.default.removeItem(at: dir) }
  try SocketSafety.directory(dir.path)
  let link = dir.appendingPathComponent("link")
  try FileManager.default.createSymbolicLink(at: link, withDestinationURL: dir)
  #expect(throws: (any Error).self) { try SocketSafety.directory(link.path) }
  try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dir.path)
  #expect(throws: (any Error).self) { try SocketSafety.directory(dir.path) }
}

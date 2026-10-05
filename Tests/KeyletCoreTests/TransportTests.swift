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
private final class FragmentedWriter: @unchecked Sendable {
  private let ready = DispatchSemaphore(value: 0)
  private let done = DispatchSemaphore(value: 0)
  private let lock = NSLock()
  private var failure: (any Error)?

  func start(pair: Pair, frame: Data) throws {
    Thread {
      self.ready.signal()
      defer { self.done.signal() }
      do {
        for byte in frame {
          try pair.send(Data([byte]))
          usleep(1000)
        }
      } catch {
        self.lock.lock()
        self.failure = error
        self.lock.unlock()
      }
    }.start()
    guard ready.wait(timeout: .now() + 1) == .success else { throw AgentError.unavailable }
  }

  func wait() throws {
    guard done.wait(timeout: .now() + 1) == .success else { throw AgentError.unavailable }
    lock.lock()
    let error = failure
    lock.unlock()
    if let error { throw error }
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
  // Swift Testing can occupy the global dispatch executor with blocking tests.
  // Use a dedicated producer thread and propagate its errors after joining it.
  let writer = FragmentedWriter()
  try writer.start(pair: pair, frame: frame)
  let response = Result {
    try SocketIO.readFrame(pair.reader, deadline: ProcessInfo.processInfo.systemUptime + 1)
  }
  try writer.wait()
  #expect(try response.get() == Data([11, 1, 2, 3]))
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

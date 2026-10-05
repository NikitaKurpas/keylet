import Darwin
import Foundation
import Testing

@testable import KeyletCore

// Exercise the production multiplexer using socketpairs and a public-key/mock-signing reply.
// No listening agent, KeyStore or cryptographic private key is involved.
@discardableResult func attach(_ pair: Pair, to sessions: SocketSessions) throws -> Int32 {
  let fd = dup(pair.reader)
  guard fd >= 0 else { throw AgentError.io(errno) }
  do { try sessions.add(fd) } catch {
    close(fd)
    throw error
  }
  return fd
}
func exchange(_ request: Data, pair: Pair, sessions: SocketSessions, reply: (Data) -> Data) throws
  -> Data
{
  try pair.send(SSHWire.string(request))
  for _ in 0..<6 { try sessions.step(waitMilliseconds: 0, reply: reply) }
  guard
    let response = try SocketIO.readFrame(
      pair.writer, deadline: ProcessInfo.processInfo.systemUptime + 1)
  else { throw AgentError.unavailable }
  return response
}
@Test func retainedIdentityThenSignAfterEightSeconds() throws {
  let sessions = SocketSessions()
  let pair = try Pair()
  let blob = try record(.afterFirstUnlock).blob()
  try attach(pair, to: sessions)
  var calls = 0
  let reply: (Data) -> Data = { request in
    AgentProtocol.reply(to: request, keyBlob: blob, label: "public fixture") { _ in
      calls += 1
      return Data(repeating: 1, count: 64)
    }
  }
  #expect(try exchange(Data([11]), pair: pair, sessions: sessions, reply: reply).first == 12)
  Thread.sleep(forTimeInterval: 8.1)
  try sessions.step(waitMilliseconds: 0, reply: reply)
  #expect(sessions.count == 1)
  let request =
    Data([13]) + SSHWire.string(blob) + SSHWire.string("test public message") + SSHWire.uint32(0)
  #expect(try exchange(request, pair: pair, sessions: sessions, reply: reply).first == 14)
  #expect(calls == 1)
}
@Test func retainedConnectionHasNoThirtyTwoRequestCutoff() throws {
  let sessions = SocketSessions()
  let pair = try Pair()
  try attach(pair, to: sessions)
  for _ in 0..<40 {
    #expect(
      try exchange(Data([11]), pair: pair, sessions: sessions) { _ in Data([12, 0, 0, 0, 0]) }.first
        == 12)
  }
  #expect(sessions.count == 1)
}
@Test func partialClientDoesNotBlockOtherClientAndExpires() throws {
  let sessions = SocketSessions(frameTimeout: 0.03)
  let slow = try Pair()
  let healthy = try Pair()
  try attach(slow, to: sessions)
  try attach(healthy, to: sessions)
  try slow.send(Data([0]))
  try sessions.step(waitMilliseconds: 0) { _ in Data([5]) }
  #expect(
    try exchange(Data([11]), pair: healthy, sessions: sessions) { _ in Data([12, 0, 0, 0, 0]) }
      .first == 12)
  Thread.sleep(forTimeInterval: 0.04)
  try sessions.step(waitMilliseconds: 0) { _ in Data([5]) }
  #expect(sessions.count == 1)
}
@Test func dripFedHeaderDoesNotRenewDeadline() throws {
  let sessions = SocketSessions(frameTimeout: 0.03)
  let pair = try Pair()
  try attach(pair, to: sessions)
  try pair.send(Data([0]))
  try sessions.step(waitMilliseconds: 0) { _ in Data([5]) }
  Thread.sleep(forTimeInterval: 0.02)
  try pair.send(Data([0]))
  try sessions.step(waitMilliseconds: 0) { _ in Data([5]) }
  Thread.sleep(forTimeInterval: 0.02)
  try sessions.step(waitMilliseconds: 0) { _ in Data([5]) }
  #expect(sessions.count == 0)
}
@Test func admissionIsBoundedAndShutdownClosesAll() throws {
  let sessions = SocketSessions(maximumConnections: 1)
  // Transfer the sole server endpoint directly; a duplicate owned by Pair would prevent EOF.
  var endpoints: [Int32] = [0, 0]
  guard socketpair(AF_UNIX, SOCK_STREAM, 0, &endpoints) == 0 else { throw AgentError.io(errno) }
  let peer = endpoints[1]
  defer { close(peer) }
  do { try sessions.add(endpoints[0]) } catch {
    close(endpoints[0])
    throw error
  }
  let second = try Pair()
  #expect(throws: (any Error).self) { try attach(second, to: sessions) }
  #expect(sessions.count == 1)
  var livePeer = pollfd(fd: peer, events: Int16(POLLIN), revents: 0)
  #expect(poll(&livePeer, 1, 0) == 0)
  sessions.closeAll()
  #expect(sessions.count == 0)
  // This still-owned peer observes EOF of its connection, regardless of FD-number reuse elsewhere.
  #expect(try SocketIO.readFrame(peer, deadline: ProcessInfo.processInfo.systemUptime + 1) == nil)
}
@Test func malformedFrameRejectedByMultiplexer() throws {
  for size in [UInt32(0), UInt32.max] {
    let sessions = SocketSessions()
    let pair = try Pair()
    try attach(pair, to: sessions)
    try pair.send(SSHWire.uint32(size))
    try sessions.step(waitMilliseconds: 0) { _ in
      Issue.record("Malformed request reached reply")
      return Data([5])
    }
    #expect(sessions.count == 0)
  }
}
@Test func responseBackpressureExpires() throws {
  let sessions = SocketSessions(frameTimeout: 0.03)
  let pair = try Pair()
  let fd = try attach(pair, to: sessions)
  var buffer: Int32 = 1024
  #expect(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buffer, socklen_t(MemoryLayout<Int32>.size)) == 0)
  try pair.send(SSHWire.string(Data([11])))
  for _ in 0..<8 {
    try sessions.step(waitMilliseconds: 0) { _ in Data(repeating: 0, count: SSHWire.maximumFrame) }
  }
  #expect(sessions.count == 1)
  Thread.sleep(forTimeInterval: 0.04)
  try sessions.step(waitMilliseconds: 0) { _ in
    Issue.record("Unexpected retry")
    return Data([5])
  }
  #expect(sessions.count == 0)
}
@Test func productionMultiplexerPreservesCoalescedFrames() throws {
  let sessions = SocketSessions()
  let pair = try Pair()
  try attach(pair, to: sessions)
  try pair.send(SSHWire.string(Data([11])) + SSHWire.string(Data([17])))
  var seen: [Data] = []
  for _ in 0..<12 {
    try sessions.step(waitMilliseconds: 0) {
      seen.append($0)
      return Data([12])
    }
  }
  #expect(seen == [Data([11]), Data([17])])
  for _ in 0..<2 {
    #expect(
      try SocketIO.readFrame(pair.writer, deadline: ProcessInfo.processInfo.systemUptime + 1)
        == Data([12]))
  }
}
@Test func productionMultiplexerPreservesFragmentedFrames() throws {
  let sessions = SocketSessions()
  let pair = try Pair()
  try attach(pair, to: sessions)
  let frame = SSHWire.string(Data([11, 1, 2, 3]))
  let done = DispatchSemaphore(value: 0)
  DispatchQueue.global().async {
    defer { done.signal() }
    for byte in frame {
      try? pair.send(Data([byte]))
      usleep(1000)
    }
  }
  var seen: [Data] = []
  let end = ProcessInfo.processInfo.systemUptime + 1
  while seen.isEmpty && ProcessInfo.processInfo.systemUptime < end {
    try sessions.step(waitMilliseconds: 1) {
      seen.append($0)
      return Data([12])
    }
  }
  for _ in 0..<3 { try sessions.step(waitMilliseconds: 0) { _ in Data([5]) } }
  #expect(done.wait(timeout: .now() + 1) == .success)
  #expect(seen == [Data([11, 1, 2, 3])])
  #expect(
    try SocketIO.readFrame(pair.writer, deadline: ProcessInfo.processInfo.systemUptime + 1)
      == Data([12]))
}
@Test func productionMultiplexerClosesTruncatedFrames() throws {
  for input in [Data(), Data([0, 0]), SSHWire.uint32(2) + Data([11])] {
    let sessions = SocketSessions()
    let pair = try Pair()
    try attach(pair, to: sessions)
    if !input.isEmpty { try pair.send(input) }
    shutdown(pair.writer, SHUT_WR)
    for _ in 0..<4 {
      try sessions.step(waitMilliseconds: 0) { _ in
        Issue.record("Truncated request reached reply")
        return Data([5])
      }
    }
    #expect(sessions.count == 0)
  }
}

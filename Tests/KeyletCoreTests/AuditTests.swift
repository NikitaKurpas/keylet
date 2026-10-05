import CSQLite
import Darwin
import Foundation
import Testing

@testable import KeyletCore

private final class AuditFixture {
  let root: String
  let directory: String
  var path: String { directory + "/audit.sqlite3" }
  init() throws {
    guard let resolved = realpath(FileManager.default.temporaryDirectory.path, nil) else {
      throw AuditError.unsafePath
    }
    defer { free(resolved) }
    root = String(cString: resolved) + "/keylet-audit-test-" + UUID().uuidString
    directory = root + "/audit"
    try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: false)
  }
  deinit { try? FileManager.default.removeItem(atPath: root) }
  func store(retention: Int = 10000) throws -> AuditStore {
    try AuditStore(directory: directory, retentionLimit: retention)
  }
  func sql(_ query: String) throws {
    var db: OpaquePointer?
    guard sqlite3_open(path, &db) == SQLITE_OK else { throw AuditError.unavailable }
    defer { sqlite3_close(db) }
    guard sqlite3_exec(db, query, nil, nil, nil) == SQLITE_OK else { throw AuditError.unavailable }
  }
}
@Test func auditPaginationRetentionAndTop() throws {
  let fixture = try AuditFixture()
  let store = try fixture.store(retention: 4)
  let key = UUID()
  for _ in 0..<3 {
    let request = UUID()
    try store.append(
      requestID: request, action: "sign", outcome: "intent", keyID: key,
      fingerprint: "SHA256:fixture", byteCount: 10)
    try store.append(
      requestID: request, action: "sign", outcome: "success", keyID: key,
      fingerprint: "SHA256:fixture", byteCount: 10)
  }
  let first = try store.list(limit: 2)
  let second = try store.list(limit: 2, before: first.last!.id)
  #expect(first.count == 2 && second.count == 2)
  #expect(first[0].id > first[1].id && first[1].id > second[0].id)
  #expect(try store.list().count == 4)
  #expect(try store.top().first?.count == 2)  // Success rows only, never double-count intent.
  #expect(first[0].peerIdentity == "unavailable")
  #expect(throws: AuditError.self) { try store.list(limit: 201) }
  #expect(throws: AuditError.self) { try store.top(limit: 0) }
  #expect(throws: AuditError.self) { try store.list(before: -1) }
  var info = stat()
  #expect(lstat(fixture.path, &info) == 0 && info.st_mode & 0o777 == 0o600)
}
@Test func auditPersistsAcrossReopenAndConcurrentConnections() throws {
  let fixture = try AuditFixture()
  do { try fixture.store().append(requestID: UUID(), action: "identities", outcome: "success") }
  let first = try fixture.store()
  let second = try fixture.store()
  try first.append(
    requestID: UUID(), action: "unsupported", outcome: "rejected", errorCode: "invalid-request")
  #expect(try second.list().count == 2)
}
@Test func auditRejectsUnsafeFilesAndDirectory() throws {
  let fixture = try AuditFixture()
  let store = try fixture.store()
  #expect(chmod(fixture.path, 0o644) == 0)
  #expect(throws: AuditError.self) { try store.list() }
  #expect(chmod(fixture.path, 0o600) == 0)
  #expect(link(fixture.path, fixture.root + "/link") == 0)
  #expect(throws: AuditError.self) {
    try store.append(requestID: UUID(), action: "sign", outcome: "intent")
  }
  #expect(unlink(fixture.root + "/link") == 0)
  #expect(chmod(fixture.directory, 0o755) == 0)
  #expect(throws: (any Error).self) { try store.top() }
}
@Test func auditRejectsDatabaseAndSidecarSymlinksAndReplacement() throws {
  let fixture = try AuditFixture()
  let store = try fixture.store()
  let other = fixture.root + "/other"
  try Data().write(to: URL(fileURLWithPath: other))
  #expect(symlink(other, fixture.path + "-journal") == 0)
  #expect(throws: AuditError.self) { try store.list() }
  #expect(unlink(fixture.path + "-journal") == 0)
  #expect(rename(fixture.path, fixture.root + "/original") == 0)
  #expect(symlink(other, fixture.path) == 0)
  #expect(throws: AuditError.self) { try store.list() }
  #expect(throws: AuditError.self) { try fixture.store() }
  #expect(unlink(fixture.path) == 0)
  try Data().write(to: URL(fileURLWithPath: fixture.path))
  #expect(chmod(fixture.path, 0o600) == 0)
  #expect(throws: AuditError.self) { try store.list() }
}
@Test func auditRejectsUnknownSchemaAndBusyWriterIsBounded() throws {
  let fixture = try AuditFixture()
  let store = try fixture.store()
  var db: OpaquePointer?
  #expect(sqlite3_open(fixture.path, &db) == SQLITE_OK)
  defer { sqlite3_close(db) }
  #expect(sqlite3_exec(db, "BEGIN IMMEDIATE", nil, nil, nil) == SQLITE_OK)
  let start = ProcessInfo.processInfo.systemUptime
  #expect(throws: AuditError.self) {
    try store.append(requestID: UUID(), action: "sign", outcome: "intent")
  }
  #expect(ProcessInfo.processInfo.systemUptime - start < 2)
  #expect(sqlite3_exec(db, "ROLLBACK; PRAGMA user_version=99", nil, nil, nil) == SQLITE_OK)
  #expect(throws: AuditError.self) { try fixture.store() }
}
@Test func auditedSigningFailsClosedAndRecordsSafeMetadata() throws {
  let fixture = try AuditFixture()
  let store = try fixture.store()
  let key = record(.afterFirstUnlock)
  let blob = try key.blob()
  let request =
    Data([13]) + SSHWire.string(blob) + SSHWire.string("sensitive payload never logged")
    + SSHWire.uint32(0)
  var calls = 0
  let response = AuditedAgentProtocol.reply(
    to: request, key: key,
    peer: AuditPeer(uid: 123, gid: 456, pid: 789), audit: store
  ) { _ in
    calls += 1
    return Data(repeating: 1, count: 64)
  }
  #expect(response.first == 14 && calls == 1)
  let events = try store.list()
  #expect(events.map(\.outcome) == ["success", "intent"])
  #expect(events[0].requestID == events[1].requestID)
  #expect(events[0].peerPID == 789 && events[0].peerUID == 123)
  #expect(events[0].byteCount == "sensitive payload never logged".utf8.count)
  #expect(events[0].fingerprint == SSHWire.fingerprint(blob))
  let encoded = try JSONEncoder().encode(events)
  #expect(!String(decoding: encoded, as: UTF8.self).contains("sensitive payload"))
  #expect(chmod(fixture.path, 0o644) == 0)
  let failed = AuditedAgentProtocol.reply(to: request, key: key, peer: AuditPeer(), audit: store) {
    _ in
    calls += 1
    return Data(repeating: 1, count: 64)
  }
  #expect(failed == Data([5]) && calls == 1)
}
@Test func auditedSigningCompletionFailureWithholdsSignature() throws {
  let key = record(.afterFirstUnlock)
  let request =
    Data([13]) + SSHWire.string(try key.blob()) + SSHWire.string("fixture") + SSHWire.uint32(0)
  var outcomes: [String] = []
  var calls = 0
  let response = AuditedAgentProtocol.reply(
    to: request, key: key, peer: AuditPeer(),
    record: { outcome, _, _, _, _ in
      outcomes.append(outcome)
      if outcome == "success" { throw AuditError.unavailable }
    },
    sign: { _ in
      calls += 1
      return Data(repeating: 1, count: 64)
    })
  #expect(response == Data([5]) && calls == 1)
  #expect(outcomes == ["intent", "success"])
}
@Test func auditedSigningRejectsUntrustedRequestAndUnavailableKey() throws {
  let fixture = try AuditFixture()
  let store = try fixture.store()
  let key = record(.afterFirstUnlock)
  let request =
    Data([13]) + SSHWire.string(Data([1])) + SSHWire.string("fixture") + SSHWire.uint32(0)
  let response = AuditedAgentProtocol.reply(to: request, key: key, peer: AuditPeer(), audit: store)
  { _ in
    Issue.record("invalid request invoked signer")
    return Data(repeating: 1, count: 64)
  }
  #expect(response == Data([5]))
  #expect(try store.list().map(\.outcome) == ["rejected"])
  #expect(try store.list().first?.peerPID == nil)
}
@Test func auditedSignerFailureRecordsFailureNotSuccess() throws {
  let fixture = try AuditFixture()
  let store = try fixture.store()
  let key = record(.afterFirstUnlock)
  let request =
    Data([13]) + SSHWire.string(try key.blob()) + SSHWire.string("fixture") + SSHWire.uint32(0)
  let response = AuditedAgentProtocol.reply(to: request, key: key, peer: AuditPeer(), audit: store)
  { _ in
    throw AgentError.unavailable
  }
  #expect(response == Data([5]))
  #expect(try store.list().map(\.outcome) == ["failure", "intent"])
  #expect(try store.top().isEmpty)
}
@Test func socketAuditPeerSnapshotSurvivesRetainedRequests() throws {
  let sessions = SocketSessions()
  let pair = try Pair()
  try attach(pair, to: sessions)
  var peers: [AuditPeer] = []
  for _ in 0..<2 {
    try pair.send(SSHWire.string(Data([11])))
    for _ in 0..<6 {
      try sessions.stepWithPeer(waitMilliseconds: 0) { _, peer in
        peers.append(peer)
        return Data([12, 0, 0, 0, 0])
      }
    }
    _ = try SocketIO.readFrame(pair.writer, deadline: ProcessInfo.processInfo.systemUptime + 1)
  }
  #expect(peers.count == 2 && peers[0] == peers[1])
  #expect(peers[0].uid == geteuid() && peers[0].gid != nil)
}
@Test func auditReadOnlyMissingAndExistingNeverCreatesOrMigrates() throws {
  let fixture = try AuditFixture()
  let missing = try AuditStore(directory: fixture.directory, readOnly: true)
  #expect(try missing.list().isEmpty && missing.top().isEmpty)
  #expect(!FileManager.default.fileExists(atPath: fixture.directory))
  let writer = try fixture.store()
  try writer.append(requestID: UUID(), action: "identities", outcome: "success")
  let reader = try AuditStore(directory: fixture.directory, readOnly: true)
  #expect(try reader.list().count == 1)
  #expect(throws: AuditError.self) {
    try reader.append(requestID: UUID(), action: "identities", outcome: "success")
  }
  try fixture.sql("PRAGMA user_version=0")
  #expect(throws: AuditError.self) { try AuditStore(directory: fixture.directory, readOnly: true) }
  #expect(sqliteSchemaVersion(fixture.path) == 0)
}
private func sqliteSchemaVersion(_ path: String) -> Int32 {
  var db: OpaquePointer?
  var statement: OpaquePointer?
  guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK else { return -1 }
  defer { sqlite3_close(db) }
  guard sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &statement, nil) == SQLITE_OK else {
    return -1
  }
  defer { sqlite3_finalize(statement) }
  guard sqlite3_step(statement) == SQLITE_ROW else { return -1 }
  return sqlite3_column_int(statement, 0)
}
@Test func auditRejectsSymlinkedAncestorBeforeCreatingDirectory() throws {
  let fixture = try AuditFixture()
  #expect(symlink(fixture.root, fixture.root + "/alias") == 0)
  #expect(throws: AuditError.self) { try AuditStore(directory: fixture.root + "/alias/audit") }
  #expect(!FileManager.default.fileExists(atPath: fixture.directory))
}
@Test func auditRejectsWALReadAndMalformedPersistedMetadata() throws {
  let fixture = try AuditFixture()
  let writer = try fixture.store()
  try writer.append(requestID: UUID(), action: "sign", outcome: "success")
  try fixture.sql("UPDATE events SET peer_uid=-99, peer_pid=9223372036854775807")
  #expect(try writer.list().first?.peerUID == nil)
  #expect(try writer.list().first?.peerPID == nil)
  try fixture.sql("UPDATE events SET action=zeroblob(1000)")
  #expect(throws: AuditError.self) { try writer.list() }
  try fixture.sql("PRAGMA journal_mode=WAL")
  #expect(throws: AuditError.self) { try AuditStore(directory: fixture.directory, readOnly: true) }
}
@Test func auditedInvalidFlagsUnsupportedAndInteractiveNeverSign() throws {
  let fixture = try AuditFixture()
  let store = try fixture.store()
  let key = record(.afterFirstUnlock)
  let invalid =
    Data([13]) + SSHWire.string(try key.blob()) + SSHWire.string("fixture") + SSHWire.uint32(1)
  let interactive = record(.userPresence)
  let validInteractive =
    Data([13]) + SSHWire.string(try interactive.blob()) + SSHWire.string("fixture")
    + SSHWire.uint32(0)
  for (request, record) in [(invalid, key), (Data([17]), key), (validInteractive, interactive)] {
    let response = AuditedAgentProtocol.reply(
      to: request, key: record, peer: AuditPeer(), audit: store
    ) { _ in
      Issue.record("rejected request invoked signer")
      return Data(repeating: 1, count: 64)
    }
    #expect(response == Data([5]))
  }
  #expect(try store.list().map(\.outcome) == ["rejected", "rejected", "rejected"])
  #expect(try store.top().isEmpty)
}
@Test func auditSchemaTriggersCannotSuppressIntent() throws {
  for trigger in [
    "CREATE TRIGGER suppress BEFORE INSERT ON events BEGIN SELECT RAISE(IGNORE); END",
    "CREATE TRIGGER suppress AFTER INSERT ON events BEGIN DELETE FROM events WHERE id=NEW.id; END",
  ] {
    let fixture = try AuditFixture()
    let store = try fixture.store()
    try fixture.sql(trigger)
    let key = record(.afterFirstUnlock)
    let request =
      Data([13]) + SSHWire.string(try key.blob()) + SSHWire.string("fixture") + SSHWire.uint32(0)
    var signed = false
    let result = AuditedAgentProtocol.reply(to: request, key: key, peer: AuditPeer(), audit: store)
    { _ in
      signed = true
      return Data(repeating: 1, count: 64)
    }
    #expect(result == Data([5]) && !signed)
    #expect(try store.list().isEmpty)
  }
}

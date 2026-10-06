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
  func legacy() throws {
    #expect(mkdir(directory, 0o700) == 0)
    try sql(
      """
      CREATE TABLE events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
        request_id TEXT NOT NULL, action TEXT NOT NULL, outcome TEXT NOT NULL,
        key_id TEXT, fingerprint TEXT, byte_count INTEGER,
        peer_uid INTEGER, peer_gid INTEGER, peer_pid INTEGER, peer_identity TEXT NOT NULL,
        error_code TEXT);
      CREATE INDEX events_key_outcome ON events(key_id, outcome, id);
      PRAGMA user_version=1;
      INSERT INTO events VALUES(9,'2026-10-06T00:00:00Z','old-request','sign','success',
        '00000000-0000-0000-0000-000000000001','SHA256:fixture',10,123,456,789,'old-peer',NULL);
      INSERT INTO events VALUES(100,'2026-10-06T00:00:00Z','old-request','identities','success',
        NULL,NULL,NULL,NULL,NULL,NULL,'unavailable',NULL);
      DELETE FROM events WHERE id=100;
      """)
    #expect(chmod(path, 0o600) == 0)
  }

  func strings(_ query: String) throws -> [String] {
    var db: OpaquePointer?
    var statement: OpaquePointer?
    guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK else {
      throw AuditError.unavailable
    }
    defer { sqlite3_close(db) }
    guard sqlite3_prepare_v2(db, query, -1, &statement, nil) == SQLITE_OK else {
      throw AuditError.unavailable
    }
    defer { sqlite3_finalize(statement) }
    var values: [String] = []
    while sqlite3_step(statement) == SQLITE_ROW {
      values.append(String(cString: sqlite3_column_text(statement, 0)))
    }
    return values
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
    try store.append(
      action: "sign", outcome: "intent", keyID: key,
      fingerprint: "SHA256:fixture", byteCount: 10)
    try store.append(
      action: "sign", outcome: "success", keyID: key,
      fingerprint: "SHA256:fixture", byteCount: 10)
  }
  let first = try store.list(limit: 2)
  let second = try store.list(limit: 2, before: first.last!.id)
  #expect(first.count == 2 && second.count == 2)
  #expect(first[0].id > first[1].id && first[1].id > second[0].id)
  #expect(try store.list().count == 4)
  #expect(try store.top().first?.count == 2)  // Success rows only, never double-count intent.
  #expect(throws: AuditError.self) { try store.list(limit: 201) }
  #expect(throws: AuditError.self) { try store.top(limit: 0) }
  #expect(throws: AuditError.self) { try store.list(before: -1) }
  var info = stat()
  #expect(lstat(fixture.path, &info) == 0 && info.st_mode & 0o777 == 0o600)
}
@Test func auditOptionalMetadataValidation() throws {
  let fixture = try AuditFixture()
  let store = try fixture.store()
  for byteCount in [nil, 0, SSHWire.maximumFrame] as [Int?] {
    try store.append(action: "sign", outcome: "intent", byteCount: byteCount)
  }
  for byteCount in [-1, SSHWire.maximumFrame + 1] {
    #expect(throws: AuditError.self) {
      try store.append(action: "sign", outcome: "intent", byteCount: byteCount)
    }
  }
  for fingerprint in ["invalid", "SHA256:" + String(repeating: "a", count: 58)] {
    #expect(throws: AuditError.self) {
      try store.append(
        action: "sign", outcome: "intent", fingerprint: fingerprint)
    }
  }
  #expect(throws: AuditError.self) {
    try store.append(action: "sign", outcome: "failure", errorCode: "unknown")
  }
  #expect(try store.list().count == 3)
}
@Test func auditPersistsAcrossReopenAndConcurrentConnections() throws {
  let fixture = try AuditFixture()
  do { try fixture.store().append(action: "identities", outcome: "success") }
  let first = try fixture.store()
  let second = try fixture.store()
  try first.append(
    action: "unsupported", outcome: "rejected", errorCode: "invalid-request")
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
    try store.append(action: "sign", outcome: "intent")
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
    try store.append(action: "sign", outcome: "intent")
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
    to: request, keys: [key],
    audit: store
  ) { _, _ in
    calls += 1
    return Data(repeating: 1, count: 64)
  }
  #expect(response.first == 14 && calls == 1)
  let events = try store.list()
  #expect(events.map(\.outcome) == ["success", "intent"])
  #expect(events[0].byteCount == "sensitive payload never logged".utf8.count)
  #expect(events[0].fingerprint == SSHWire.fingerprint(blob))
  let encoded = try JSONEncoder().encode(events)
  #expect(!String(decoding: encoded, as: UTF8.self).contains("sensitive payload"))
  #expect(chmod(fixture.path, 0o644) == 0)
  let failed = AuditedAgentProtocol.reply(to: request, keys: [key], audit: store) {
    _, _ in
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
    to: request, keys: [key],
    record: { outcome, _, _, _, _ in
      outcomes.append(outcome)
      if outcome == "success" { throw AuditError.unavailable }
    },
    sign: { _, _ in
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
  let response = AuditedAgentProtocol.reply(to: request, keys: [key], audit: store) { _, _ in
    Issue.record("invalid request invoked signer")
    return Data(repeating: 1, count: 64)
  }
  #expect(response == Data([5]))
  #expect(try store.list().map(\.outcome) == ["rejected"])
}
@Test func auditedSignerFailureRecordsFailureNotSuccess() throws {
  let fixture = try AuditFixture()
  let store = try fixture.store()
  let key = record(.afterFirstUnlock)
  let request =
    Data([13]) + SSHWire.string(try key.blob()) + SSHWire.string("fixture") + SSHWire.uint32(0)
  let response = AuditedAgentProtocol.reply(to: request, keys: [key], audit: store) { _, _ in
    throw AgentError.unavailable
  }
  #expect(response == Data([5]))
  #expect(try store.list().map(\.outcome) == ["failure", "intent"])
  #expect(try store.top().isEmpty)
}

@Test func multipleAgentKeysListSignAndAuditTheRequestedKey() throws {
  let fixture = try AuditFixture()
  let store = try fixture.store()
  // SEC1 encoding of the public P256 generator point; no private key is created.
  let otherPublicKey = Data(
    base64Encoded:
      "BGsX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfU=")!
  let keys = [
    record(.afterFirstUnlock),
    KeyRecord(id: UUID(), label: "other", policy: .whenUnlocked, publicKey: otherPublicKey),
  ]
  var identities = SSHReader(
    AuditedAgentProtocol.reply(to: Data([11]), keys: keys, audit: store) { _, _ in
      Issue.record("identity request invoked signer")
      return Data()
    })
  #expect(try identities.byte() == 12)
  #expect(try identities.uint32() == 2)
  for key in keys {
    #expect(try identities.string() == key.blob())
    #expect(try identities.string() == Data(key.label.utf8))
  }
  #expect(identities.done)

  var signed: [UUID] = []
  for key in keys {
    let request =
      Data([13]) + SSHWire.string(try key.blob()) + SSHWire.string("fixture") + SSHWire.uint32(0)
    let response = AuditedAgentProtocol.reply(to: request, keys: keys, audit: store) {
      data, selected in
      #expect(data == Data("fixture".utf8))
      #expect(selected == key)
      signed.append(selected.id)
      return Data(repeating: 1, count: 64)
    }
    #expect(response.first == 14)
  }
  #expect(signed == keys.map(\.id))
  let events = try store.list().filter { $0.action == "sign" && $0.outcome == "success" }
  #expect(events.map(\.keyID) == keys.reversed().map { $0.id.uuidString })
  #expect(
    try events.map(\.fingerprint) == keys.reversed().map { SSHWire.fingerprint(try $0.blob()) })

  let excludedRequest =
    Data([13]) + SSHWire.string(try keys[1].blob()) + SSHWire.string("fixture") + SSHWire.uint32(0)
  let restricted = Inventory(keys: keys, unavailableClasses: []).agentKeys(id: keys[0].id)
  let response = AuditedAgentProtocol.reply(
    to: excludedRequest, keys: restricted, audit: store
  ) { _, _ in
    Issue.record("excluded key invoked signer")
    return Data()
  }
  #expect(response == Data([5]))
}
@Test func auditReadOnlyMissingAndExistingNeverCreatesOrMigrates() throws {
  let fixture = try AuditFixture()
  let missing = try AuditStore(directory: fixture.directory, readOnly: true)
  #expect(try missing.list().isEmpty && missing.top().isEmpty)
  #expect(!FileManager.default.fileExists(atPath: fixture.directory))
  let writer = try fixture.store()
  try writer.append(action: "identities", outcome: "success")
  let reader = try AuditStore(directory: fixture.directory, readOnly: true)
  #expect(try reader.list().count == 1)
  #expect(throws: AuditError.self) {
    try reader.append(action: "identities", outcome: "success")
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
  try writer.append(action: "sign", outcome: "success")
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
      to: request, keys: [record], audit: store
    ) { _, _ in
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
    let result = AuditedAgentProtocol.reply(to: request, keys: [key], audit: store) { _, _ in
      signed = true
      return Data(repeating: 1, count: 64)
    }
    #expect(result == Data([5]) && !signed)
    #expect(try store.list().isEmpty)
  }
}

@Test func auditMigrationPreservesEventsCursorsAndSequence() throws {
  let fixture = try AuditFixture()
  try fixture.legacy()
  let reader = try AuditStore(directory: fixture.directory, readOnly: true)
  let original = try reader.list()
  #expect(original.count == 1 && original[0].id == 9)
  #expect(sqliteSchemaVersion(fixture.path) == 1)  // Read-only access does not migrate.
  let store = try fixture.store()
  #expect(sqliteSchemaVersion(fixture.path) == 2)
  #expect(
    try fixture.strings("SELECT name FROM pragma_table_info('events')") == [
      "id", "timestamp", "action", "outcome", "key_id", "fingerprint", "byte_count", "error_code",
    ])
  #expect(
    try fixture.strings("SELECT name FROM pragma_index_list('events')") == ["events_key_outcome"])
  let migrated = try store.list()
  #expect(migrated[0].timestamp == original[0].timestamp)
  #expect(migrated[0].action == "sign" && migrated[0].outcome == "success")
  #expect(migrated[0].keyID == original[0].keyID && migrated[0].fingerprint == "SHA256:fixture")
  #expect(migrated[0].byteCount == 10 && migrated[0].errorCode == nil)
  #expect(try store.append(action: "identities", outcome: "success") == 101)
  #expect(try reader.list(before: 101).map(\.id) == [9])
  #expect(try store.top().first?.count == 1)
  #expect(try fixture.store().list().count == 2)  // Reopening schema 2 is idempotent.
}

@Test func auditMigrationFailureRollsBackAllColumnDrops() throws {
  let fixture = try AuditFixture()
  try fixture.legacy()
  // This dependency makes a later DROP fail after request_id and peer_uid were dropped.
  try fixture.sql("CREATE INDEX incompatible_peer ON events(peer_gid)")
  #expect(throws: AuditError.self) { try fixture.store() }
  #expect(sqliteSchemaVersion(fixture.path) == 1)
  #expect(
    try fixture.strings("SELECT request_id || ':' || peer_uid || ':' || peer_identity FROM events")
      == ["old-request:123:old-peer"])
  #expect(try AuditStore(directory: fixture.directory, readOnly: true).list().map(\.id) == [9])
}

@Test func auditDefaultRetentionAndExclusivePaginationAfterOverflow() throws {
  let fixture = try AuditFixture()
  let store = try fixture.store()
  // Seed efficiently; production append must enforce its existing 10,000-row default.
  try fixture.sql(
    """
    WITH RECURSIVE numbers(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM numbers WHERE n<10001)
    INSERT INTO events(timestamp,action,outcome)
      SELECT '2026-10-06T00:00:00Z','identities','success' FROM numbers;
    """)
  let newest = try store.append(action: "identities", outcome: "success")
  #expect(newest == 10002)
  let first = try store.list(limit: 200)
  #expect(first.first?.id == newest)
  try store.append(action: "identities", outcome: "success")
  var ids = first.map(\.id)
  while let cursor = ids.last {
    let page = try store.list(limit: 200, before: cursor)
    if page.isEmpty { break }
    ids.append(contentsOf: page.map(\.id))
  }
  #expect(ids == Array((4...10002).reversed()).map(Int64.init))
  #expect(try fixture.strings("SELECT COUNT(*) FROM events") == ["10000"])
  #expect(try store.list(before: 4).isEmpty)
}

@Test func auditMigrationPrunesExistingOverflow() throws {
  let fixture = try AuditFixture()
  try fixture.legacy()
  try fixture.sql(
    """
    WITH RECURSIVE numbers(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM numbers WHERE n<10001)
    INSERT INTO events(timestamp,request_id,action,outcome,peer_identity)
      SELECT '2026-10-06T00:00:00Z','old-request','identities','success','unavailable' FROM numbers;
    """)
  let store = try fixture.store()
  #expect(sqliteSchemaVersion(fixture.path) == 2)
  #expect(try fixture.strings("SELECT COUNT(*) FROM events") == ["10000"])
  #expect(try store.list(limit: 1).first?.id == 10101)
  #expect(try store.list(before: 102).isEmpty)
}

@Test func auditCommitFailureRollsBackInsertionAndPruning() throws {
  let fixture = try AuditFixture()
  let store = try fixture.store(retention: 2)
  try store.append(action: "identities", outcome: "success")
  try store.append(action: "identities", outcome: "success")
  let original = try store.list().map(\.id)
  var reader: OpaquePointer?
  #expect(sqlite3_open_v2(fixture.path, &reader, SQLITE_OPEN_READONLY, nil) == SQLITE_OK)
  defer { sqlite3_close(reader) }
  // A shared read lock allows INSERT and pruning but prevents COMMIT's exclusive lock.
  #expect(sqlite3_exec(reader, "BEGIN; SELECT * FROM events", nil, nil, nil) == SQLITE_OK)
  #expect(throws: AuditError.self) {
    try store.append(action: "identities", outcome: "success")
  }
  #expect(try store.list().map(\.id) == original)
  #expect(sqlite3_exec(reader, "ROLLBACK", nil, nil, nil) == SQLITE_OK)
  #expect(try store.append(action: "identities", outcome: "success") == 3)
  #expect(try store.list().map(\.id) == [3, 2])
}

@Test func auditJSONIsPrettyValidAndContainsOnlyRetainedFields() throws {
  let fixture = try AuditFixture()
  let store = try fixture.store()
  let key = UUID()
  try store.append(
    action: "sign", outcome: "failure", keyID: key,
    fingerprint: "SHA256:fixture", byteCount: 10, errorCode: "signing-unavailable")
  let encoder = JSONEncoder()
  encoder.keyEncodingStrategy = .convertToSnakeCase
  let events = try JSONSerialization.jsonObject(with: encoder.encode(store.list()))
  let text = try CLIOutput.json([
    "ok": true, "events": events, "next_before": NSNull(), "limit": 20,
  ])
  #expect(text.contains("\n  \"events\" : ["))
  let envelope = try #require(JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
  let rows = try #require(envelope["events"] as? [[String: Any]])
  #expect(
    Set(rows[0].keys)
      == Set([
        "id", "timestamp", "action", "outcome", "key_id", "fingerprint", "byte_count", "error_code",
      ]))
  #expect(rows[0]["key_id"] as? String == key.uuidString)
  #expect(rows[0]["outcome"] as? String == "failure")
  #expect(envelope["next_before"] is NSNull)
  let escaped = try CLIOutput.json(["message": "quote \" slash \\ newline\n", "ok": false])
  let error = try #require(JSONSerialization.jsonObject(with: Data(escaped.utf8)) as? [String: Any])
  #expect(error["message"] as? String == "quote \" slash \\ newline\n")
}

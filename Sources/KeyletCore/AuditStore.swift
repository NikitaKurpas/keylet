import CSQLite
import Darwin
import Foundation

public enum AuditError: Error { case unsafePath, unavailable, invalidLimit, unsupportedSchema }

/// Kernel credentials describe the socket peer at connection time, not the human or Git repository.
/// A passed/inherited descriptor may be used by another process. PID is only an unauthenticated hint
/// after the connection snapshot; no process lookup or ancestry inference is performed.
public struct AuditPeer: Codable, Equatable, Sendable {
  public let uid: UInt32?
  public let gid: UInt32?
  public let pid: Int32?
  public init(uid: UInt32? = nil, gid: UInt32? = nil, pid: Int32? = nil) {
    self.uid = uid
    self.gid = gid
    self.pid = pid
  }
}
public struct AuditEvent: Codable, Sendable {
  public let id: Int64
  public let timestamp: String
  public let requestID: String
  public let action: String
  public let outcome: String
  public let keyID: String?
  public let fingerprint: String?
  public let byteCount: Int?
  public let peerUID: UInt32?
  public let peerGID: UInt32?
  public let peerPID: Int32?
  public let peerIdentity: String
  public let errorCode: String?
}
public struct AuditKeySummary: Codable, Sendable {
  public let keyID: String
  public let fingerprint: String
  public let count: Int
  public let lastTimestamp: String
}

/// Serialized SQLite writes with FULL synchronous rollback-journal durability. This is a local,
/// bounded operational log, not a tamper-proof ledger against the user or a compromised process.
public final class AuditStore: @unchecked Sendable {
  public static var defaultDirectory: String {
    (getpwuid(geteuid()).map { String(cString: $0.pointee.pw_dir) } ?? NSHomeDirectory())
      + "/Library/Containers/me.kurpas.keylet/Data/audit"
  }
  public static var defaultPath: String { defaultDirectory + "/audit.sqlite3" }
  private let directory: String
  private let path: String
  private var device: dev_t = 0
  private var inode: ino_t = 0
  private let readOnly: Bool
  private let lock = NSLock()
  private let retentionLimit: Int
  private var db: OpaquePointer?

  public init(
    directory: String = AuditStore.defaultDirectory, retentionLimit: Int = 10000,
    readOnly: Bool = false
  ) throws {
    guard directory.hasPrefix("/"), !directory.utf8.contains(0), retentionLimit >= 2,
      retentionLimit <= 100000
    else { throw AuditError.unsafePath }
    self.directory = directory
    self.path = directory + "/audit.sqlite3"
    self.retentionLimit = retentionLimit
    self.readOnly = readOnly
    try Self.validateAncestors(directory)
    if readOnly {
      var info = stat()
      if lstat(directory, &info) != 0 {
        guard errno == ENOENT else { throw AuditError.unsafePath }
        return
      }
      try Self.validateDirectory(directory)
      let fd = Darwin.open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
      if fd < 0 {
        guard errno == ENOENT else { throw AuditError.unsafePath }
        return
      }
      defer { close(fd) }
      guard fstat(fd, &info) == 0, Self.safeFile(info) else { throw AuditError.unsafePath }
      device = info.st_dev
      inode = info.st_ino
      try Self.validateJournalHeader(fd)
      try validateFiles()
      var handle: OpaquePointer?
      guard
        sqlite3_open_v2(
          path, &handle, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nil)
          == SQLITE_OK,
        let handle
      else {
        if let handle { sqlite3_close(handle) }
        throw AuditError.unavailable
      }
      db = handle
      do {
        _ = sqlite3_busy_timeout(handle, 250)
        try execute("PRAGMA trusted_schema=OFF; PRAGMA query_only=ON")
        guard try scalar("PRAGMA user_version") == 1 else { throw AuditError.unsupportedSchema }
        try validateFiles()
      } catch {
        sqlite3_close(handle)
        db = nil
        throw error
      }
      return
    }
    if mkdir(directory, 0o700) != 0 && errno != EEXIST { throw AuditError.unsafePath }
    try Self.validateDirectory(directory)
    let fd = Darwin.open(path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
    guard fd >= 0 else { throw AuditError.unsafePath }
    defer { close(fd) }
    var info = stat()
    guard fstat(fd, &info) == 0, Self.safeFile(info) else { throw AuditError.unsafePath }
    device = info.st_dev
    inode = info.st_ino
    if info.st_size > 0 { try Self.validateJournalHeader(fd) }
    try validateFiles()
    var handle: OpaquePointer?
    guard
      sqlite3_open_v2(
        path, &handle, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nil)
        == SQLITE_OK,
      let handle
    else {
      if let handle { sqlite3_close(handle) }
      throw AuditError.unavailable
    }
    db = handle
    do {
      _ = sqlite3_busy_timeout(handle, 250)
      try execute("PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;")
      let version = try scalar("PRAGMA user_version")
      guard version == 0 || version == 1 else { throw AuditError.unsupportedSchema }
      try execute("BEGIN IMMEDIATE")
      do {
        try execute(
          """
          CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
            request_id TEXT NOT NULL, action TEXT NOT NULL, outcome TEXT NOT NULL,
            key_id TEXT, fingerprint TEXT, byte_count INTEGER,
            peer_uid INTEGER, peer_gid INTEGER, peer_pid INTEGER, peer_identity TEXT NOT NULL,
            error_code TEXT);
          CREATE INDEX IF NOT EXISTS events_key_outcome ON events(key_id, outcome, id);
          PRAGMA user_version=1;
          COMMIT;
          """)
      } catch {
        try? execute("ROLLBACK")
        throw error
      }
      try validateFiles()
    } catch {
      sqlite3_close(handle)
      db = nil
      throw error
    }
  }
  deinit { if let db { sqlite3_close(db) } }
  private static func validateAncestors(_ directory: String) throws {
    let components = directory.split(separator: "/", omittingEmptySubsequences: true)
    guard !components.contains(".."), !components.contains(".") else { throw AuditError.unsafePath }
    var path = ""
    for component in components.dropLast() {
      path += "/" + component
      var info = stat()
      guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR else {
        throw AuditError.unsafePath
      }
    }
  }
  private static func validateDirectory(_ directory: String) throws {
    try validateAncestors(directory)
    do { try SocketSafety.directory(directory) } catch { throw AuditError.unsafePath }
  }
  private static func validateJournalHeader(_ fd: Int32) throws {
    var header = [UInt8](repeating: 0, count: 20)
    let count = header.withUnsafeMutableBytes { pread(fd, $0.baseAddress, $0.count, 0) }
    // A read-only WAL connection can create shared-memory sidecars. Accept only our rollback
    // journal format, keeping read-only audit commands free of filesystem mutations.
    guard count == 20, header[18] == 1, header[19] == 1 else { throw AuditError.unavailable }
  }
  private static func safeFile(_ info: stat) -> Bool {
    (info.st_mode & S_IFMT) == S_IFREG && info.st_uid == geteuid()
      && (info.st_mode & 0o777) == 0o600 && info.st_nlink == 1
  }
  private func validateFiles() throws {
    try Self.validateDirectory(directory)
    var info = stat()
    guard lstat(path, &info) == 0, Self.safeFile(info), info.st_dev == device,
      info.st_ino == inode
    else { throw AuditError.unsafePath }
    for suffix in ["-journal", "-wal", "-shm"] {
      if lstat(path + suffix, &info) == 0 {
        guard Self.safeFile(info) else { throw AuditError.unsafePath }
      } else if errno != ENOENT {
        throw AuditError.unsafePath
      }
    }
  }
  private func execute(_ sql: String) throws {
    guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else { throw AuditError.unavailable }
  }
  private func prepare(_ sql: String) throws -> OpaquePointer {
    var statement: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK, let statement else {
      throw AuditError.unavailable
    }
    return statement
  }
  private func scalar(_ sql: String) throws -> Int64 {
    let statement = try prepare(sql)
    defer { sqlite3_finalize(statement) }
    guard sqlite3_step(statement) == SQLITE_ROW else { throw AuditError.unavailable }
    return sqlite3_column_int64(statement, 0)
  }
  private func bind(_ value: String?, _ index: Int32, _ statement: OpaquePointer) throws {
    let status =
      value.map { value in
        value.withCString {
          sqlite3_bind_text(
            statement, index, $0, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))
        }
      } ?? sqlite3_bind_null(statement, index)
    guard status == SQLITE_OK else { throw AuditError.unavailable }
  }
  private func bind(_ value: Int64?, _ index: Int32, _ statement: OpaquePointer) throws {
    let status =
      value.map { sqlite3_bind_int64(statement, index, $0) } ?? sqlite3_bind_null(statement, index)
    guard status == SQLITE_OK else { throw AuditError.unavailable }
  }
  @discardableResult
  public func append(
    requestID: UUID, action: String, outcome: String, keyID: UUID? = nil,
    fingerprint: String? = nil, byteCount: Int? = nil,
    peer: AuditPeer = AuditPeer(), errorCode: String? = nil
  ) throws -> Int64 {
    guard !readOnly else { throw AuditError.unavailable }
    // Only fixed enums and public key identifiers enter the DB. Never persist request data.
    guard ["sign", "identities", "unsupported"].contains(action),
      ["intent", "success", "failure", "rejected"].contains(outcome),
      errorCode == nil || ["invalid-request", "signing-unavailable"].contains(errorCode!),
      byteCount == nil || (0...SSHWire.maximumFrame).contains(byteCount!),
      fingerprint == nil || (fingerprint!.hasPrefix("SHA256:") && fingerprint!.utf8.count <= 64)
    else { throw AuditError.unavailable }
    lock.lock()
    defer { lock.unlock() }
    try validateFiles()
    try execute("BEGIN IMMEDIATE")
    do {
      guard try scalar("SELECT COUNT(*) FROM sqlite_master WHERE type IN ('trigger','view')") == 0
      else {
        throw AuditError.unavailable
      }
      let statement = try prepare(
        "INSERT INTO events(timestamp,request_id,action,outcome,key_id,fingerprint,byte_count,peer_uid,peer_gid,peer_pid,peer_identity,error_code) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)"
      )
      defer { sqlite3_finalize(statement) }
      try bind(ISO8601DateFormatter().string(from: Date()), 1, statement)
      try bind(requestID.uuidString, 2, statement)
      try bind(action, 3, statement)
      try bind(outcome, 4, statement)
      try bind(keyID?.uuidString, 5, statement)
      try bind(fingerprint, 6, statement)
      try bind(byteCount.map(Int64.init), 7, statement)
      try bind(peer.uid.map(Int64.init), 8, statement)
      try bind(peer.gid.map(Int64.init), 9, statement)
      try bind(peer.pid.map(Int64.init), 10, statement)
      try bind(
        peer.uid == nil ? "unavailable" : "kernel-peer-at-connect;process-unverified", 11, statement
      )
      try bind(errorCode, 12, statement)
      guard sqlite3_step(statement) == SQLITE_DONE, sqlite3_changes(db) == 1 else {
        throw AuditError.unavailable
      }
      let id = sqlite3_last_insert_rowid(db)
      try execute(
        "DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT \(retentionLimit))"
      )
      let verification = try prepare(
        "SELECT COUNT(*) FROM events WHERE id=? AND request_id=? AND outcome=?")
      defer { sqlite3_finalize(verification) }
      try bind(id, 1, verification)
      try bind(requestID.uuidString, 2, verification)
      try bind(outcome, 3, verification)
      guard sqlite3_step(verification) == SQLITE_ROW,
        sqlite3_column_int64(verification, 0) == 1
      else { throw AuditError.unavailable }
      try validateFiles()
      try execute("COMMIT")
      return id
    } catch {
      try? execute("ROLLBACK")
      throw error
    }
  }
  private func checkLimit(_ limit: Int) throws {
    guard (1...200).contains(limit) else { throw AuditError.invalidLimit }
  }
  private func string(_ statement: OpaquePointer, _ index: Int32) -> String? {
    guard let value = sqlite3_column_text(statement, index) else { return nil }
    return String(cString: value)
  }
  private func integer(_ statement: OpaquePointer, _ index: Int32) -> Int64? {
    sqlite3_column_type(statement, index) == SQLITE_NULL
      ? nil : sqlite3_column_int64(statement, index)
  }
  public func list(limit: Int = 20, before: Int64? = nil) throws -> [AuditEvent] {
    try checkLimit(limit)
    guard before == nil || before! > 0 else { throw AuditError.invalidLimit }
    lock.lock()
    defer { lock.unlock() }
    if db == nil { return [] }
    try validateFiles()
    let statement = try prepare(
      "SELECT id,timestamp,request_id,action,outcome,key_id,fingerprint,byte_count,peer_uid,peer_gid,peer_pid,peer_identity,error_code FROM events WHERE (? IS NULL OR id < ?) ORDER BY id DESC LIMIT ?"
    )
    defer { sqlite3_finalize(statement) }
    try bind(before, 1, statement)
    try bind(before, 2, statement)
    try bind(Int64(limit), 3, statement)
    var events: [AuditEvent] = []
    while true {
      let result = sqlite3_step(statement)
      if result == SQLITE_DONE { return events }
      guard result == SQLITE_ROW else { throw AuditError.unavailable }
      guard
        [1, 2, 3, 4, 11].allSatisfy({
          sqlite3_column_type(statement, Int32($0)) == SQLITE_TEXT
            && sqlite3_column_bytes(statement, Int32($0)) <= 256
        }),
        [5, 6, 12].allSatisfy({
          sqlite3_column_type(statement, Int32($0)) == SQLITE_NULL
            || (sqlite3_column_type(statement, Int32($0)) == SQLITE_TEXT
              && sqlite3_column_bytes(statement, Int32($0)) <= 256)
        })
      else { throw AuditError.unavailable }
      events.append(
        AuditEvent(
          id: sqlite3_column_int64(statement, 0), timestamp: string(statement, 1)!,
          requestID: string(statement, 2)!, action: string(statement, 3)!,
          outcome: string(statement, 4)!,
          keyID: string(statement, 5), fingerprint: string(statement, 6),
          byteCount: integer(statement, 7).map(Int.init),
          peerUID: integer(statement, 8).flatMap(UInt32.init(exactly:)),
          peerGID: integer(statement, 9).flatMap(UInt32.init(exactly:)),
          peerPID: integer(statement, 10).flatMap(Int32.init(exactly:)),
          peerIdentity: string(statement, 11)!, errorCode: string(statement, 12)))
    }
  }
  /// Counts successful signatures, not requests or signing intents; limited to retained events.
  public func top(limit: Int = 20) throws -> [AuditKeySummary] {
    try checkLimit(limit)
    lock.lock()
    defer { lock.unlock() }
    if db == nil { return [] }
    try validateFiles()
    let statement = try prepare(
      "SELECT key_id,fingerprint,COUNT(*),MAX(timestamp) FROM events WHERE action='sign' AND outcome='success' AND key_id IS NOT NULL AND fingerprint IS NOT NULL GROUP BY key_id,fingerprint ORDER BY COUNT(*) DESC,key_id ASC LIMIT ?"
    )
    defer { sqlite3_finalize(statement) }
    try bind(Int64(limit), 1, statement)
    var values: [AuditKeySummary] = []
    while true {
      let result = sqlite3_step(statement)
      if result == SQLITE_DONE { return values }
      guard result == SQLITE_ROW else { throw AuditError.unavailable }
      guard
        [0, 1, 3].allSatisfy({
          sqlite3_column_type(statement, Int32($0)) == SQLITE_TEXT
            && sqlite3_column_bytes(statement, Int32($0)) <= 256
        })
      else { throw AuditError.unavailable }
      values.append(
        AuditKeySummary(
          keyID: string(statement, 0)!, fingerprint: string(statement, 1)!,
          count: Int(sqlite3_column_int64(statement, 2)), lastTimestamp: string(statement, 3)!))
    }
  }
}

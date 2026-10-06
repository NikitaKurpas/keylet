import ArgumentParser
import CryptoKit
import Foundation
import KeyletCore
import Security

// The legacy global flag is accepted anywhere before `--`. All commands, options,
// validation and help are handled by ArgumentParser; this normalization preserves
// existing `keylet --json keys ...` and `keylet keys ... --json` invocations.
let keyletVersion = AppVersion.read(executable: Bundle.main.executableURL)

/// Owns normalized CLI arguments and dispatches the command with the selected output mode.
struct CLIInvocation {
  let arguments: [String]
  let jsonRequested: Bool

  init(_ rawArguments: [String]) {
    let endOfOptions = rawArguments.firstIndex(of: "--") ?? rawArguments.endIndex
    jsonRequested = rawArguments[..<endOfOptions].contains("--json")
    arguments = rawArguments.enumerated().compactMap { index, argument in
      index < endOfOptions && argument == "--json" ? nil : argument
    }
  }

  /// Parses and runs the command, preserving ArgumentParser's help and version exits.
  func run() {
    var isParsing = true
    do {
      var command = try Keylet.parseAsRoot(arguments)
      isParsing = false
      try command.run()
    } catch {
      if Keylet.exitCode(for: error) == .success {
        writeHelpOrVersion(for: error)
        exit(0)
      }
      reportFailure(error, isParsing: isParsing)
      exit(1)
    }
  }

  private func writeHelpOrVersion(for error: Error) {
    let text = Keylet.fullMessage(for: error)
    guard jsonRequested else {
      print(text, terminator: text.hasSuffix("\n") ? "" : "\n")
      return
    }
    if arguments.contains("--version"), !arguments.contains("--help"), !arguments.contains("-h") {
      try? output(["ok": true, "version": text.trimmingCharacters(in: .whitespacesAndNewlines)])
    } else {
      try? output(["ok": true, "help": text])
    }
  }
}

let invocation = CLIInvocation(Array(CommandLine.arguments.dropFirst()))
let jsonRequested = invocation.jsonRequested

/// Writes a result object in the selected text or JSON format.
func output(_ data: [String: Any], prettyJSON: Bool = false) throws {
  if jsonRequested || prettyJSON {
    let encoded = try JSONSerialization.data(
      withJSONObject: data, options: [.prettyPrinted, .sortedKeys])
    print(String(decoding: encoded, as: UTF8.self))
  } else {
    for key in data.keys.sorted() { print("\(key): \(data[key]!)") }
  }
}

/// Encodes a value with the CLI's stable snake_case JSON key convention.
func encodedObject<T: Encodable>(_ value: T) throws -> Any {
  let encoder = JSONEncoder()
  encoder.keyEncodingStrategy = .convertToSnakeCase
  return try JSONSerialization.jsonObject(with: encoder.encode(value))
}

/// Parses a UUID argument or reports the CLI's invalid-arguments error.
func validatedUUID(_ text: String) throws -> UUID {
  guard let id = UUID(uuidString: text) else { throw AgentError.invalidArguments }
  return id
}

/// Returns the public fields exposed for a key, including its SSH fingerprint.
func recordJSON(_ record: KeyRecord) throws -> [String: Any] {
  [
    "id": record.id.uuidString, "label": record.label, "policy": record.policy.rawValue,
    "algorithm": "P256", "fingerprint": SSHWire.fingerprint(try record.blob()),
    "public_key": try record.openSSH(),
  ]
}

/// Resolves one key by UUID, or by exact label when the inventory is complete.
func selectedKey(id: UUID? = nil, label: String? = nil) throws -> KeyRecord {
  let inventory = KeyStore(context: try SigningContext.current()).inventory()
  let matches = inventory.keys.filter { id != nil ? $0.id == id : $0.label == label }
  guard id != nil || inventory.complete, matches.count == 1 else { throw AgentError.unavailable }
  return matches[0]
}

struct Keylet: ParsableCommand {
  static let configuration = CommandConfiguration(
    commandName: "keylet",
    abstract: "Dedicated Secure Enclave P256 keys and a foreground OpenSSH agent.",
    discussion:
      "Credential operations require a signed Keylet.app and authorized profile. Use SSH_AUTH_SOCK with stock ssh/git; no global settings are changed.",
    version: keyletVersion,
    subcommands: [Doctor.self, Version.self, Keys.self, Agent.self, WireProtocol.self, Audit.self])
  @Flag(help: "Return stable JSON, including errors. Accepted before or after the subcommand.")
  var json = false
  mutating func run() throws {
    if jsonRequested {
      try output(["ok": true, "help": Self.helpMessage()])
    } else {
      print(Self.helpMessage())
    }
  }
}

struct Version: ParsableCommand {
  static let configuration = CommandConfiguration(abstract: "Show the CLI version.")
  mutating func run() throws {
    if jsonRequested {
      try output(["ok": true, "version": keyletVersion])
    } else {
      print(keyletVersion)
    }
  }
}

struct Doctor: ParsableCommand {
  static let configuration = CommandConfiguration(
    abstract: "Check hardware and signing metadata without using keys or the audit database.")
  mutating func run() throws {
    let runtime = SigningContext.supportedRuntime
    let report = DoctorReport(
      version: keyletVersion, runtime: runtime, enclave: SecureEnclave.isAvailable,
      signingMetadata: runtime ? (try? SigningContext.current()) != nil : nil,
      socket: SocketAgent.defaultSocket)
    if jsonRequested {
      guard let object = try encodedObject(report) as? [String: Any] else {
        throw AgentError.unavailable
      }
      try output(object)
    } else {
      print(report.text)
    }
  }
}

struct Keys: ParsableCommand {
  static let configuration = CommandConfiguration(
    abstract: "Inspect, create or delete dedicated keys; no private-key export.",
    subcommands: [List.self, Resolve.self, Public.self, Create.self, Delete.self])
  struct List: ParsableCommand {
    static let configuration = CommandConfiguration(
      abstract: "Public inventory and protection-class completeness.")
    mutating func run() throws {
      let inventory = KeyStore(context: try SigningContext.current()).inventory()
      try output([
        "ok": true, "complete": inventory.complete,
        "unavailable_classes": inventory.unavailableClasses,
        "keys": try inventory.keys.map(recordJSON),
      ])
    }
  }

  struct Resolve: ParsableCommand {
    static let configuration = CommandConfiguration(
      abstract: "Resolve an exact unique label to a UUID.")
    @Option(help: "Exact key label.") var label: String
    func validate() throws { try KeyStore.validate(label: label) }
    mutating func run() throws {
      try output(["ok": true, "key": try recordJSON(selectedKey(label: label))])
    }
  }

  struct Public: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Export the public OpenSSH key only.")
    @Option(help: "Key UUID.") var id: String
    func validate() throws { _ = try validatedUUID(id) }
    mutating func run() throws {
      let record = try selectedKey(id: validatedUUID(id))
      if jsonRequested {
        try output(["ok": true, "key": try recordJSON(record)])
      } else {
        print(try record.openSSH())
      }
    }
  }

  struct Delete: ParsableCommand {
    static let warning =
      "Deletion is permanent: Secure Enclave keys cannot be exported or restored. A signature already in progress may finish; restart any older agent that caches keys and remove remote public-key authorizations separately."
    static let configuration = CommandConfiguration(
      abstract: "Permanently delete one exact UUID; preview with --dry-run first.",
      discussion: warning)
    @Option(help: "Exact key UUID; labels and prefixes are not accepted.") var id: String
    @Option(help: "Repeat the UUID to acknowledge permanent deletion (required without --dry-run).")
    var confirmId: String?
    @Flag(help: "Resolve public metadata without deleting; requires signed Keychain read access.")
    var dryRun = false

    func validate() throws {
      let target = try validatedUUID(id)
      if let confirmId {
        guard try validatedUUID(confirmId) == target else { throw AgentError.invalidArguments }
      } else if !dryRun {
        throw AgentError.invalidArguments
      }
    }

    mutating func run() throws {
      let store = KeyStore(context: try SigningContext.current())
      let target = try validatedUUID(id)
      let record =
        dryRun
        ? try KeyStore.deletionTarget(id: target, inventory: store.inventory())
        : try store.delete(id: target)
      try output([
        "ok": true, "dry_run": dryRun, "key_deleted": !dryRun,
        "key": try recordJSON(record), "warning": Self.warning,
      ])
    }
  }

  struct Create: ParsableCommand {
    static let configuration = CommandConfiguration(
      abstract: "Create one hardware-bound key; preview with --dry-run first.")
    @Option(help: "Immutable public key label.") var label: String
    @Option(help: "Protection policy: after-first-unlock, when-unlocked, or user-presence.")
    var policy: String
    @Flag(help: "Validate and preview without Keychain access or creating a key.") var dryRun =
      false
    func validate() throws {
      try KeyStore.validate(label: label)
      guard KeyPolicy(rawValue: policy) != nil else { throw AgentError.invalidArguments }
    }

    mutating func run() throws {
      guard let parsedPolicy = KeyPolicy(rawValue: policy) else {
        throw AgentError.invalidArguments
      }
      if dryRun {
        try output([
          "ok": true, "dry_run": true, "label": label, "policy": policy, "algorithm": "P256",
          "key_created": false,
        ])
      } else {
        let store = KeyStore(context: try SigningContext.current())
        try output([
          "ok": true, "key": try recordJSON(store.create(label: label, policy: parsedPolicy)),
        ])
      }
    }
  }
}

struct Agent: ParsableCommand {
  static let configuration = CommandConfiguration(
    abstract: "Serve all unattended keys in the foreground.")
  @Option(help: "Restrict the agent to one key UUID.") var key: String?
  @Option(help: "Absolute socket path in a user-owned 0700 directory.") var socket: String?
  func validate() throws {
    if let key { _ = try validatedUUID(key) }
  }
  mutating func run() throws {
    let store = KeyStore(context: try SigningContext.current())
    try SocketAgent.run(
      path: socket ?? SocketAgent.defaultSocket, store: store, id: try key.map(validatedUUID))
  }
}

struct WireProtocol: ParsableCommand {
  static let configuration = CommandConfiguration(
    commandName: "protocol", abstract: "Offline read-only SSH agent wire inspection.",
    subcommands: [Decode.self])
  struct Decode: ParsableCommand {
    static let configuration = CommandConfiguration(
      abstract: "Inspect a hexadecimal SSH agent payload without credentials.")
    @Option(help: "Hexadecimal payload, excluding the frame-length prefix.") var hex: String
    func validate() throws {
      guard !hex.isEmpty, hex.utf8.count % 2 == 0, hex.utf8.count <= SSHWire.maximumFrame * 2,
        hex.utf8.allSatisfy({
          (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0)
        })
      else { throw AgentError.invalidArguments }
    }

    mutating func run() throws {
      var data = Data()
      var index = hex.startIndex
      while index < hex.endIndex {
        let end = hex.index(index, offsetBy: 2)
        guard let byte = UInt8(hex[index..<end], radix: 16) else {
          throw AgentError.invalidArguments
        }
        data.append(byte)
        index = end
      }
      var reader = SSHReader(data)
      let type = try reader.byte()
      try output([
        "ok": true, "message_type": type, "bytes": data.count,
        "supported": [11, 13].contains(type),
      ])
    }
  }
}

struct Audit: ParsableCommand {
  static let configuration = CommandConfiguration(
    abstract: "Read the bounded local signing audit database; no Keychain access.",
    subcommands: [List.self, Top.self])
  struct List: ParsableCommand {
    static let configuration = CommandConfiguration(
      abstract: "Newest events first, with an exclusive event-ID cursor.")
    @Option(help: "Maximum events, 1–200.") var limit = 20
    @Option(help: "Return event IDs strictly smaller than this cursor.") var before: Int64?
    func validate() throws {
      guard (1...200).contains(limit), before.map({ $0 > 0 }) ?? true else {
        throw AgentError.invalidArguments
      }
    }

    mutating func run() throws {
      let events = try AuditStore(readOnly: true).list(limit: limit, before: before)
      // An extra empty page is acceptable when the final page is exactly full.
      let cursor: Any
      if events.count == limit, let last = events.last {
        cursor = last.id
      } else {
        cursor = NSNull()
      }
      try output(
        [
          "ok": true, "events": try encodedObject(events), "limit": limit, "next_before": cursor,
        ], prettyJSON: true)
    }
  }

  struct Top: ParsableCommand {
    static let configuration = CommandConfiguration(
      abstract: "Most successful signatures per key in the retained audit window.")
    @Option(help: "Maximum key summaries, 1–200.") var limit = 20
    func validate() throws {
      guard (1...200).contains(limit) else { throw AgentError.invalidArguments }
    }

    mutating func run() throws {
      try output(
        [
          "ok": true, "keys": try encodedObject(AuditStore(readOnly: true).top(limit: limit)),
          "limit": limit,
        ], prettyJSON: true)
    }
  }
}

private struct CLIErrorDetails {
  let code: String
  let message: String
}

/// Selects the stable machine code and user-facing message for a CLI failure.
private func errorDetails(for error: Error, isParsing: Bool) -> CLIErrorDetails {
  let fallbackCode = isParsing ? "invalid_arguments" : "operation_failed"
  switch error {
  case AgentError.invalidArguments, AuditError.invalidLimit:
    return CLIErrorDetails(
      code: "invalid_arguments",
      message: "Missing or invalid arguments; use the subcommand's --help")
  case KeyDeletionError.incompleteInventory:
    return CLIErrorDetails(
      code: "key_inventory_incomplete",
      message: "Deletion refused: unlock and obtain a complete keys list before retrying")
  case KeyDeletionError.notFound:
    return CLIErrorDetails(code: "key_not_found", message: "No key matches the exact UUID")
  case KeyDeletionError.ambiguous:
    return CLIErrorDetails(
      code: "key_ambiguous", message: "Deletion refused: multiple keys match the UUID")
  case AgentError.signingSetup:
    return CLIErrorDetails(
      code: "signing_setup_required",
      message: "Use the correctly signed Keylet.app bundle; run doctor and review signing setup")
  case AgentError.invalidPath:
    return CLIErrorDetails(
      code: "unsafe_socket_path",
      message:
        "Use an absolute short socket path in a user-owned 0700 directory; existing endpoints are refused"
    )
  case AuditError.unsafePath:
    return CLIErrorDetails(
      code: "audit_unsafe_path",
      message:
        "Audit database path or permissions are unsafe; review the private container directory"
    )
  case AuditError.unavailable:
    return CLIErrorDetails(
      code: "audit_unavailable",
      message:
        "Audit database unavailable or busy; retry and inspect the documented audit requirements")
  case AuditError.unsupportedSchema:
    return CLIErrorDetails(
      code: "audit_schema_unsupported",
      message:
        "Audit database schema is unsupported by this version; use a compatible Keylet release"
    )
  case let failure as KeychainFailure:
    return CLIErrorDetails(
      code: "keychain_\(failure.status)",
      message: "Dedicated Keychain operation failed; check provisioning and unlock state")
  case AgentError.unavailable:
    return CLIErrorDetails(
      code: fallbackCode,
      message: "Key or protection class unavailable, or label not unique; inspect keys list")
  case AgentError.invalidRequest:
    return CLIErrorDetails(
      code: fallbackCode,
      message: "Invalid or incomplete SSH payload; inspect protocol decode --help")
  case AgentError.io:
    return CLIErrorDetails(
      code: fallbackCode,
      message: "Local socket I/O failed; check endpoint permissions and running clients")
  default:
    let message =
      isParsing
      ? "Missing or invalid arguments; use the subcommand's --help"
      : "Operation failed; check doctor and the documented setup requirements"
    return CLIErrorDetails(code: fallbackCode, message: message)
  }
}

/// Writes a failure in the selected format, keeping parser diagnostics on stderr.
func reportFailure(_ error: Error, isParsing: Bool) {
  let details = errorDetails(for: error, isParsing: isParsing)
  if jsonRequested {
    try? output(["ok": false, "error": ["code": details.code, "message": details.message]])
  } else if isParsing {
    FileHandle.standardError.write(Data(Keylet.fullMessage(for: error).utf8))
  } else {
    FileHandle.standardError.write(Data((details.code + ": " + details.message + "\n").utf8))
  }
}

invocation.run()

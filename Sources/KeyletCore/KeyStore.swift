import CryptoKit
// Secure Enclave persistence adapted from Secretive and PR #819, pinned in NOTICE.md.
import Foundation
import LocalAuthentication
import Security

public enum KeyPolicy: String, Codable, CaseIterable, Sendable {
  case afterFirstUnlock = "after-first-unlock"
  case whenUnlocked = "when-unlocked"
  case userPresence = "user-presence"
  public var accessibility: CFString {
    self == .afterFirstUnlock
      ? kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
      : kSecAttrAccessibleWhenUnlockedThisDeviceOnly
  }
  public var flags: SecAccessControlCreateFlags {
    self == .userPresence ? [.privateKeyUsage, .userPresence] : [.privateKeyUsage]
  }
}
public struct KeyRecord: Codable, Equatable, Sendable {
  public let id: UUID
  public let label: String
  public let policy: KeyPolicy
  public let publicKey: Data
  public init(id: UUID, label: String, policy: KeyPolicy, publicKey: Data) {
    self.id = id
    self.label = label
    self.policy = policy
    self.publicKey = publicKey
  }
  public func blob() throws -> Data { try SSHWire.publicBlob(publicKey) }
  public func openSSH() throws -> String {
    SSHWire.algorithm + " " + (try blob()).base64EncodedString() + " " + label
  }
}
public struct KeychainFailure: Error {
  public let status: OSStatus
  public init(_ status: OSStatus) { self.status = status }
}
public struct Inventory: Sendable {
  public let keys: [KeyRecord]
  public let unavailableClasses: [String]
  public var complete: Bool { unavailableClasses.isEmpty }
}
public struct SigningContext: Sendable {
  public static let identifier = "me.kurpas.keylet"
  public let group: String
  public static var supportedRuntime: Bool {
    if #available(macOS 26.4, *) { return true }
    return false
  }
  public static func current() throws -> SigningContext {
    guard supportedRuntime else { throw AgentError.signingSetup }
    var code: SecCode?
    var staticCode: SecStaticCode?
    var info: CFDictionary?
    guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
      SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
      SecStaticCodeCheckValidity(staticCode, [], nil) == errSecSuccess,
      SecCodeCopySigningInformation(
        staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
      let values = info as? [String: Any],
      values[kSecCodeInfoIdentifier as String] as? String == identifier,
      let team = values[kSecCodeInfoTeamIdentifier as String] as? String,
      let entitlements = values[kSecCodeInfoEntitlementsDict as String] as? [String: Any],
      (entitlements["keychain-access-groups"] as? [String])?.contains(team + "." + identifier)
        == true,
      entitlements["com.apple.security.app-sandbox"] as? Bool == true,
      entitlements["com.apple.security.hardened-process"] as? Bool == true,
      entitlements["com.apple.security.hardened-process.enhanced-security-version-string"]
        as? String == "2",
      (values[kSecCodeInfoFlags as String] as? NSNumber).map({ $0.uint32Value & 0x10000 != 0 })
        == true,
      entitlements["com.apple.security.get-task-allow"] as? Bool != true
    else { throw AgentError.signingSetup }
    return SigningContext(group: team + "." + identifier)
  }
}
public final class KeyStore {
  public static let service = "me.kurpas.keylet.keys.v1"
  private let group: String
  public init(context: SigningContext) { group = context.group }
  private static func noninteractiveContext() -> LAContext {
    let context = LAContext()
    context.interactionNotAllowed = true
    return context
  }
  private func query(id: UUID? = nil) -> [CFString: Any] {
    var q: [CFString: Any] = [
      kSecClass: kSecClassGenericPassword, kSecAttrService: Self.service,
      kSecAttrAccessGroup: group, kSecUseDataProtectionKeychain: true,
      kSecAttrSynchronizable: false, kSecUseAuthenticationContext: Self.noninteractiveContext(),
    ]
    if let id { q[kSecAttrAccount] = id.uuidString }
    return q
  }
  /// Each class is queried independently on every inventory request: no stale all-or-nothing cache.
  public func inventory() -> Inventory {
    return Self.readInventory { name, protection in
      var q = query()
      q[kSecAttrAccessible] = protection
      q[kSecReturnAttributes] = true
      q[kSecMatchLimit] = kSecMatchLimitAll
      var output: CFTypeRef?
      let status = SecItemCopyMatching(q as CFDictionary, &output)
      if status == errSecItemNotFound { return [] }
      guard status == errSecSuccess, let rows = output as? [[CFString: Any]] else {
        throw KeychainFailure(status)
      }
      return try rows.map { row in
        guard let metadata = row[kSecAttrGeneric] as? Data,
          let account = row[kSecAttrAccount] as? String
        else { throw AgentError.unavailable }
        let record = try JSONDecoder().decode(KeyRecord.self, from: metadata)
        guard record.id.uuidString == account else { throw AgentError.unavailable }
        return record
      }
    }
  }
  /// Credential-free seam: failure of one protection class cannot hide the other.
  public static func readInventory(fetch: (String, CFString) throws -> [KeyRecord]) -> Inventory {
    var keys: [KeyRecord] = []
    var unavailable: [String] = []
    for (name, protection) in [
      ("when-unlocked", kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
      ("after-first-unlock", kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly),
    ] {
      do {
        let records = try fetch(name, protection)
        for record in records {
          guard record.policy.accessibility == protection else { throw AgentError.unavailable }
          try validate(label: record.label)
          _ = try record.blob()
        }
        keys.append(contentsOf: records)
      } catch { unavailable.append(name) }
    }
    return Inventory(
      keys: keys.sorted { $0.id.uuidString < $1.id.uuidString },
      unavailableClasses: unavailable.sorted())
  }
  public static func validate(label: String) throws {
    guard !label.isEmpty, label.utf8.count <= 80,
      label.unicodeScalars.allSatisfy({ $0.value >= 32 && $0.value < 127 && $0 != "\"" })
    else { throw AgentError.invalidArguments }
  }
  public func create(label: String, policy: KeyPolicy) throws -> KeyRecord {
    try Self.validate(label: label)
    var error: Unmanaged<CFError>?
    guard let acl = SecAccessControlCreateWithFlags(nil, policy.accessibility, policy.flags, &error)
    else {
      if let error { throw error.takeRetainedValue() as Error }
      throw AgentError.unavailable
    }
    let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: acl)
    let record = KeyRecord(
      id: UUID(), label: label, policy: policy, publicKey: key.publicKey.x963Representation)
    var q = query(id: record.id)
    q.removeValue(forKey: kSecUseAuthenticationContext)
    q[kSecAttrAccessible] = policy.accessibility
    q[kSecAttrLabel] = label
    q[kSecAttrGeneric] = try JSONEncoder().encode(record)
    q[kSecValueData] = key.dataRepresentation
    let status = SecItemAdd(q as CFDictionary, nil)
    guard status == errSecSuccess else { throw KeychainFailure(status) }
    return record
  }
  public func sign(_ data: Data, key record: KeyRecord) throws -> Data {
    // No mode update API: both protections and metadata are immutable after creation.
    var q = query(id: record.id)
    q[kSecAttrAccessible] = record.policy.accessibility
    q[kSecReturnData] = true
    q[kSecReturnAttributes] = true
    var value: CFTypeRef?
    let status = SecItemCopyMatching(q as CFDictionary, &value)
    guard status == errSecSuccess else { throw KeychainFailure(status) }
    guard let row = value as? [CFString: Any], let blob = row[kSecValueData] as? Data,
      let metadata = row[kSecAttrGeneric] as? Data,
      try JSONDecoder().decode(KeyRecord.self, from: metadata) == record
    else { throw AgentError.unavailable }
    let context = LAContext()
    context.interactionNotAllowed = true
    let key = try SecureEnclave.P256.Signing.PrivateKey(
      dataRepresentation: blob, authenticationContext: context)
    guard key.publicKey.x963Representation == record.publicKey else { throw AgentError.unavailable }
    return try key.signature(for: data).rawRepresentation
  }
}

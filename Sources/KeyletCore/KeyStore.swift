import CryptoKit
// Secure Enclave persistence adapted from Secretive and PR #819, pinned in NOTICE.md.
import Foundation
import LocalAuthentication
import Security

/// Immutable Keychain accessibility and Secure Enclave authorization policy.
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

/// Public metadata; contains no private or opaque key representation.
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

/// Public keys plus protection classes that could not be read.
public struct Inventory: Sendable {
  public let keys: [KeyRecord]
  public let unavailableClasses: [String]
  public var complete: Bool { unavailableClasses.isEmpty }
}

/// Dedicated Keychain group derived from the running executable’s verified signature.
public struct SigningContext: Sendable {
  public static let identifier = "me.kurpas.keylet"
  public let group: String
  public static var supportedRuntime: Bool {
    if #available(macOS 26.4, *) { return true }
    return false
  }

  /// Rejects unsupported runtimes and signatures outside the maintained security policy.
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
      let values = info as? [String: Any]
    else { throw AgentError.signingSetup }
    return try validated(signingInformation: values)
  }

  /// Validates signature metadata; native provisioning and policy enforcement remain OS duties.
  static func validated(signingInformation values: [String: Any]) throws -> SigningContext {
    guard
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

/// Creates and uses hardware-bound keys in the dedicated, nonsynchronizing Keychain group.
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
    var attributes: [CFString: Any] = [
      kSecClass: kSecClassGenericPassword, kSecAttrService: Self.service,
      kSecAttrAccessGroup: group, kSecUseDataProtectionKeychain: true,
      kSecAttrSynchronizable: false, kSecUseAuthenticationContext: Self.noninteractiveContext(),
    ]
    if let id { attributes[kSecAttrAccount] = id.uuidString }
    return attributes
  }

  /// Each class is queried independently on every inventory request: no stale all-or-nothing cache.
  public func inventory() -> Inventory {
    return Self.readInventory { _, protection in
      var attributes = query()
      attributes[kSecAttrAccessible] = protection
      attributes[kSecReturnAttributes] = true
      attributes[kSecMatchLimit] = kSecMatchLimitAll
      var output: CFTypeRef?
      let status = SecItemCopyMatching(attributes as CFDictionary, &output)
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

  /// Persists a new key with an immutable label and policy; never exports its private material.
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
    var attributes = query(id: record.id)
    attributes.removeValue(forKey: kSecUseAuthenticationContext)
    attributes[kSecAttrAccessible] = policy.accessibility
    attributes[kSecAttrLabel] = label
    attributes[kSecAttrGeneric] = try JSONEncoder().encode(record)
    attributes[kSecValueData] = key.dataRepresentation
    let status = SecItemAdd(attributes as CFDictionary, nil)
    guard status == errSecSuccess else { throw KeychainFailure(status) }
    return record
  }

  /// Reloads and matches stored metadata before signing without authentication UI.
  public func sign(_ data: Data, key record: KeyRecord) throws -> Data {
    // No mode update API: both protections and metadata are immutable after creation.
    var attributes = query(id: record.id)
    attributes[kSecAttrAccessible] = record.policy.accessibility
    attributes[kSecReturnData] = true
    attributes[kSecReturnAttributes] = true
    var value: CFTypeRef?
    let status = SecItemCopyMatching(attributes as CFDictionary, &value)
    guard status == errSecSuccess else { throw KeychainFailure(status) }
    guard let row = value as? [CFString: Any], let blob = row[kSecValueData] as? Data,
      let metadata = row[kSecAttrGeneric] as? Data,
      try JSONDecoder().decode(KeyRecord.self, from: metadata) == record
    else { throw AgentError.unavailable }
    let key = try SecureEnclave.P256.Signing.PrivateKey(
      dataRepresentation: blob, authenticationContext: Self.noninteractiveContext())
    guard key.publicKey.x963Representation == record.publicKey else { throw AgentError.unavailable }
    return try key.signature(for: data).rawRepresentation
  }
}

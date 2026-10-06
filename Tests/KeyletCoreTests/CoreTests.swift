import Foundation
import Security
import Testing

@testable import KeyletCore

// Public SEC1 fixture from Secretive; no private keys, Keychain operations or agents.
let publicFixture = Data(
  base64Encoded:
    "BOVEjgAA5PHqRgwykjN5qM21uWCHFSY/Sqo5gkHAkn+e1MMQKHOLga7ucB9b3mif33MBid59GRK9GEPVlMiSQwo=")!
func record(_ policy: KeyPolicy) -> KeyRecord {
  KeyRecord(
    id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!, label: "fixture", policy: policy,
    publicKey: publicFixture)
}
@Test func openSSHEncoding() throws {
  let blob = try SSHWire.publicBlob(publicFixture)
  #expect(
    blob.base64EncodedString()
      == "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOVEjgAA5PHqRgwykjN5qM21uWCHFSY/Sqo5gkHAkn+e1MMQKHOLga7ucB9b3mif33MBid59GRK9GEPVlMiSQwo="
  )
  #expect(SSHWire.fingerprint(blob) == "SHA256:/VQFeGyM8qKA8rB6WGMuZZxZLJln2UgXLk3F0uTF650")
  #expect(throws: (any Error).self) { try SSHWire.publicBlob(Data([4])) }
}
@Test func mpintEncoding() {
  #expect(SSHWire.mpint(Data([0, 0])).isEmpty)
  #expect(SSHWire.mpint(Data([0, 1])) == Data([1]))
  #expect(SSHWire.mpint(Data([0x80])) == Data([0, 0x80]))
}
@Test func signatureEnvelope() throws {
  let raw = Data(repeating: 1, count: 64)
  var outer = SSHReader(try SSHWire.signature(raw))
  var inner = SSHReader(try outer.string())
  #expect(outer.done)
  #expect(try inner.string() == Data(SSHWire.algorithm.utf8))
  var numbers = SSHReader(try inner.string())
  #expect(inner.done)
  #expect(try numbers.string() == Data(repeating: 1, count: 32))
  #expect(try numbers.string() == Data(repeating: 1, count: 32))
  #expect(numbers.done)
  #expect(throws: (any Error).self) { try SSHWire.signature(Data(repeating: 0, count: 63)) }
}
@Test func validRequestSignsExactlyPayload() throws {
  let blob = try record(.afterFirstUnlock).blob()
  let message = Data("public test message".utf8)
  let request = Data([13]) + SSHWire.string(blob) + SSHWire.string(message) + SSHWire.uint32(0)
  var calls = 0
  let response = AgentProtocol.reply(to: request, keys: [record(.afterFirstUnlock)]) { data, _ in
    calls += 1
    #expect(data == message)
    return Data(repeating: 1, count: 64)
  }
  #expect(calls == 1)
  #expect(response.first == 14)
  #expect(
    AgentProtocol.reply(to: Data([11]), keys: []) { _, _ in fatalError() }
      == Data([12, 0, 0, 0, 0]))
}
@Test func rejectedRequestsNeverSign() throws {
  let blob = try record(.afterFirstUnlock).blob()
  let valid = Data([13]) + SSHWire.string(blob) + SSHWire.string("message") + SSHWire.uint32(0)
  var invalid: [Data] = [
    Data(), Data([11, 0]), Data([13]), Data([17]), Data([18]), Data([22]), Data([27]),
  ]
  invalid.append(valid + Data([0]))
  invalid.append(Data([13]) + SSHWire.string(blob) + SSHWire.string("message") + SSHWire.uint32(1))
  invalid.append(
    Data([13]) + SSHWire.string("wrong") + SSHWire.string("message") + SSHWire.uint32(0))
  invalid.append(Data(repeating: 0, count: SSHWire.maximumFrame + 1))
  for length in 0..<valid.count { invalid.append(Data(valid.prefix(length))) }
  for input in invalid {
    #expect(
      AgentProtocol.reply(to: input, keys: [record(.afterFirstUnlock)]) { _, _ in
        Issue.record("Unexpected signing call")
        return Data()
      } == Data([5]))
  }
}
@Test func hostileLengthsAreBounded() {
  var reader = SSHReader(Data([255, 255, 255, 255]))
  #expect(throws: (any Error).self) { try reader.string() }
  for size in 0..<1024 {
    let data = Data((0..<size).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ size) })
    _ = AgentProtocol.reply(to: data, keys: []) { _, _ in
      Issue.record("Unexpected sign")
      return Data()
    }
  }
}
@Test func protectionPolicies() {
  #expect(
    KeyPolicy.afterFirstUnlock.accessibility == kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
  #expect(KeyPolicy.whenUnlocked.accessibility == kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
  #expect(KeyPolicy.afterFirstUnlock.flags == [.privateKeyUsage])
  #expect(KeyPolicy.userPresence.flags == [.privateKeyUsage, .userPresence])
}
@Test func independentClassRecovery() {
  var calls: [String] = []
  let partial = KeyStore.readInventory { name, _ in
    calls.append(name)
    if name == "when-unlocked" { throw AgentError.unavailable }
    return [record(.afterFirstUnlock)]
  }
  #expect(calls.count == 2)
  #expect(partial.keys.count == 1)
  #expect(!partial.complete)
  let recovered = KeyStore.readInventory { name, _ in
    name == "when-unlocked" ? [record(.whenUnlocked)] : []
  }
  #expect(recovered.complete)
  #expect(recovered.keys.count == 1)
  let wrong = KeyStore.readInventory { _, _ in [record(.afterFirstUnlock)] }
  #expect(!wrong.complete)
  #expect(wrong.keys.count == 1)
}
@Test func labelsAndPaths() throws {
  try KeyStore.validate(label: "safe label")
  for label in ["", "\n", "a\"b", String(repeating: "a", count: 81)] {
    #expect(throws: (any Error).self) { try KeyStore.validate(label: label) }
  }
  try SocketSafety.validate(path: "/tmp/example/socket")
  for path in ["relative", "/a\0b", "/" + String(repeating: "x", count: 104)] {
    #expect(throws: (any Error).self) { try SocketSafety.validate(path: path) }
  }
}

@Test func agentKeySelectionIncludesAllAvailableUnattendedKeys() {
  let unattended = record(.afterFirstUnlock)
  let unlocked = KeyRecord(id: UUID(), label: "other", policy: .whenUnlocked, publicKey: publicFixture)
  let inventory = Inventory(keys: [unattended, unlocked, record(.userPresence)], unavailableClasses: [])
  #expect(inventory.agentKeys() == [unattended, unlocked])
  #expect(inventory.agentKeys(id: unlocked.id) == [unlocked])
  #expect(inventory.agentKeys(id: UUID()).isEmpty)
  #expect(Inventory(keys: [], unavailableClasses: []).agentKeys().isEmpty)
  #expect(
    Inventory(keys: [unattended], unavailableClasses: ["when-unlocked"]).agentKeys() == [unattended])
}

private func signingInformationFixture() -> [String: Any] {
  [
    kSecCodeInfoIdentifier as String: SigningContext.identifier,
    kSecCodeInfoTeamIdentifier as String: "PUBLICTEAM",
    kSecCodeInfoFlags as String: NSNumber(value: 0x10000),
    kSecCodeInfoEntitlementsDict as String: [
      "keychain-access-groups": ["PUBLICTEAM." + SigningContext.identifier],
      "com.apple.security.app-sandbox": true,
      "com.apple.security.hardened-process": true,
      "com.apple.security.hardened-process.enhanced-security-version-string": "2",
    ],
  ]
}

@Test func signingMetadataRequiresEveryPolicyClaim() throws {
  let information = signingInformationFixture()
  #expect(
    try SigningContext.validated(signingInformation: information).group
      == "PUBLICTEAM.me.kurpas.keylet")
  for field in information.keys {
    var incomplete = information
    incomplete.removeValue(forKey: field)
    #expect(throws: AgentError.self) {
      try SigningContext.validated(signingInformation: incomplete)
    }
  }
  let entitlements = try #require(
    information[kSecCodeInfoEntitlementsDict as String] as? [String: Any])
  for field in entitlements.keys {
    var incomplete = entitlements
    incomplete.removeValue(forKey: field)
    var invalid = information
    invalid[kSecCodeInfoEntitlementsDict as String] = incomplete
    #expect(throws: AgentError.self) { try SigningContext.validated(signingInformation: invalid) }
  }
}

@Test func signingMetadataRejectsWrongGroupDebuggingAndRuntime() throws {
  let information = signingInformationFixture()
  let entitlements = try #require(
    information[kSecCodeInfoEntitlementsDict as String] as? [String: Any])
  for (field, value) in [
    ("keychain-access-groups", ["OTHERTEAM.me.kurpas.keylet"] as Any),
    ("com.apple.security.get-task-allow", true as Any),
    ("com.apple.security.hardened-process.enhanced-security-version-string", "*" as Any),
  ] {
    var invalidEntitlements = entitlements
    invalidEntitlements[field] = value
    var invalid = information
    invalid[kSecCodeInfoEntitlementsDict as String] = invalidEntitlements
    #expect(throws: AgentError.self) { try SigningContext.validated(signingInformation: invalid) }
  }
  var unsignedRuntime = information
  unsignedRuntime[kSecCodeInfoFlags as String] = NSNumber(value: 0)
  #expect(throws: AgentError.self) {
    try SigningContext.validated(signingInformation: unsignedRuntime)
  }
}

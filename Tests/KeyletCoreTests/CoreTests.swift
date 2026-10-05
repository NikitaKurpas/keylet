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
  let response = AgentProtocol.reply(to: request, keyBlob: blob, label: "fixture") { data in
    calls += 1
    #expect(data == message)
    return Data(repeating: 1, count: 64)
  }
  #expect(calls == 1)
  #expect(response.first == 14)
  #expect(
    AgentProtocol.reply(to: Data([11]), keyBlob: nil, label: "") { _ in fatalError() }
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
      AgentProtocol.reply(to: input, keyBlob: blob, label: "") { _ in
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
    _ = AgentProtocol.reply(to: data, keyBlob: nil, label: "") { _ in
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

import Foundation
import LocalAuthentication
import Security
import Testing

@testable import KeyletCore

@Test func deletionRefusesUncertainTargetsBeforeMutation() {
  let target = record(.afterFirstUnlock)
  for inventory in [
    Inventory(keys: [], unavailableClasses: []),
    Inventory(keys: [target, target], unavailableClasses: []),
    Inventory(keys: [target], unavailableClasses: ["when-unlocked"]),
  ] {
    #expect(throws: KeyDeletionError.self) {
      try KeyStore.delete(id: target.id, inventory: inventory, group: "FIXTURE.me.kurpas.keylet") {
        _ in
        Issue.record("Uncertain target reached deletion")
        return errSecSuccess
      }
    }
  }
}

@Test func deletionQueryIsExactAndPreservesOtherNamespaces() throws {
  for policy in KeyPolicy.allCases {
    let target = record(policy)
    let other = KeyRecord(id: UUID(), label: target.label, policy: policy, publicKey: publicFixture)
    let group = "FIXTURE.me.kurpas.keylet"
    var remaining = [target.id, other.id]
    var calls = 0
    let deleted = try KeyStore.delete(
      id: target.id, inventory: Inventory(keys: [target, other], unavailableClasses: []),
      group: group
    ) { query in
      calls += 1
      #expect(query.count == 8)
      #expect(query[kSecClass] as? String == kSecClassGenericPassword as String)
      #expect(query[kSecAttrService] as? String == KeyStore.service)
      #expect(query[kSecAttrAccessGroup] as? String == group)
      #expect(query[kSecUseDataProtectionKeychain] as? Bool == true)
      #expect(query[kSecAttrSynchronizable] as? Bool == false)
      #expect(query[kSecAttrAccount] as? String == target.id.uuidString)
      #expect(query[kSecAttrAccessible] as? String == policy.accessibility as String)
      #expect((query[kSecUseAuthenticationContext] as? LAContext)?.interactionNotAllowed == true)
      #expect(query[kSecValueData] == nil)
      // Simulate exact matching: unrelated account/service/group rows must survive.
      let rows: [(UUID, String, String)] = [
        (target.id, KeyStore.service, group), (other.id, KeyStore.service, group),
        (target.id, "other.service", group), (target.id, KeyStore.service, "OTHER.group"),
      ]
      let matched = rows.filter {
        $0.0.uuidString == query[kSecAttrAccount] as? String
          && $0.1 == query[kSecAttrService] as? String
          && $0.2 == query[kSecAttrAccessGroup] as? String
      }
      #expect(matched.count == 1)
      remaining.removeAll { $0 == matched.first?.0 }
      return errSecSuccess
    }
    #expect(deleted == target)
    #expect(calls == 1)
    #expect(remaining == [other.id])
  }
}

@Test func deletionDoesNotReportSuccessOnKeychainFailure() throws {
  let target = record(.afterFirstUnlock)
  for status in [
    errSecItemNotFound, errSecInteractionNotAllowed, errSecAuthFailed, errSecMissingEntitlement,
  ] {
    do {
      _ = try KeyStore.delete(
        id: target.id, inventory: Inventory(keys: [target], unavailableClasses: []),
        group: "FIXTURE"
      ) { _ in status }
      Issue.record("Deletion incorrectly succeeded")
    } catch let failure as KeychainFailure {
      #expect(failure.status == status)
    }
  }
}

@Test func deletionPreviewResolvesWithoutMutation() throws {
  let target = record(.whenUnlocked)
  #expect(
    try KeyStore.deletionTarget(
      id: target.id, inventory: Inventory(keys: [target], unavailableClasses: [])) == target)
  #expect(throws: KeyDeletionError.self) {
    try KeyStore.deletionTarget(
      id: UUID(), inventory: Inventory(keys: [target], unavailableClasses: []))
  }
}

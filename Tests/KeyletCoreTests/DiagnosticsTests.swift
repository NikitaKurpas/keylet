import Foundation
import Testing

@testable import KeyletCore

@Test func doctorDistinguishesUncheckedFromFailed() throws {
  let report = DoctorReport(
    version: "1.2.3", runtime: true, enclave: true, signingMetadata: true, socket: "/fixture/socket"
  )
  #expect(report.problems.isEmpty)
  #expect(report.checks["signing_metadata"] == "passed")
  for field in ["credential_access", "provisioning", "security_policy_enforcement"] {
    #expect(report.checks[field] == "not_checked")
  }
  #expect(report.text.contains("Signing metadata: valid"))
  #expect(report.text.contains("not checked"))
  let json = try #require(
    JSONSerialization.jsonObject(with: JSONEncoder().encode(report)) as? [String: Any])
  #expect(json["ok"] as? Bool == true)
  #expect(json["problems"] as? [String] == [])
  #expect(json["offline"] == nil && json["audit_path"] == nil && json["minimum_macos"] == nil)
}

@Test func doctorExplainsActualProblemsAndSkippedChecks() {
  let unsupported = DoctorReport(
    version: "development", runtime: false, enclave: false, signingMetadata: nil,
    socket: "/fixture/socket")
  #expect(unsupported.checks["macos"] == "failed")
  #expect(unsupported.checks["secure_enclave"] == "failed")
  #expect(unsupported.checks["signing_metadata"] == "not_checked")
  #expect(
    unsupported.problems == [
      "Use macOS 26.4 or later.", "Use an Apple Silicon Mac with a Secure Enclave.",
    ])
  let unsigned = DoctorReport(
    version: "development", runtime: true, enclave: true, signingMetadata: false,
    socket: "/fixture/socket")
  #expect(unsigned.checks["signing_metadata"] == "failed")
  #expect(unsigned.problems.count == 1)
  #expect(unsigned.text.contains("Problem: Use the correctly signed Keylet.app"))
}

@Test func unbundledVersionDoesNotInventARelease() {
  #expect(AppVersion.read(executable: nil) == "development")
  #expect(AppVersion.read(executable: URL(fileURLWithPath: "/tmp/fixture/keylet")) == "development")
}

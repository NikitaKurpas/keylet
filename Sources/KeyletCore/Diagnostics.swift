import Foundation

public enum AppVersion {
  /// Homebrew invokes the executable through a symlink outside its app bundle.
  public static func read(executable: URL?) -> String {
    guard let executable else { return "development" }
    let app = executable.resolvingSymlinksInPath()
      .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    guard app.pathExtension == "app",
      let version = Bundle(url: app)?.object(forInfoDictionaryKey: "CFBundleShortVersionString")
        as? String, !version.isEmpty
    else { return "development" }
    return version
  }
}

/// Reports only the existing hardware/runtime/signature checks; never probes credentials.
public struct DoctorReport: Encodable {
  public let ok = true
  public let version: String
  public let checks: [String: String]
  public let problems: [String]
  public let socket: String

  public init(version: String, runtime: Bool, enclave: Bool, signingMetadata: Bool?, socket: String)
  {
    self.version = version
    self.socket = socket
    checks = [
      "macos": runtime ? "passed" : "failed",
      "secure_enclave": enclave ? "passed" : "failed",
      "signing_metadata": signingMetadata.map { $0 ? "passed" : "failed" } ?? "not_checked",
      "credential_access": "not_checked", "provisioning": "not_checked",
      "security_policy_enforcement": "not_checked",
    ]
    var problems: [String] = []
    if !runtime { problems.append("Use macOS 26.4 or later.") }
    if !enclave { problems.append("Use an Apple Silicon Mac with a Secure Enclave.") }
    if signingMetadata == false {
      problems.append("Use the correctly signed Keylet.app; review signing setup in the README.")
    }
    self.problems = problems
  }

  public var text: String {
    let signature =
      checks["signing_metadata"] == "passed"
      ? "valid"
      : checks["signing_metadata"] == "failed" ? "invalid" : "not checked"
    var lines = [
      "Keylet \(version)",
      "macOS: \(checks["macos"] == "passed" ? "supported" : "unsupported")",
      "Secure Enclave: \(checks["secure_enclave"] == "passed" ? "available" : "unavailable")",
      "Signing metadata: \(signature)",
      "Credential access, provisioning and security policy enforcement: not checked.",
      "Socket: \(socket)",
    ]
    lines += problems.map { "Problem: " + $0 }
    return lines.joined(separator: "\n")
  }
}

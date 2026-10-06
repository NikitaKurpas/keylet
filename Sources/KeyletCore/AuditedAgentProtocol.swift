import Foundation

/// Requires durable intent and completion before releasing a signature.
/// An intent without completion records an ambiguous attempt, not a successful signature.
public enum AuditedAgentProtocol {
  /// Records each request without storing its payload or signature.
  public static func reply(
    to payload: Data, keys: [KeyRecord],
    audit: AuditStore, sign: (Data, KeyRecord) throws -> Data
  ) -> Data {
    reply(
      to: payload, keys: keys,
      record: { outcome, action, count, error, key in
        try audit.append(
          action: action, outcome: outcome, keyID: key?.id,
          fingerprint: try key.map { SSHWire.fingerprint(try $0.blob()) }, byteCount: count,
          errorCode: error)
      }, sign: sign)
  }

  // Inject persistence only for credential-free fault tests.
  static func reply(
    to payload: Data, keys: [KeyRecord],
    record: (String, String, Int?, String?, KeyRecord?) throws -> Void,
    sign: (Data, KeyRecord) throws -> Data
  ) -> Data {
    let action = auditAction(for: payload)
    var signingAttempted = false
    let response = AgentProtocol.reply(to: payload, keys: keys) { data, key in
      signingAttempted = true
      return try auditedSignature(
        for: data, key: key,
        record: { outcome, errorCode in
          try record(outcome, action, data.count, errorCode, key)
        }, sign: { try sign($0, key) })
    }
    guard !signingAttempted else { return response }

    let rejected = response == AgentProtocol.failure
    do {
      try record(
        rejected ? "rejected" : "success", action, nil,
        rejected ? "invalid-request" : nil, nil)
      return response
    } catch {
      return AgentProtocol.failure
    }
  }

  private static func auditAction(for payload: Data) -> String {
    switch payload.first.flatMap(SSHAgentMessage.init(rawValue:)) {
    case .signRequest: return "sign"
    case .requestIdentities: return "identities"
    default: return "unsupported"
    }
  }

  /// Persists intent before signing and withholds the signature if completion cannot commit.
  private static func auditedSignature(
    for data: Data, key: KeyRecord, record: (String, String?) throws -> Void,
    sign: (Data) throws -> Data
  ) throws -> Data {
    guard key.policy != .userPresence else {
      try record("rejected", "signing-unavailable")
      throw AgentError.unavailable
    }
    try record("intent", nil)

    let signature: Data
    do {
      signature = try sign(data)
      _ = try SSHWire.signature(signature)
    } catch {
      try? record("failure", "signing-unavailable")
      throw AgentError.unavailable
    }
    try record("success", nil)
    return signature
  }
}

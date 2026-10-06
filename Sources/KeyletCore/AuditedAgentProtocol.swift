import Foundation

/// Requires durable intent and completion before releasing a signature.
/// An intent without completion records an ambiguous attempt, not a successful signature.
public enum AuditedAgentProtocol {
  /// Records each request without storing its payload or signature.
  public static func reply(
    to payload: Data, key: KeyRecord?, peer: AuditPeer,
    audit: AuditStore, sign: (Data) throws -> Data
  ) -> Data {
    reply(
      to: payload, key: key,
      record: { outcome, request, action, count, error in
        try audit.append(
          requestID: request, action: action, outcome: outcome, keyID: key?.id,
          fingerprint: try key.map { SSHWire.fingerprint(try $0.blob()) }, byteCount: count,
          peer: peer, errorCode: error)
      }, sign: sign)
  }

  // Inject persistence only for credential-free fault tests.
  static func reply(
    to payload: Data, key: KeyRecord?,
    record: (String, UUID, String, Int?, String?) throws -> Void,
    sign: (Data) throws -> Data
  ) -> Data {
    let requestID = UUID()
    let action = auditAction(for: payload)
    var signingAttempted = false
    let response = AgentProtocol.reply(
      to: payload, keyBlob: try? key?.blob(), label: key?.label ?? "unavailable"
    ) { data in
      signingAttempted = true
      return try auditedSignature(
        for: data, key: key,
        record: { outcome, errorCode in
          try record(outcome, requestID, action, data.count, errorCode)
        }, sign: sign)
    }
    guard !signingAttempted else { return response }

    let rejected = response == AgentProtocol.failure
    do {
      try record(
        rejected ? "rejected" : "success", requestID, action, nil,
        rejected ? "invalid-request" : nil)
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
    for data: Data, key: KeyRecord?, record: (String, String?) throws -> Void,
    sign: (Data) throws -> Data
  ) throws -> Data {
    guard let key, key.policy != .userPresence else {
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

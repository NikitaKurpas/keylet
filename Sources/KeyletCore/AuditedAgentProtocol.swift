import Foundation

/// Audit intent must commit before calling the signer. Completion must commit before returning
/// a signature. If completion fails, a signature may already have been computed but is withheld;
/// a retained intent with no completion is an ambiguous attempt, not proof of a signature.
public enum AuditedAgentProtocol {
  public static func reply(
    to payload: Data, key: KeyRecord?, peer: AuditPeer,
    audit: AuditStore, sign: (Data) throws -> Data
  ) -> Data {
    reply(
      to: payload, key: key, peer: peer,
      record: { outcome, request, action, count, error in
        try audit.append(
          requestID: request, action: action, outcome: outcome, keyID: key?.id,
          fingerprint: try key.map { SSHWire.fingerprint(try $0.blob()) }, byteCount: count,
          peer: peer, errorCode: error)
      }, sign: sign)
  }
  // Inject persistence only for credential-free fault tests.
  static func reply(
    to payload: Data, key: KeyRecord?, peer: AuditPeer,
    record: (String, UUID, String, Int?, String?) throws -> Void,
    sign: (Data) throws -> Data
  ) -> Data {
    let requestID = UUID()
    let action = payload.first == 13 ? "sign" : payload.first == 11 ? "identities" : "unsupported"
    var attempted = false
    var persistenceFailed = false
    let response = AgentProtocol.reply(
      to: payload, keyBlob: try? key?.blob(), label: key?.label ?? "unavailable"
    ) { data in
      attempted = true
      guard let key, key.policy != .userPresence else {
        try record("rejected", requestID, action, data.count, "signing-unavailable")
        throw AgentError.unavailable
      }
      do { try record("intent", requestID, action, data.count, nil) } catch {
        persistenceFailed = true
        throw error
      }
      let result: Data
      do {
        result = try sign(data)
        // Encoding/shape failures must never be logged as success.
        _ = try SSHWire.signature(result)
      } catch {
        do { try record("failure", requestID, action, data.count, "signing-unavailable") } catch {
          persistenceFailed = true
        }
        throw AgentError.unavailable
      }
      do { try record("success", requestID, action, data.count, nil) } catch {
        persistenceFailed = true
        throw error
      }
      return result
    }
    if !attempted && !persistenceFailed {
      do {
        try record(
          response.first == 5 ? "rejected" : "success", requestID, action, nil,
          response.first == 5 ? "invalid-request" : nil)
      } catch { return Data([5]) }
    }
    return response
  }
}

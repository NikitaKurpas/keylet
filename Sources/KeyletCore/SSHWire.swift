import CryptoKit
// Adapted from Secretive SSHProtocolKit at 9edc8799009a9d4fb30b45c13689d19e7c31a3c7.
// Copyright (c) 2020 Max Goedjen. MIT; see LICENSE and NOTICE.md.
import Foundation

public enum AgentError: Error {
  case invalidRequest, unavailable, invalidPath
  case io(Int32)
  case invalidArguments, signingSetup
}

/// Encodes P256 keys, signatures, and length-prefixed fields in SSH wire format.
public enum SSHWire {
  public static let maximumFrame = 256 * 1024
  public static let algorithm = "ecdsa-sha2-nistp256"
  public static func uint32(_ value: UInt32) -> Data {
    Data([
      UInt8(value >> 24), UInt8((value >> 16) & 255), UInt8((value >> 8) & 255), UInt8(value & 255),
    ])
  }

  public static func string(_ data: Data) -> Data { uint32(UInt32(data.count)) + data }
  public static func string(_ text: String) -> Data { string(Data(text.utf8)) }
  /// Validates and wraps an X9.63 public key as an SSH identity.
  public static func publicBlob(_ x963: Data) throws -> Data {
    _ = try P256.Signing.PublicKey(x963Representation: x963)
    return string(algorithm) + string("nistp256") + string(x963)
  }

  public static func fingerprint(_ blob: Data) -> String {
    "SHA256:"
      + Data(SHA256.hash(data: blob)).base64EncodedString().replacingOccurrences(of: "=", with: "")
  }

  /// Removes leading zeros and preserves the sign of an unsigned integer.
  public static func mpint(_ bytes: Data) -> Data {
    guard let first = bytes.firstIndex(where: { $0 != 0 }) else { return Data() }
    let trimmed = Data(bytes[first...])
    return bytes[first] >= 0x80 ? Data([0]) + trimmed : trimmed
  }

  /// Wraps a 64-byte P256 signature as the SSH agent signature field.
  public static func signature(_ raw: Data) throws -> Data {
    guard raw.count == 64 else { throw AgentError.invalidRequest }
    let r = mpint(Data(raw.prefix(32)))
    let s = mpint(Data(raw.suffix(32)))
    return string(string(algorithm) + string(string(r) + string(s)))
  }
}

/// Reads bounded SSH fields; truncated or oversized fields throw `invalidRequest`.
public struct SSHReader {
  private let bytes: [UInt8]
  private var offset = 0
  public init(_ data: Data) { bytes = Array(data) }
  public var done: Bool { offset == bytes.count }
  public mutating func byte() throws -> UInt8 {
    guard offset < bytes.count else { throw AgentError.invalidRequest }
    defer { offset += 1 }
    return bytes[offset]
  }

  public mutating func uint32() throws -> UInt32 {
    guard bytes.count - offset >= 4 else { throw AgentError.invalidRequest }
    var result: UInt32 = 0
    for _ in 0..<4 { result = (result << 8) | UInt32(try byte()) }
    return result
  }

  public mutating func string() throws -> Data {
    let count = Int(try uint32())
    guard count <= SSHWire.maximumFrame, count <= bytes.count - offset else {
      throw AgentError.invalidRequest
    }
    defer { offset += count }
    return Data(bytes[offset..<offset + count])
  }
}

enum SSHAgentMessage: UInt8 {
  case failure = 5
  case requestIdentities = 11
  case identities = 12
  case signRequest = 13
  case signResponse = 14

  var payload: Data { Data([rawValue]) }
}

/// Handles identity and signing requests, returning failure for all other operations.
public enum AgentProtocol {
  static let failure = SSHAgentMessage.failure.payload
  /// Input is one bounded payload without its outer length. Only identity/sign operations are supported.
  public static func reply(
    to payload: Data, keys: [KeyRecord], sign: (Data, KeyRecord) throws -> Data
  ) -> Data {
    do {
      guard !payload.isEmpty, payload.count <= SSHWire.maximumFrame else {
        throw AgentError.invalidRequest
      }
      var reader = SSHReader(payload)
      switch SSHAgentMessage(rawValue: try reader.byte()) {
      case .requestIdentities:
        guard reader.done else { throw AgentError.invalidRequest }
        var response = SSHAgentMessage.identities.payload + SSHWire.uint32(UInt32(keys.count))
        for key in keys {
          response += SSHWire.string(try key.blob()) + SSHWire.string(key.label)
          guard response.count <= SSHWire.maximumFrame else { throw AgentError.invalidRequest }
        }
        return response
      case .signRequest:
        let requestedKey = try reader.string()
        let data = try reader.string()
        let flags = try reader.uint32()
        guard reader.done, flags == 0,
          let key = try keys.first(where: { try $0.blob() == requestedKey })
        else {
          throw AgentError.invalidRequest
        }
        return SSHAgentMessage.signResponse.payload + (try SSHWire.signature(sign(data, key)))
      default:
        // Includes add/remove/lock/forwarding extensions: never import keys.
        return failure
      }
    } catch { return failure }
  }
}

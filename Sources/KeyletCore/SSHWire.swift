import CryptoKit
// Adapted from Secretive SSHProtocolKit at 9edc8799009a9d4fb30b45c13689d19e7c31a3c7.
// Copyright (c) 2020 Max Goedjen. MIT; see LICENSE and NOTICE.md.
import Foundation

public enum AgentError: Error {
  case invalidRequest, unavailable, invalidPath
  case io(Int32)
  case invalidArguments, signingSetup
}
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
  public static func publicBlob(_ x963: Data) throws -> Data {
    _ = try P256.Signing.PublicKey(x963Representation: x963)
    return string(algorithm) + string("nistp256") + string(x963)
  }
  public static func fingerprint(_ blob: Data) -> String {
    "SHA256:"
      + Data(SHA256.hash(data: blob)).base64EncodedString().replacingOccurrences(of: "=", with: "")
  }
  public static func mpint(_ bytes: Data) -> Data {
    guard let first = bytes.firstIndex(where: { $0 != 0 }) else { return Data() }
    let trimmed = Data(bytes[first...])
    return trimmed.first! >= 0x80 ? Data([0]) + trimmed : trimmed
  }
  public static func signature(_ raw: Data) throws -> Data {
    guard raw.count == 64 else { throw AgentError.invalidRequest }
    let r = mpint(Data(raw.prefix(32)))
    let s = mpint(Data(raw.suffix(32)))
    return string(string(algorithm) + string(string(r) + string(s)))
  }
}
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
public enum AgentProtocol {
  /// Input is one bounded payload without its outer length. Only identity/sign operations are supported.
  public static func reply(
    to payload: Data, keyBlob: Data?, label: String, sign: (Data) throws -> Data
  ) -> Data {
    do {
      guard !payload.isEmpty, payload.count <= SSHWire.maximumFrame else {
        throw AgentError.invalidRequest
      }
      var reader = SSHReader(payload)
      switch try reader.byte() {
      case 11:
        guard reader.done else { throw AgentError.invalidRequest }
        guard let keyBlob else { return Data([12]) + SSHWire.uint32(0) }
        return Data([12]) + SSHWire.uint32(1) + SSHWire.string(keyBlob) + SSHWire.string(label)
      case 13:
        let requested = try reader.string()
        let data = try reader.string()
        let flags = try reader.uint32()
        guard reader.done, flags == 0, let keyBlob, requested == keyBlob else {
          throw AgentError.invalidRequest
        }
        return Data([14]) + (try SSHWire.signature(sign(data)))
      default:
        // Includes add/remove/lock/forwarding extensions: never import keys.
        return Data([5])
      }
    } catch { return Data([5]) }
  }
}

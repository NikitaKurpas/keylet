import Foundation

/// Serializes CLI envelopes without Foundation collection descriptions or private fields.
public enum CLIOutput {
  public static func json(_ data: [String: Any]) throws -> String {
    let encoded = try JSONSerialization.data(
      withJSONObject: data, options: [.prettyPrinted, .sortedKeys])
    return String(decoding: encoded, as: UTF8.self)
  }
}

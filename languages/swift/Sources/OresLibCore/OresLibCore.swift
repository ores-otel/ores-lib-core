import Foundation
public let oresRedacted = "[REDACTED]"
private let sensitiveFields: Set<String> = ["authorization","cookie","password","secret","token","access_token","refresh_token","id_token","client_secret","private_key","totp_seed","webauthn_challenge","face_image","face_template","fingerprint_image","fingerprint_template","biometric_template","voiceprint"]
private func compact(_ value: String) -> String { value.lowercased().unicodeScalars.filter { CharacterSet.alphanumerics.contains($0) }.map(String.init).joined() }
public func isSensitiveField(_ key: String) -> Bool { let normalized=compact(key); return sensitiveFields.contains(where:{normalized == compact($0) || normalized.hasSuffix(compact($0))}) }
public func validCorrelationId(_ value: String) -> Bool { (8...128).contains(value.count) && value.unicodeScalars.allSatisfy { CharacterSet.alphanumerics.contains($0) || "._:-".unicodeScalars.contains($0) } }
public struct Secret<Value>: CustomStringConvertible { private let value: Value; public init(_ value:Value){self.value=value}; public func expose<Result>(_ action:(Value)->Result)->Result{action(value)}; public var description:String{oresRedacted} }

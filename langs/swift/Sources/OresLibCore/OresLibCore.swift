import Foundation
public let oresRedacted = "[REDACTED]"
private let sensitiveFields: Set<String> = ["authorization","cookie","password","secret","token","access_token","refresh_token","id_token","client_secret","private_key","totp_seed","webauthn_challenge","face_image","face_template","fingerprint_image","fingerprint_template","biometric_template","voiceprint"]
private func compact(_ value: String) -> String { value.lowercased().unicodeScalars.filter { CharacterSet.alphanumerics.contains($0) }.map(String.init).joined() }
public func isSensitiveField(_ key: String) -> Bool { let normalized=compact(key); return sensitiveFields.contains(where:{normalized == compact($0) || normalized.hasSuffix(compact($0))}) }
public func validCorrelationId(_ value: String) -> Bool { (8...128).contains(value.count) && value.unicodeScalars.allSatisfy { CharacterSet.alphanumerics.contains($0) || "._:-".unicodeScalars.contains($0) } }
public struct Secret<Value>: CustomStringConvertible { private let value: Value; public init(_ value:Value){self.value=value}; public func expose<Result>(_ action:(Value)->Result)->Result{action(value)}; public var description:String{oresRedacted} }
public let directoryAdminRole = "directory_admin"
public let directoryRevocationsExecuteScope = "directory.revocations.execute"
public struct DirectoryGrant: Sendable {
  public let grantId: String; public let organizationId: String; public let projectIds: [String]?; public let scopes: [String]; public let roles: [String]; public let grantedAt: String; public let expiresAt: String?
  public init(grantId: String, organizationId: String, projectIds: [String]?, scopes: [String], roles: [String], grantedAt: String, expiresAt: String?) { self.grantId=grantId; self.organizationId=organizationId; self.projectIds=projectIds; self.scopes=scopes; self.roles=roles; self.grantedAt=grantedAt; self.expiresAt=expiresAt }
  public func allows(_ requiredScope: String) -> Bool { !requiredScope.contains("*") && roles.contains(directoryAdminRole) && scopes.contains(requiredScope) }
}
public func authorizedDirectoryOrganizations(_ requested: [String]?, requiredScope: String, grants: [DirectoryGrant]) -> [String] {
  let requestedSet = requested.map(Set.init)
  return Array(Set(grants.filter { $0.allows(requiredScope) && $0.projectIds == nil && (requestedSet == nil || requestedSet!.contains($0.organizationId)) }.map(\.organizationId))).sorted()
}

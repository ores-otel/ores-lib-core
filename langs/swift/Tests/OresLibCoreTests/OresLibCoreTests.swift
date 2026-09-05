import XCTest
@testable import OresLibCore

final class OresLibCoreTests: XCTestCase {
    func testSecurityHelpersFailClosed() {
        XCTAssertTrue(isSensitiveField("oauthAccessToken"))
        XCTAssertTrue(validCorrelationId("req-12345678"))
        XCTAssertFalse(validCorrelationId("bad space"))
        XCTAssertEqual(String(describing: Secret("must-not-escape")), oresRedacted)
    }

    func testDirectoryAuthorizationRequiresExactRoleAndScope() {
        let grant = DirectoryGrant(
            grantId: "20000000-0000-4000-8000-000000000001",
            organizationId: "10000000-0000-4000-8000-000000000001",
            projectIds: nil,
            scopes: [directoryRevocationsExecuteScope],
            roles: [directoryAdminRole],
            grantedAt: "2026-08-11T21:00:00Z",
            expiresAt: nil
        )
        XCTAssertEqual(
            authorizedDirectoryOrganizations(nil, requiredScope: directoryRevocationsExecuteScope, grants: [grant]),
            [grant.organizationId]
        )
        XCTAssertTrue(authorizedDirectoryOrganizations(nil, requiredScope: "directory.*", grants: [grant]).isEmpty)
        let projectBounded = DirectoryGrant(
            grantId: grant.grantId,
            organizationId: grant.organizationId,
            projectIds: ["30000000-0000-4000-8000-000000000001"],
            scopes: grant.scopes,
            roles: grant.roles,
            grantedAt: grant.grantedAt,
            expiresAt: grant.expiresAt
        )
        XCTAssertTrue(authorizedDirectoryOrganizations(nil, requiredScope: directoryRevocationsExecuteScope, grants: [projectBounded]).isEmpty)
    }
}

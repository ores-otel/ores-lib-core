import XCTest
@testable import OresLibCore

final class OresLibCoreTests: XCTestCase {
    func testSecurityHelpersFailClosed() {
        XCTAssertTrue(isSensitiveField("oauthAccessToken"))
        XCTAssertTrue(validCorrelationId("req-12345678"))
        XCTAssertFalse(validCorrelationId("bad space"))
        XCTAssertEqual(String(describing: Secret("must-not-escape")), oresRedacted)
    }
}

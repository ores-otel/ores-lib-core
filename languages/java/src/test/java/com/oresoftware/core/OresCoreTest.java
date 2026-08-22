package com.oresoftware.core;

import java.util.Map;
import java.util.List;

public final class OresCoreTest {
  private OresCoreTest() {}
  public static void main(String[] args) {
    var redacted = OresCore.redactRecord(Map.of(
      "requestId", "req-12345678",
      "accessToken", "must-not-escape"
    ));
    if (!OresCore.REDACTED.equals(redacted.get("accessToken"))) {
      throw new AssertionError("credential field was not redacted");
    }
    if (!OresCore.validCorrelationId("req-12345678") || OresCore.validCorrelationId("bad space")) {
      throw new AssertionError("correlation validation drift");
    }
    if (!OresCore.REDACTED.equals(new OresCore.Secret<>("must-not-escape").toString())) {
      throw new AssertionError("secret serialization was not redacted");
    }
    var grant = new OresCore.DirectoryGrant(
      "20000000-0000-4000-8000-000000000001",
      "10000000-0000-4000-8000-000000000001",
      null,
      List.of(OresCore.DIRECTORY_REVOCATIONS_EXECUTE_SCOPE),
      List.of(OresCore.DIRECTORY_ADMIN_ROLE),
      "2026-08-11T21:00:00Z",
      null
    );
    if (OresCore.authorizedDirectoryOrganizations(null, OresCore.DIRECTORY_REVOCATIONS_EXECUTE_SCOPE, List.of(grant)).size() != 1
        || !OresCore.authorizedDirectoryOrganizations(null, "directory.*", List.of(grant)).isEmpty()) {
      throw new AssertionError("directory authorization did not fail closed");
    }
    var projectBounded = new OresCore.DirectoryGrant(
      grant.grantId(), grant.organizationId(), List.of("30000000-0000-4000-8000-000000000001"),
      grant.scopes(), grant.roles(), grant.grantedAt(), grant.expiresAt()
    );
    if (!OresCore.authorizedDirectoryOrganizations(null, OresCore.DIRECTORY_REVOCATIONS_EXECUTE_SCOPE, List.of(projectBounded)).isEmpty()) {
      throw new AssertionError("project grant was elevated to organization authority");
    }
  }
}

package com.oresoftware.core;

import java.util.Map;

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
  }
}

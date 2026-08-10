#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
LANGUAGES = {"rust", "typescript", "go", "python", "dart", "java", "swift"}
SKIP_PARTS = {
    ".git",
    "target",
    "node_modules",
    "__pycache__",
    ".dart_tool",
    "build",
    ".vendor",
    "zed_modules",
}
SKIP_SUFFIXES = {".pyc", ".class", ".o", ".a", ".so", ".dylib", ".dll", ".exe", ".jar"}
FORBIDDEN = re.compile(
    r"(?i)(BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,})"
)


def validate_dashboard_runtime() -> None:
    policy = json.loads(
        (ROOT / "contracts/shared-auth-dashboard-runtime.json").read_text(encoding="utf-8")
    )
    dependencies = policy["dependencies"]
    assert dependencies["interfaces"] == "ores-otel/ores-interfaces"
    assert dependencies["core"] == "ores-otel/ores-lib-core"
    assert dependencies["loggerPackage"] == "oresoftware/next-loggers"
    assert dependencies["loggerRepository"] == "ores-otel/ores.otel.log"

    authorization = policy["authorization"]
    assert authorization["requiresOnlineIntrospection"] is True
    assert authorization["exactAudienceRequired"] is True
    assert authorization["exactOrganizationMembershipRequired"] is True
    assert authorization["crossOrganizationFallbackAllowed"] is False
    assert authorization["productRoleClaimsAuthoritative"] is False
    assert authorization["directAuthDatabaseAccessAllowed"] is False

    pagination = policy["pagination"]
    assert 1 <= pagination["defaultLimit"] <= pagination["maximumLimit"] <= 200
    assert pagination["cursorOpaque"] is True
    assert pagination["offsetPaginationAllowed"] is False

    logging = policy["logging"]
    assert logging["globalProviderInstallationAllowed"] is False
    for forbidden_field in (
        "bearerTokensAllowed",
        "cookiesAllowed",
        "privateKeysAllowed",
        "totpSeedsAllowed",
        "rawBiometricMaterialAllowed",
        "highCardinalityIdentityLabelsAllowed",
    ):
        assert logging[forbidden_field] is False

    capabilities = policy["authenticationCapabilities"]
    assert capabilities["candidateOrContractAdvertisedAsEnabledAllowed"] is False
    assert capabilities["sshRequiresOnlineIntrospection"] is True
    assert capabilities["kerberosRequiresOnlineIntrospection"] is True
    assert capabilities["openpgpAuthority"] == "provenance_only"
    assert capabilities["rawBiometricRetentionAllowed"] is False


def main() -> int:
    deps = json.loads((ROOT / "contracts/dependencies.json").read_text(encoding="utf-8"))
    packages = {entry["package"] for entry in deps["dependencies"]}
    assert packages == {"ores-otel/ores-interfaces", "oresoftware/next-loggers"}
    assert deps["globalProviderInstallationAllowed"] is False
    assert deps["rawBiometricMaterialAllowed"] is False

    validate_dashboard_runtime()

    present = {path.name for path in (ROOT / "languages").iterdir() if path.is_dir()}
    assert LANGUAGES <= present, LANGUAGES - present
    for path in ROOT.rglob("*"):
        if path.resolve() == pathlib.Path(__file__).resolve():
            continue
        if any(part in SKIP_PARTS for part in path.parts) or path.suffix in SKIP_SUFFIXES:
            continue
        if path.is_file() and path.stat().st_size < 2_000_000:
            text = path.read_text(encoding="utf-8", errors="ignore")
            if match := FORBIDDEN.search(text):
                raise AssertionError(f"secret marker in {path}: {match.group(0)}")
    print(
        "core valid: "
        f"dependencies={len(packages)} languages={len(present)} dashboard_runtime=v1"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

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


def validate_shared_auth_data_model() -> None:
    contract = json.loads(
        (ROOT / "contracts/shared-auth-data-model.json").read_text(encoding="utf-8")
    )
    assert contract["wireContract"].endswith(
        "ores-interfaces/contracts/shared-auth/v1/schema.json"
    )
    assert contract["emailLookup"]["persistence"] == "hmac_sha256_only"
    assert contract["emailLookup"]["rawOrNormalizedEmailPersisted"] is False
    assert contract["emailLookup"]["rawOrNormalizedEmailLogged"] is False
    storage = contract["credentialStorage"]
    for field in (
        "privateKeysAllowed",
        "rawBiometricMaterialAllowed",
        "biometricTemplatesAllowed",
        "bearerTokensAllowed",
        "refreshTokensAllowed",
    ):
        assert storage[field] is False
    revocation = contract["revocation"]
    assert revocation["authorizationPermission"] == "sessions.revoke"
    assert revocation["authorizationGranularity"] == "per_organization"
    assert revocation["inaccessibleOrganizationIdentitiesDisclosed"] is False
    assert revocation["idempotencyScope"] == ["actor_subject", "idempotency_key"]
    assert revocation["sameKeyDifferentRequest"] == "conflict"

    sql_path = ROOT / contract["postgresMigration"]
    sql = sql_path.read_text(encoding="utf-8")
    for table in contract["entities"]:
        assert f"ores_shared_auth.{table}" in sql, f"missing SQL entity {table}"
    assert "UNIQUE (actor_subject, idempotency_key)" in sql
    assert "request_digest bytea" in sql
    assert "email_lookup_hmac bytea" in sql
    assert "position('*' IN email_redacted) > 0" in sql
    assert "auth_methods <@ ARRAY['jwt', 'oidc', 'webauthn'" in sql
    assert "authorization_verified boolean NOT NULL CHECK (authorization_verified)" in sql
    assert "authorization_policy = 'per_organization_sessions.revoke'" in sql
    assert "CHECK (NOT dry_run OR sessions_revoked = 0)" in sql
    assert "normalized_email " not in sql.lower()
    factor_table = re.search(
        r"CREATE TABLE IF NOT EXISTS ores_shared_auth\.factor \((.*?)\n\);",
        sql,
        flags=re.DOTALL,
    )
    assert factor_table, "factor table missing"
    factor_columns = factor_table.group(1).lower()
    for prohibited_column in (
        "private_key ",
        "private_key_material ",
        "biometric_template ",
        "face_image ",
        "fingerprint_image ",
        "totp_seed ",
    ):
        assert prohibited_column not in factor_columns
    for table in contract["entities"]:
        assert f"ALTER TABLE ores_shared_auth.{table} FORCE ROW LEVEL SECURITY;" in sql
    assert "REVOKE ALL ON ALL TABLES IN SCHEMA ores_shared_auth FROM PUBLIC;" in sql

    sources = "\n".join(
        (ROOT / "languages" / language / path).read_text(encoding="utf-8")
        for language, path in (
            ("rust", "src/lib.rs"),
            ("typescript", "src/index.js"),
            ("go", "core.go"),
            ("dart", "lib/ores_lib_core.dart"),
        )
    )
    for symbol in (
        "normalize_email_for_revocation",
        "normalizeEmailForRevocation",
        "NormalizeEmailForRevocation",
        "authorized_organizations",
        "authorizedOrganizations",
        "AuthorizedOrganizations",
        "classify_idempotency",
        "classifyIdempotency",
        "ClassifyIdempotency",
    ):
        assert symbol in sources, f"missing polyglot core symbol {symbol}"


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

    zpkg = (ROOT / ".zpkg.toml").read_text(encoding="utf-8")
    assert '"ores-otel/ores-interfaces" = "^0.1.0"' in zpkg
    assert '"oresoftware/next-loggers" = "^0.1.0"' in zpkg
    assert '[targets.postgres]' in zpkg
    assert 'dir = "database/postgres"' in zpkg

    validate_dashboard_runtime()
    validate_shared_auth_data_model()

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
        f"dependencies={len(packages)} languages={len(present)} "
        "dashboard_runtime=v1 shared_auth_data_model=v1"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

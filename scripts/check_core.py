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
    assert contract["wireContract"] == (
        "ores-otel/ores-interfaces/contracts/shared-auth-admin/v1/schema.json"
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
    assert revocation["authorizationPermission"] == "directory.revocations.execute"
    assert revocation["authorizationGranularity"] == (
        "directory_grant_organization_and_optional_projects"
    )
    assert revocation["inaccessibleOrganizationIdentitiesDisclosed"] is False
    assert revocation["idempotencyScope"] == [
        "actor_principal_id",
        "idempotency_key_hmac",
    ]
    assert revocation["sameKeyDifferentRequest"] == "conflict"
    assert revocation["centralFenceRequired"] is True
    assert revocation["phishingResistantAal2StepUpRequired"] is True
    assert revocation["commitAuthorizationSingleUseRequired"] is True
    assert revocation["commitAuthorizationBoundFields"] == [
        "preview_id",
        "principal_id",
        "selected_scopes",
        "authorized_actor",
        "verified_step_up",
    ]
    assert revocation["commitAuthorizationExpiryBound"] == (
        "min(preview_expires_at,step_up_fresh_until)"
    )
    assert revocation["productionCapabilityEnabled"] is False
    assert "auth-epoch fence" in revocation["disabledReason"]
    assert "per-provider target state" in revocation["disabledReason"]
    assert set(revocation["wireContracts"]) == {
        "AdminRevocationTokenExchangeRequest",
        "AdminRevocationTokenExchangeResult",
        "PrincipalSearchRequest",
        "PrincipalSearchResult",
        "PrincipalSelectionRequest",
        "PrincipalSelectionResult",
        "GlobalRevocationPreviewRequest",
        "GlobalRevocationPreview",
        "GlobalRevocationCommitAuthorization",
        "GlobalRevocationRequest",
        "GlobalRevocationOperation",
    }

    exchange = contract["revocationTokenExchange"]
    assert exchange["requestDiscriminator"] == "AdminRevocationTokenExchangeRequest"
    assert exchange["resultDiscriminator"] == "AdminRevocationTokenExchangeResult"
    assert exchange["audience"] == exchange["authorizedParty"] == (
        "shared-auth-web-server"
    )
    assert exchange["scope"] == "shared-auth:sessions:revoke:global"
    assert exchange["subjectTokenWriteOnly"] is True
    assert exchange["accessTokenWriteOnly"] is True
    assert exchange["maximumLifetimeSeconds"] == 300
    assert exchange["tokensLogged"] is False
    assert exchange["tokensPersisted"] is False

    directory = contract["directoryAdministration"]
    assert directory["wireDiscriminator"] == "DirectoryAdminGrantSet"
    assert directory["wireSchema"] == (
        "ores.shared-auth-admin-directory-grant-set/v1"
    )
    assert directory["requiredRole"] == "directory_admin"
    assert directory["scopeValues"] == [
        "directory.dashboard.read",
        "directory.users.read",
        "directory.sessions.read",
        "directory.roles.read",
        "directory.revocations.read",
        "directory.revocations.execute",
    ]
    assert directory["grantSetExpiresAtRequired"] is True
    assert directory["exactOrganizationMatchRequired"] is True
    assert directory["crossOrganizationFallbackAllowed"] is False
    assert directory["rawEmailsAllowed"] is False

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
    assert "role_key NOT IN ('directory_admin', 'directory_security_operator', 'directory_auditor')" in sql
    assert "'directory.revocations.execute'" in sql
    assert "array_position(permissions, 'directory.*') IS NULL" in sql
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
        (ROOT / "langs" / language / path).read_text(encoding="utf-8")
        for language, path in (
            ("rust", "src/lib.rs"),
            ("typescript", "src/index.js"),
            ("go", "core.go"),
            ("dart", "lib/ores_lib_core.dart"),
            ("python", "src/ores_lib_core/__init__.py"),
            ("java", "src/main/java/com/oresoftware/core/OresCore.java"),
            ("swift", "Sources/OresLibCore/OresLibCore.swift"),
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
    for symbol in (
        "DirectoryAdminGrant",
        "DirectoryGrant",
        "authorized_directory_organizations",
        "authorizedDirectoryOrganizations",
        "AuthorizedDirectoryOrganizations",
        "directory_admin",
        "directory.revocations.execute",
    ):
        assert symbol in sources, f"missing directory-grant core symbol {symbol}"

    boundary_guards = {
        "rust": "grant.project_ids.is_none()",
        "typescript": "grant.projectIds === undefined",
        "go": "grant.ProjectIDs != nil",
        "dart": "grant.projectIds == null",
        "python": "grant.project_ids is None",
        "java": "grant.projectIds() == null",
        "swift": "$0.projectIds == nil",
    }
    for language, guard in boundary_guards.items():
        source_path = {
            "rust": "src/lib.rs",
            "typescript": "src/index.js",
            "go": "core.go",
            "dart": "lib/ores_lib_core.dart",
            "python": "src/ores_lib_core/__init__.py",
            "java": "src/main/java/com/oresoftware/core/OresCore.java",
            "swift": "Sources/OresLibCore/OresLibCore.swift",
        }[language]
        source = (ROOT / "langs" / language / source_path).read_text(encoding="utf-8")
        assert guard in source, f"{language} elevates project-bound directory grants"


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

    rust_lock = ROOT / "langs/rust/Cargo.lock"
    assert rust_lock.is_file(), "Rust lockfile is required for locked verification"
    assert 'name = "ores-lib-core"' in rust_lock.read_text(encoding="utf-8")

    data_model_doc = (ROOT / "docs/shared-auth-data-model.md").read_text(encoding="utf-8")
    assert "contracts/shared-auth-admin/v1/schema.json" in data_model_doc
    assert "production capability" in data_model_doc

    validate_dashboard_runtime()
    validate_shared_auth_data_model()

    present = {path.name for path in (ROOT / "langs").iterdir() if path.is_dir()}
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

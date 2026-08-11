-- Canonical Shared Auth persistence model for PostgreSQL 15+ / Supabase.
-- The trusted web/API server is the only database client. Browser roles receive no grants.
-- Run through the migration owner in a transaction; the runtime role must have BYPASSRLS and
-- must perform online token introspection plus per-organization authorization first.

BEGIN;

CREATE SCHEMA IF NOT EXISTS ores_shared_auth;

CREATE TABLE IF NOT EXISTS ores_shared_auth.organization (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?$'),
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 256),
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'suspended', 'archived')),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp()
);

CREATE TABLE IF NOT EXISTS ores_shared_auth.project (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES ores_shared_auth.organization(id) ON DELETE RESTRICT,
    slug text NOT NULL CHECK (slug ~ '^[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?$'),
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 256),
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'suspended', 'archived')),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE (organization_id, slug),
    UNIQUE (id, organization_id)
);

CREATE TABLE IF NOT EXISTS ores_shared_auth.user_account (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_provider_subject text NOT NULL UNIQUE CHECK (char_length(identity_provider_subject) BETWEEN 1 AND 256),
    email_hmac_key_id text NOT NULL CHECK (email_hmac_key_id ~ '^[A-Za-z0-9._:-]{1,64}$'),
    email_lookup_hmac bytea NOT NULL CHECK (octet_length(email_lookup_hmac) = 32),
    email_redacted text NOT NULL CHECK (char_length(email_redacted) BETWEEN 3 AND 320 AND position('*' IN email_redacted) > 0),
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 256),
    state text NOT NULL DEFAULT 'invited' CHECK (state IN ('invited', 'active', 'suspended', 'deprovisioned')),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    last_authenticated_at timestamptz,
    UNIQUE (email_hmac_key_id, email_lookup_hmac)
);

COMMENT ON COLUMN ores_shared_auth.user_account.email_lookup_hmac IS
    'HMAC-SHA-256 of the in-memory canonical email using a KMS-managed pepper; never a plain or unkeyed email hash.';

CREATE TABLE IF NOT EXISTS ores_shared_auth.membership (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES ores_shared_auth.organization(id) ON DELETE RESTRICT,
    user_id uuid NOT NULL REFERENCES ores_shared_auth.user_account(id) ON DELETE RESTRICT,
    state text NOT NULL DEFAULT 'invited' CHECK (state IN ('invited', 'active', 'suspended', 'removed')),
    joined_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE (organization_id, user_id),
    UNIQUE (id, organization_id)
);

CREATE TABLE IF NOT EXISTS ores_shared_auth.role (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES ores_shared_auth.organization(id) ON DELETE RESTRICT,
    role_key text NOT NULL CHECK (role_key ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 256),
    permissions text[] NOT NULL DEFAULT '{}'::text[] CHECK (cardinality(permissions) <= 256),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CHECK (
        role_key NOT IN ('directory_admin', 'directory_security_operator', 'directory_auditor')
        OR (
            cardinality(permissions) BETWEEN 1 AND 6
            AND permissions <@ ARRAY[
                'directory.dashboard.read',
                'directory.users.read',
                'directory.sessions.read',
                'directory.roles.read',
                'directory.revocations.read',
                'directory.revocations.execute'
            ]::text[]
            AND array_position(permissions, 'directory.*') IS NULL
        )
    ),
    UNIQUE (organization_id, role_key),
    UNIQUE (id, organization_id)
);

CREATE TABLE IF NOT EXISTS ores_shared_auth.role_binding (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES ores_shared_auth.organization(id) ON DELETE RESTRICT,
    membership_id uuid NOT NULL,
    role_id uuid NOT NULL,
    project_id uuid,
    scope_kind text NOT NULL CHECK (scope_kind IN ('organization', 'project', 'repository')),
    scope_id text NOT NULL CHECK (char_length(scope_id) BETWEEN 1 AND 128),
    granted_by_subject text NOT NULL CHECK (char_length(granted_by_subject) BETWEEN 1 AND 256),
    granted_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    expires_at timestamptz,
    FOREIGN KEY (membership_id, organization_id)
        REFERENCES ores_shared_auth.membership(id, organization_id) ON DELETE RESTRICT,
    FOREIGN KEY (role_id, organization_id)
        REFERENCES ores_shared_auth.role(id, organization_id) ON DELETE RESTRICT,
    FOREIGN KEY (project_id, organization_id)
        REFERENCES ores_shared_auth.project(id, organization_id) ON DELETE RESTRICT,
    CHECK (
        (scope_kind = 'organization' AND project_id IS NULL AND scope_id = organization_id::text)
        OR (scope_kind = 'project' AND project_id IS NOT NULL AND scope_id = project_id::text)
        OR (scope_kind = 'repository' AND scope_id <> '')
    ),
    CHECK (expires_at IS NULL OR expires_at > granted_at),
    UNIQUE (membership_id, role_id, scope_kind, scope_id)
);

CREATE TABLE IF NOT EXISTS ores_shared_auth.session (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id_hmac bytea NOT NULL UNIQUE CHECK (octet_length(session_id_hmac) = 32),
    user_id uuid NOT NULL REFERENCES ores_shared_auth.user_account(id) ON DELETE RESTRICT,
    organization_id uuid NOT NULL REFERENCES ores_shared_auth.organization(id) ON DELETE RESTRICT,
    project_id uuid,
    client_id text NOT NULL CHECK (char_length(client_id) BETWEEN 1 AND 128),
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked', 'expired')),
    assurance text NOT NULL CHECK (assurance IN ('aal0', 'aal1', 'aal2', 'aal3')),
    auth_methods text[] NOT NULL CHECK (
        cardinality(auth_methods) BETWEEN 1 AND 16
        AND auth_methods <@ ARRAY['jwt', 'oidc', 'webauthn', 'totp', 'kerberos', 'ssh', 'openpgp', 'platform_biometric', 'recovery']::text[]
    ),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    last_seen_at timestamptz,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revocation_reason text CHECK (char_length(revocation_reason) <= 256),
    FOREIGN KEY (organization_id, user_id)
        REFERENCES ores_shared_auth.membership(organization_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (project_id, organization_id)
        REFERENCES ores_shared_auth.project(id, organization_id) ON DELETE RESTRICT,
    CHECK (expires_at > created_at),
    CHECK ((state = 'revoked') = (revoked_at IS NOT NULL))
);

COMMENT ON COLUMN ores_shared_auth.session.session_id_hmac IS
    'Keyed audit/lookup digest. Bearer tokens, refresh tokens, cookies, and raw provider session IDs are never stored.';

CREATE TABLE IF NOT EXISTS ores_shared_auth.factor (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES ores_shared_auth.user_account(id) ON DELETE RESTRICT,
    method text NOT NULL CHECK (method IN ('jwt', 'oidc', 'webauthn', 'totp', 'kerberos', 'ssh', 'openpgp', 'platform_biometric', 'recovery')),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'active', 'disabled', 'compromised')),
    external_credential_ref_hmac bytea CHECK (external_credential_ref_hmac IS NULL OR octet_length(external_credential_ref_hmac) = 32),
    public_key_fingerprint text CHECK (public_key_fingerprint IS NULL OR char_length(public_key_fingerprint) BETWEEN 16 AND 256),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    last_used_at timestamptz,
    CHECK (method <> 'platform_biometric' OR (external_credential_ref_hmac IS NULL AND public_key_fingerprint IS NULL))
);

COMMENT ON TABLE ores_shared_auth.factor IS
    'Metadata only. TOTP/recovery secrets, private keys, WebAuthn verifier material, and biometric samples/templates live only in their external authority and are not columns here.';

CREATE TABLE IF NOT EXISTS ores_shared_auth.revocation_operation (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_subject text NOT NULL CHECK (char_length(actor_subject) BETWEEN 1 AND 256),
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9._:-]{16,128}$'),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    email_hmac_key_id text NOT NULL CHECK (email_hmac_key_id ~ '^[A-Za-z0-9._:-]{1,64}$'),
    email_lookup_hmac bytea NOT NULL CHECK (octet_length(email_lookup_hmac) = 32),
    scope_mode text NOT NULL CHECK (scope_mode IN ('all_authorized_organizations', 'selected_organizations')),
    selected_organization_ids uuid[] NOT NULL DEFAULT '{}'::uuid[],
    reason text NOT NULL CHECK (reason IN ('admin_action', 'compromised', 'incident_response', 'offboarding', 'user_request')),
    dry_run boolean NOT NULL DEFAULT false,
    authorization_policy text NOT NULL DEFAULT 'per_organization_sessions.revoke'
        CHECK (authorization_policy = 'per_organization_sessions.revoke'),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'partial', 'denied', 'no_match')),
    authorized_organization_count integer NOT NULL DEFAULT 0 CHECK (authorized_organization_count >= 0),
    unprocessed_organization_count integer NOT NULL DEFAULT 0 CHECK (unprocessed_organization_count >= 0),
    matched_users integer NOT NULL DEFAULT 0 CHECK (matched_users >= 0),
    sessions_revoked integer NOT NULL DEFAULT 0 CHECK (sessions_revoked >= 0),
    sessions_already_inactive integer NOT NULL DEFAULT 0 CHECK (sessions_already_inactive >= 0),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    completed_at timestamptz,
    CHECK (
        (scope_mode = 'selected_organizations' AND cardinality(selected_organization_ids) BETWEEN 1 AND 500)
        OR (scope_mode = 'all_authorized_organizations' AND cardinality(selected_organization_ids) = 0)
    ),
    CHECK ((status = 'pending') = (completed_at IS NULL)),
    CHECK (NOT dry_run OR sessions_revoked = 0),
    UNIQUE (actor_subject, idempotency_key)
);

COMMENT ON COLUMN ores_shared_auth.revocation_operation.request_digest IS
    'A repeated actor/key pair is a replay only when this digest matches; otherwise return IDEMPOTENCY_KEY_REUSED.';

CREATE TABLE IF NOT EXISTS ores_shared_auth.revocation_organization_result (
    operation_id uuid NOT NULL REFERENCES ores_shared_auth.revocation_operation(id) ON DELETE RESTRICT,
    organization_id uuid NOT NULL REFERENCES ores_shared_auth.organization(id) ON DELETE RESTRICT,
    authorization_verified boolean NOT NULL CHECK (authorization_verified),
    outcome text NOT NULL CHECK (outcome IN ('revoked', 'no_active_sessions', 'failed')),
    matched_users integer NOT NULL DEFAULT 0 CHECK (matched_users >= 0),
    sessions_revoked integer NOT NULL DEFAULT 0 CHECK (sessions_revoked >= 0),
    sessions_already_inactive integer NOT NULL DEFAULT 0 CHECK (sessions_already_inactive >= 0),
    error_code text CHECK (error_code IS NULL OR error_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
    completed_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CHECK ((outcome = 'failed') = (error_code IS NOT NULL)),
    PRIMARY KEY (operation_id, organization_id)
);

CREATE TABLE IF NOT EXISTS ores_shared_auth.audit_event (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid REFERENCES ores_shared_auth.organization(id) ON DELETE RESTRICT,
    project_id uuid,
    actor_subject text NOT NULL CHECK (char_length(actor_subject) BETWEEN 1 AND 256),
    action text NOT NULL CHECK (action ~ '^[a-z][a-z0-9._:-]{2,127}$'),
    target_kind text NOT NULL CHECK (char_length(target_kind) BETWEEN 1 AND 64),
    target_id_hmac bytea NOT NULL CHECK (octet_length(target_id_hmac) = 32),
    outcome text NOT NULL CHECK (outcome IN ('allowed', 'denied', 'succeeded', 'failed')),
    reason_code text CHECK (reason_code IS NULL OR reason_code ~ '^[A-Z][A-Z0-9_]{0,127}$'),
    request_id text NOT NULL CHECK (char_length(request_id) BETWEEN 8 AND 128),
    trace_id text NOT NULL CHECK (char_length(trace_id) BETWEEN 8 AND 128),
    occurred_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES ores_shared_auth.project(id, organization_id) ON DELETE RESTRICT
);

COMMENT ON TABLE ores_shared_auth.audit_event IS
    'Append-only sanitized security events. Emit the same event through the injected ores.otel.log adapter; never attach emails, session IDs, bearer material, keys, or biometric data.';

CREATE OR REPLACE FUNCTION ores_shared_auth.reject_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit events are append-only' USING ERRCODE = '55000';
END;
$$;

DROP TRIGGER IF EXISTS audit_event_append_only ON ores_shared_auth.audit_event;
CREATE TRIGGER audit_event_append_only
BEFORE UPDATE OR DELETE ON ores_shared_auth.audit_event
FOR EACH ROW EXECUTE FUNCTION ores_shared_auth.reject_audit_mutation();

CREATE INDEX IF NOT EXISTS membership_user_idx ON ores_shared_auth.membership(user_id, organization_id);
CREATE INDEX IF NOT EXISTS role_binding_membership_idx ON ores_shared_auth.role_binding(membership_id, expires_at);
CREATE INDEX IF NOT EXISTS session_user_org_state_idx ON ores_shared_auth.session(user_id, organization_id, state);
CREATE INDEX IF NOT EXISTS session_expiry_idx ON ores_shared_auth.session(expires_at) WHERE state = 'active';
CREATE INDEX IF NOT EXISTS factor_user_state_idx ON ores_shared_auth.factor(user_id, state);
CREATE INDEX IF NOT EXISTS audit_event_org_time_idx ON ores_shared_auth.audit_event(organization_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS revocation_created_idx ON ores_shared_auth.revocation_operation(created_at DESC);

-- Direct browser/Supabase client access fails closed: RLS is forced and no policy is created.
-- The dedicated server role must have BYPASSRLS and is granted only by deployment-specific SQL.
ALTER TABLE ores_shared_auth.organization ENABLE ROW LEVEL SECURITY;
ALTER TABLE ores_shared_auth.organization FORCE ROW LEVEL SECURITY;
ALTER TABLE ores_shared_auth.project ENABLE ROW LEVEL SECURITY;
ALTER TABLE ores_shared_auth.project FORCE ROW LEVEL SECURITY;
ALTER TABLE ores_shared_auth.user_account ENABLE ROW LEVEL SECURITY;
ALTER TABLE ores_shared_auth.user_account FORCE ROW LEVEL SECURITY;
ALTER TABLE ores_shared_auth.membership ENABLE ROW LEVEL SECURITY;
ALTER TABLE ores_shared_auth.membership FORCE ROW LEVEL SECURITY;
ALTER TABLE ores_shared_auth.role ENABLE ROW LEVEL SECURITY;
ALTER TABLE ores_shared_auth.role FORCE ROW LEVEL SECURITY;
ALTER TABLE ores_shared_auth.role_binding ENABLE ROW LEVEL SECURITY;
ALTER TABLE ores_shared_auth.role_binding FORCE ROW LEVEL SECURITY;
ALTER TABLE ores_shared_auth.session ENABLE ROW LEVEL SECURITY;
ALTER TABLE ores_shared_auth.session FORCE ROW LEVEL SECURITY;
ALTER TABLE ores_shared_auth.factor ENABLE ROW LEVEL SECURITY;
ALTER TABLE ores_shared_auth.factor FORCE ROW LEVEL SECURITY;
ALTER TABLE ores_shared_auth.revocation_operation ENABLE ROW LEVEL SECURITY;
ALTER TABLE ores_shared_auth.revocation_operation FORCE ROW LEVEL SECURITY;
ALTER TABLE ores_shared_auth.revocation_organization_result ENABLE ROW LEVEL SECURITY;
ALTER TABLE ores_shared_auth.revocation_organization_result FORCE ROW LEVEL SECURITY;
ALTER TABLE ores_shared_auth.audit_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE ores_shared_auth.audit_event FORCE ROW LEVEL SECURITY;

REVOKE ALL ON SCHEMA ores_shared_auth FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA ores_shared_auth FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA ores_shared_auth FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ores_shared_auth FROM PUBLIC;

COMMIT;

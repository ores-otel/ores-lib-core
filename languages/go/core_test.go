package orescore
import "testing"
func TestRedaction(t *testing.T) { if RedactRecord(map[string]any{"oauth_access-token":"x"})["oauth_access-token"] != Redacted { t.Fatal("credential not redacted") } }
func TestCorrelation(t *testing.T) { if !ValidCorrelationID("req-12345678") || ValidCorrelationID("bad space") { t.Fatal("correlation validation failed") } }
func TestEmailNormalizationAndRedaction(t *testing.T) {
    normalized, err := NormalizeEmailForRevocation("  Alex+Ops@Example.COM\n")
    if err != nil || normalized != "alex+ops@example.com" { t.Fatalf("normalization failed: %q %v", normalized, err) }
    if _, err := NormalizeEmailForRevocation("a..b@example.com"); err == nil { t.Fatal("ambiguous local part accepted") }
    if RedactRecord(map[string]any{"normalizedEmail":"alex@example.com"})["normalizedEmail"] != Redacted { t.Fatal("email not redacted") }
}
func TestAuthorizationIntersection(t *testing.T) {
    grants := []RevocationGrant{{"org-b",true},{"org-a",false},{"org-c",true}}
    authorized := AuthorizedOrganizations([]string{"org-a","org-b","org-unknown"}, grants)
    if len(authorized) != 1 || authorized[0] != "org-b" { t.Fatalf("bad authorization intersection: %#v", authorized) }
}
func TestIdempotency(t *testing.T) {
    a, b := [32]byte{}, [32]byte{}; for index := range a { a[index] = 1; b[index] = 2 }
    if ClassifyIdempotency(nil, a) != IdempotencyNew || ClassifyIdempotency(&a, a) != IdempotencyReplay || ClassifyIdempotency(&a, b) != IdempotencyConflict { t.Fatal("idempotency classification drifted") }
}
func TestDirectoryAuthorization(t *testing.T) {
    grants := []DirectoryGrant{{
        GrantID: "20000000-0000-4000-8000-000000000001",
        OrganizationID: "10000000-0000-4000-8000-000000000001",
        Scopes: []string{DirectoryRevocationsExecuteScope},
        Roles: []string{DirectoryAdminRole},
        GrantedAt: "2026-08-11T21:00:00Z",
    }}
    got := AuthorizedDirectoryOrganizations(nil, DirectoryRevocationsExecuteScope, grants)
    if len(got) != 1 || got[0] != grants[0].OrganizationID { t.Fatal("exact directory grant rejected") }
    if len(AuthorizedDirectoryOrganizations(nil, "directory.*", grants)) != 0 { t.Fatal("wildcard directory scope accepted") }
    projectBounded := grants[0]
    projectBounded.ProjectIDs = []string{"30000000-0000-4000-8000-000000000001"}
    if len(AuthorizedDirectoryOrganizations(nil, DirectoryRevocationsExecuteScope, []DirectoryGrant{projectBounded})) != 0 { t.Fatal("project grant elevated to organization authority") }
}

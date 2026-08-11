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

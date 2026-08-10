package orescore
import "testing"
func TestRedaction(t *testing.T) { if RedactRecord(map[string]any{"oauth_access-token":"x"})["oauth_access-token"] != Redacted { t.Fatal("credential not redacted") } }
func TestCorrelation(t *testing.T) { if !ValidCorrelationID("req-12345678") || ValidCorrelationID("bad space") { t.Fatal("correlation validation failed") } }

package orescore

import (
	"crypto/subtle"
	"errors"
	"sort"
	"strings"
)

const Redacted = "[REDACTED]"

var sensitive = []string{
	"authorization",
	"cookie",
	"password",
	"secret",
	"token",
	"email",
	"normalized_email",
	"email_lookup_hmac",
	"access_token",
	"refresh_token",
	"id_token",
	"client_secret",
	"private_key",
	"totp_seed",
	"webauthn_challenge",
	"face_image",
	"face_template",
	"fingerprint_image",
	"fingerprint_template",
	"biometric_template",
	"voiceprint",
}

func compactKey(value string) string {
	var builder strings.Builder
	for _, character := range strings.ToLower(strings.TrimSpace(value)) {
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') {
			builder.WriteRune(character)
		}
	}
	return builder.String()
}

func IsSensitiveField(key string) bool {
	normalized := compactKey(key)
	for _, field := range sensitive {
		expected := compactKey(field)
		if normalized == expected || strings.HasSuffix(normalized, expected) {
			return true
		}
	}
	return false
}

func RedactRecord(input map[string]any) map[string]any {
	out := make(map[string]any, len(input))
	for key, value := range input {
		if IsSensitiveField(key) {
			out[key] = Redacted
		} else {
			out[key] = value
		}
	}
	return out
}

func ValidCorrelationID(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			strings.ContainsRune("._:-", character)) {
			return false
		}
	}
	return true
}

type SecurityLogSink interface {
	Emit(action, outcome, reasonCode string, fields map[string]string)
}

func NormalizeEmailForRevocation(value string) (string, error) {
	trimmed := strings.Trim(value, " \t\r\n")
	if trimmed == "" {
		return "", errors.New("email is empty")
	}
	if len(trimmed) > 320 {
		return "", errors.New("email is too long")
	}
	for _, value := range []byte(trimmed) {
		if value > 127 {
			return "", errors.New("email must be ASCII")
		}
	}

	normalized := strings.ToLower(trimmed)
	if strings.Count(normalized, "@") != 1 {
		return "", errors.New("email structure is invalid")
	}
	parts := strings.SplitN(normalized, "@", 2)
	local, domain := parts[0], parts[1]
	if len(local) == 0 ||
		len(local) > 64 ||
		strings.HasPrefix(local, ".") ||
		strings.HasSuffix(local, ".") ||
		strings.Contains(local, "..") {
		return "", errors.New("email local part is invalid")
	}
	for _, value := range []byte(local) {
		if !validEmailLocalByte(value) {
			return "", errors.New("email local part is invalid")
		}
	}

	labels := strings.Split(domain, ".")
	if len(domain) > 255 || len(labels) < 2 {
		return "", errors.New("email domain is invalid")
	}
	for _, label := range labels {
		if !validDomainLabel(label) {
			return "", errors.New("email domain is invalid")
		}
	}
	return normalized, nil
}

func validEmailLocalByte(value byte) bool {
	if (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') {
		return true
	}
	return strings.ContainsRune(".!#$%&'*+-/=?^_`{|}~", rune(value))
}

func validDomainLabel(label string) bool {
	if len(label) == 0 ||
		len(label) > 63 ||
		strings.HasPrefix(label, "-") ||
		strings.HasSuffix(label, "-") {
		return false
	}
	for _, value := range []byte(label) {
		if !((value >= 'a' && value <= 'z') ||
			(value >= '0' && value <= '9') ||
			value == '-') {
			return false
		}
	}
	return true
}

type EmailLookupHMAC interface {
	Derive(normalizedEmail string) [32]byte
	KeyID() string
}

type RevocationGrant struct {
	OrganizationID string
	SessionsRevoke bool
}

const DirectoryAdminRole = "directory_admin"
const DirectoryRevocationsExecuteScope = "directory.revocations.execute"

type DirectoryGrant struct {
	GrantID        string
	OrganizationID string
	ProjectIDs     []string
	Scopes         []string
	Roles          []string
	GrantedAt      string
	ExpiresAt      string
}

func (grant DirectoryGrant) Allows(requiredScope string) bool {
	if strings.Contains(requiredScope, "*") {
		return false
	}
	hasRole := false
	for _, role := range grant.Roles {
		if role == DirectoryAdminRole {
			hasRole = true
			break
		}
	}
	if !hasRole {
		return false
	}
	for _, scope := range grant.Scopes {
		if scope == requiredScope {
			return true
		}
	}
	return false
}

func AuthorizedDirectoryOrganizations(
	requested []string,
	requiredScope string,
	grants []DirectoryGrant,
) []string {
	var requestedSet map[string]struct{}
	if requested != nil {
		requestedSet = make(map[string]struct{}, len(requested))
		for _, id := range requested {
			requestedSet[id] = struct{}{}
		}
	}
	authorizedSet := map[string]struct{}{}
	for _, grant := range grants {
		if !grant.Allows(requiredScope) {
			continue
		}
		if grant.ProjectIDs != nil {
			continue
		}
		if requestedSet != nil {
			if _, ok := requestedSet[grant.OrganizationID]; !ok {
				continue
			}
		}
		authorizedSet[grant.OrganizationID] = struct{}{}
	}
	authorized := make([]string, 0, len(authorizedSet))
	for id := range authorizedSet {
		authorized = append(authorized, id)
	}
	sort.Strings(authorized)
	return authorized
}

// AuthorizedOrganizations returns only the sorted authorized intersection.
func AuthorizedOrganizations(requested []string, grants []RevocationGrant) []string {
	var requestedSet map[string]struct{}
	if requested != nil {
		requestedSet = make(map[string]struct{}, len(requested))
		for _, id := range requested {
			requestedSet[id] = struct{}{}
		}
	}

	authorizedSet := map[string]struct{}{}
	for _, grant := range grants {
		if !grant.SessionsRevoke {
			continue
		}
		if requestedSet != nil {
			if _, ok := requestedSet[grant.OrganizationID]; !ok {
				continue
			}
		}
		authorizedSet[grant.OrganizationID] = struct{}{}
	}

	authorized := make([]string, 0, len(authorizedSet))
	for id := range authorizedSet {
		authorized = append(authorized, id)
	}
	sort.Strings(authorized)
	return authorized
}

type IdempotencyDisposition string

const (
	IdempotencyNew      IdempotencyDisposition = "new"
	IdempotencyReplay   IdempotencyDisposition = "replay"
	IdempotencyConflict IdempotencyDisposition = "conflict"
)

func ClassifyIdempotency(
	existingRequestDigest *[32]byte,
	incomingRequestDigest [32]byte,
) IdempotencyDisposition {
	if existingRequestDigest == nil {
		return IdempotencyNew
	}
	if subtle.ConstantTimeCompare(
		existingRequestDigest[:],
		incomingRequestDigest[:],
	) == 1 {
		return IdempotencyReplay
	}
	return IdempotencyConflict
}

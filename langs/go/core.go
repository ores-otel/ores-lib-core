package orescore

import (
	"crypto/subtle"
	"errors"
	"slices"
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

func lowerAlphanumeric(character rune) bool {
	return (character >= 'a' && character <= 'z') ||
		(character >= '0' && character <= '9')
}

func compactKey(value string) string {
	return keepRunes(strings.ToLower(strings.TrimSpace(value)), lowerAlphanumeric)
}

func IsSensitiveField(key string) bool {
	normalized := compactKey(key)
	return slices.ContainsFunc(sensitive, func(field string) bool {
		expected := compactKey(field)
		return normalized == expected || strings.HasSuffix(normalized, expected)
	})
}

// RedactRecord returns a new record; the input map is never written to.
func RedactRecord(input map[string]any) map[string]any {
	return mapValues(input, func(key string, value any) any {
		if IsSensitiveField(key) {
			return Redacted
		}
		return value
	})
}

func correlationIDRune(character rune) bool {
	return (character >= 'a' && character <= 'z') ||
		(character >= 'A' && character <= 'Z') ||
		(character >= '0' && character <= '9') ||
		strings.ContainsRune("._:-", character)
}

func ValidCorrelationID(value string) bool {
	return len(value) >= 8 &&
		len(value) <= 128 &&
		strings.IndexFunc(value, func(character rune) bool { return !correlationIDRune(character) }) < 0
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
	if !allBytes(trimmed, asciiByte) {
		return "", errors.New("email must be ASCII")
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
		strings.Contains(local, "..") ||
		!allBytes(local, validEmailLocalByte) {
		return "", errors.New("email local part is invalid")
	}

	labels := strings.Split(domain, ".")
	if len(domain) > 255 || len(labels) < 2 || !allSlice(labels, validDomainLabel) {
		return "", errors.New("email domain is invalid")
	}
	return normalized, nil
}

func asciiByte(value byte) bool {
	return value <= 127
}

func validEmailLocalByte(value byte) bool {
	if (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') {
		return true
	}
	return strings.ContainsRune(".!#$%&'*+-/=?^_`{|}~", rune(value))
}

func validDomainLabelByte(value byte) bool {
	return (value >= 'a' && value <= 'z') ||
		(value >= '0' && value <= '9') ||
		value == '-'
}

func validDomainLabel(label string) bool {
	return len(label) != 0 &&
		len(label) <= 63 &&
		!strings.HasPrefix(label, "-") &&
		!strings.HasSuffix(label, "-") &&
		allBytes(label, validDomainLabelByte)
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
	return !strings.Contains(requiredScope, "*") &&
		slices.Contains(grant.Roles, DirectoryAdminRole) &&
		slices.Contains(grant.Scopes, requiredScope)
}

// projectBounded reports whether the grant is limited to projects; such grants
// must never be elevated to organization-wide authority.
func (grant DirectoryGrant) projectBounded() bool {
	return grant.ProjectIDs != nil
}

// requestedFilter returns the organization predicate encoded by a request: a nil
// request admits every organization, any other request admits only its members.
func requestedFilter(requested []string) func(string) bool {
	requestedSet := setOf(requested)
	return func(organizationID string) bool {
		if requestedSet == nil {
			return true
		}
		_, ok := requestedSet[organizationID]
		return ok
	}
}

func AuthorizedDirectoryOrganizations(
	requested []string,
	requiredScope string,
	grants []DirectoryGrant,
) []string {
	inRequest := requestedFilter(requested)
	authorized := filterSlice(grants, func(grant DirectoryGrant) bool {
		return grant.Allows(requiredScope) &&
			!grant.projectBounded() &&
			inRequest(grant.OrganizationID)
	})
	return sortedUnique(mapSlice(authorized, func(grant DirectoryGrant) string {
		return grant.OrganizationID
	}))
}

// AuthorizedOrganizations returns only the sorted authorized intersection.
func AuthorizedOrganizations(requested []string, grants []RevocationGrant) []string {
	inRequest := requestedFilter(requested)
	authorized := filterSlice(grants, func(grant RevocationGrant) bool {
		return grant.SessionsRevoke && inRequest(grant.OrganizationID)
	})
	return sortedUnique(mapSlice(authorized, func(grant RevocationGrant) string {
		return grant.OrganizationID
	}))
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

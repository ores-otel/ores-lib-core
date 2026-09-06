package com.oresoftware.core;

import java.util.Map;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

public final class OresCore {
  public static final String REDACTED = "[REDACTED]";
  public static final String DIRECTORY_ADMIN_ROLE = "directory_admin";
  public static final String DIRECTORY_REVOCATIONS_EXECUTE_SCOPE = "directory.revocations.execute";
  private static final Set<String> SENSITIVE = Set.of("authorization","cookie","password","secret","token","access_token","refresh_token","id_token","client_secret","private_key","totp_seed","webauthn_challenge","face_image","face_template","fingerprint_image","fingerprint_template","biometric_template","voiceprint");
  private OresCore() {}
  private static String compact(String value) { return value.trim().toLowerCase().replaceAll("[^a-z0-9]", ""); }
  public static boolean isSensitiveField(String key) { String normalized=compact(key); return SENSITIVE.stream().anyMatch(field -> normalized.equals(compact(field)) || normalized.endsWith(compact(field))); }
  public static Map<String,Object> redactRecord(Map<String,Object> input) { return input.entrySet().stream().collect(Collectors.toUnmodifiableMap(Map.Entry::getKey, entry -> isSensitiveField(entry.getKey()) ? REDACTED : entry.getValue())); }
  public static boolean validCorrelationId(String value) { return value != null && value.length() >= 8 && value.length() <= 128 && value.matches("[A-Za-z0-9._:-]+"); }
  public static final class Secret<T> { private final T value; public Secret(T value){this.value=value;} public <R> R expose(Function<T,R> action){return action.apply(value);} @Override public String toString(){return REDACTED;} }
  public record DirectoryGrant(String grantId, String organizationId, List<String> projectIds, List<String> scopes, List<String> roles, String grantedAt, String expiresAt) {
    public boolean allows(String requiredScope) { return !requiredScope.contains("*") && roles.contains(DIRECTORY_ADMIN_ROLE) && scopes.contains(requiredScope); }
  }
  public static List<String> authorizedDirectoryOrganizations(List<String> requested, String requiredScope, List<DirectoryGrant> grants) {
    Set<String> requestedSet = requested == null ? null : Set.copyOf(requested);
    return grants.stream().filter(grant -> grant.allows(requiredScope)).filter(grant -> grant.projectIds() == null).filter(grant -> requestedSet == null || requestedSet.contains(grant.organizationId())).map(DirectoryGrant::organizationId).distinct().sorted().toList();
  }
}

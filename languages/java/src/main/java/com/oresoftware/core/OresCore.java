package com.oresoftware.core;

import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

public final class OresCore {
  public static final String REDACTED = "[REDACTED]";
  private static final Set<String> SENSITIVE = Set.of("authorization","cookie","password","secret","token","access_token","refresh_token","id_token","client_secret","private_key","totp_seed","webauthn_challenge","face_image","face_template","fingerprint_image","fingerprint_template","biometric_template","voiceprint");
  private OresCore() {}
  private static String compact(String value) { return value.trim().toLowerCase().replaceAll("[^a-z0-9]", ""); }
  public static boolean isSensitiveField(String key) { String normalized=compact(key); return SENSITIVE.stream().anyMatch(field -> normalized.equals(compact(field)) || normalized.endsWith(compact(field))); }
  public static Map<String,Object> redactRecord(Map<String,Object> input) { return input.entrySet().stream().collect(Collectors.toUnmodifiableMap(Map.Entry::getKey, entry -> isSensitiveField(entry.getKey()) ? REDACTED : entry.getValue())); }
  public static boolean validCorrelationId(String value) { return value != null && value.length() >= 8 && value.length() <= 128 && value.matches("[A-Za-z0-9._:-]+"); }
  public static final class Secret<T> { private final T value; public Secret(T value){this.value=value;} public <R> R expose(Function<T,R> action){return action.apply(value);} @Override public String toString(){return REDACTED;} }
}

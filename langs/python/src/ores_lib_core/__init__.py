from __future__ import annotations
from collections.abc import Callable
from dataclasses import dataclass
from typing import Generic, TypeVar
T=TypeVar("T"); R=TypeVar("R")
REDACTED="[REDACTED]"
SENSITIVE={"authorization","cookie","password","secret","token","access_token","refresh_token","id_token","client_secret","private_key","totp_seed","webauthn_challenge","face_image","face_template","fingerprint_image","fingerprint_template","biometric_template","voiceprint"}
def is_sensitive_field(key: str) -> bool:
    compact="".join(ch for ch in key.strip().lower() if ch.isalnum())
    return any(compact == "".join(ch for ch in field if ch.isalnum()) or compact.endswith("".join(ch for ch in field if ch.isalnum())) for field in SENSITIVE)
def redact_record(record: dict[str, object]) -> dict[str, object]:
    return {key:(REDACTED if is_sensitive_field(key) else value) for key,value in record.items()}
def valid_correlation_id(value: str) -> bool:
    return 8 <= len(value) <= 128 and all(ch.isalnum() or ch in "._:-" for ch in value)
class Secret(Generic[T]):
    __slots__=("__value",)
    def __init__(self, value:T): self.__value=value
    def expose(self, action:Callable[[T],R])->R: return action(self.__value)
    def __repr__(self)->str: return REDACTED
    __str__=__repr__

DIRECTORY_ADMIN_ROLE="directory_admin"
DIRECTORY_REVOCATIONS_EXECUTE_SCOPE="directory.revocations.execute"
@dataclass(frozen=True, slots=True)
class DirectoryGrant:
    grant_id: str
    organization_id: str
    project_ids: tuple[str, ...] | None
    scopes: tuple[str, ...]
    roles: tuple[str, ...]
    granted_at: str
    expires_at: str | None
    def allows(self, required_scope: str) -> bool:
        return "*" not in required_scope and DIRECTORY_ADMIN_ROLE in self.roles and required_scope in self.scopes
def authorized_directory_organizations(requested: tuple[str, ...] | None, required_scope: str, grants: tuple[DirectoryGrant, ...]) -> tuple[str, ...]:
    requested_set=None if requested is None else set(requested)
    return tuple(sorted({grant.organization_id for grant in grants if grant.allows(required_scope) and grant.project_ids is None and (requested_set is None or grant.organization_id in requested_set)}))

from __future__ import annotations
from collections.abc import Callable
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

import base64
import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from config import Config

from cryptography.fernet import Fernet


def _load_key() -> bytes:
    """
    Load the AES key from DATA_ENCRYPTION_KEY (URL-safe base64 encoded).
    Accepts 128/192/256-bit keys (16/24/32 bytes after decoding).
    """
    key_b64 = Config.DATA_ENCRYPTION_KEY
    if not key_b64:
        raise RuntimeError("DATA_ENCRYPTION_KEY is not set")

    try:
        key = base64.urlsafe_b64decode(key_b64)
    except Exception as exc:  # pragma: no cover - defensive
        raise ValueError("DATA_ENCRYPTION_KEY must be URL-safe base64") from exc

    if len(key) not in (16, 24, 32):
        raise ValueError("DATA_ENCRYPTION_KEY must decode to 16/24/32 bytes")
    return key


def encrypt_value(value: Optional[str]) -> Optional[str]:
    """Encrypt a string with AES-GCM and return a URL-safe base64 payload."""
    if value is None:
        return None

    data = value if isinstance(value, bytes) else str(value).encode()
    key = _load_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce recommended for GCM
    ciphertext = aesgcm.encrypt(nonce, data, associated_data=None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode()


def decrypt_value(token: Optional[str], *, fallback_on_error: bool = False) -> Optional[str]:
    """
    Decrypt a value produced by encrypt_value. If fallback_on_error is True,
    the original token is returned when decryption fails (useful for legacy
    plaintext rows during migration).
    """
    if token is None:
        return None

    try:
        key = _load_key()
        raw = base64.urlsafe_b64decode(token)
        nonce, ciphertext = raw[:12], raw[12:]
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        return plaintext.decode()
    except Exception:
        if fallback_on_error:
            return token
        raise
def _load_db_key() -> bytes:
    key_b64 = Config.DB_ENCRYPTION_KEY
    if not key_b64:
        raise RuntimeError("DB_ENCRYPTION_KEY is not set")

    try:
        key = base64.urlsafe_b64decode(key_b64)
    except Exception as exc:
        raise ValueError("DB_ENCRYPTION_KEY must be URL-safe base64") from exc

    if len(key) not in (16, 24, 32):
        raise ValueError("DB_ENCRYPTION_KEY must decode to 16/24/32 bytes")
    return key

def encrypt_db_value(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    data = value if isinstance(value, bytes) else str(value).encode()
    key = _load_db_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode()

def decrypt_db_value(token: Optional[str], *, fallback_on_error: bool = False) -> Optional[str]:
    if token is None:
        return None
    try:
        key = _load_db_key()
        raw = base64.urlsafe_b64decode(token)
        nonce, ciphertext = raw[:12], raw[12:]
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except Exception:
        if fallback_on_error:
            return token
        raise

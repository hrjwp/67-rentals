"""
File-level encryption helpers for incident report uploads.
Uses AES-GCM with a per-file random nonce.
"""
import base64
import os
from typing import Dict, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _load_key() -> bytes:
    key_b64 = os.environ.get("DATA_ENCRYPTION_KEY")
    if not key_b64:
        raise RuntimeError("DATA_ENCRYPTION_KEY is not set")

    try:
        key = base64.urlsafe_b64decode(key_b64)
    except Exception as exc:
        raise ValueError("DATA_ENCRYPTION_KEY must be URL-safe base64") from exc

    if len(key) not in (16, 24, 32):
        raise ValueError("DATA_ENCRYPTION_KEY must decode to 16/24/32 bytes")
    return key


def _encrypt_bytes(data: bytes) -> bytes:
    key = _load_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext


def decrypt_file(encrypted_data: bytes) -> bytes:
    """Decrypt AES-GCM payload produced by _encrypt_bytes."""
    if not encrypted_data or len(encrypted_data) < 13:
        raise ValueError("Encrypted payload is too short")

    key = _load_key()
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def encrypt_file(file_content: bytes) -> bytes:
    """Encrypt raw bytes with AES-GCM for at-rest storage."""
    if file_content is None:
        raise ValueError("File content is required for encryption")
    return _encrypt_bytes(file_content)


def process_incident_file(
    file_content: bytes,
    filename: str,
    *,
    encrypt: bool = True,
    watermark: bool = True,
) -> Tuple[bytes, Dict[str, object]]:
    """
    Process incident report files. Watermarking is a no-op placeholder and
    can be extended without changing the call sites.
    """
    processed = file_content
    metadata: Dict[str, object] = {
        "encrypted": False,
        "watermarked": False,
        "filename": filename,
    }

    if watermark:
        # Placeholder for future watermarking; keep data unchanged.
        metadata["watermarked"] = False

    if encrypt:
        processed = _encrypt_bytes(processed)
        metadata["encrypted"] = True

    return processed, metadata

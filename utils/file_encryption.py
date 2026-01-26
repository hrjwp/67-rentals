"""
File encryption and watermarking utilities for incident report uploads.
Uses AES-GCM with a per-file random nonce. Watermarking is optional and
only applied when PIL/Pillow is available.
"""
import base64
import os
from io import BytesIO
from typing import Dict, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from config import Config

try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


def _load_key() -> bytes:
    key_b64 = Config.DATA_ENCRYPTION_KEY
    if not key_b64:
        raise RuntimeError("DATA_ENCRYPTION_KEY is not set")

    try:
        key = base64.urlsafe_b64decode(key_b64)
    except Exception as exc:
        raise ValueError("DATA_ENCRYPTION_KEY must be URL-safe base64") from exc

    if len(key) not in (16, 24, 32):
        raise ValueError("DATA_ENCRYPTION_KEY must decode to 16/24/32 bytes")
    return key


def encrypt_file(file_content: bytes) -> bytes:
    """Encrypt raw bytes with AES-GCM for at-rest storage."""
    if file_content is None:
        raise ValueError("File content is required for encryption")
    key = _load_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, file_content, None)
    return nonce + ciphertext


def decrypt_file(encrypted_data: bytes) -> bytes:
    """Decrypt AES-GCM payload produced by encrypt_file."""
    if not encrypted_data or len(encrypted_data) < 13:
        raise ValueError("Encrypted payload is too short")
    key = _load_key()
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def add_watermark_to_image(image_content: bytes, watermark_text: str = "67 RENTALS - CONFIDENTIAL") -> bytes:
    """Add watermark to image bytes (no-op if PIL is unavailable)."""
    if not PIL_AVAILABLE:
        return image_content

    try:
        image = Image.open(BytesIO(image_content))
        original_format = image.format

        if image.mode != "RGB":
            image = image.convert("RGB")

        watermarked = image.copy()
        width, height = watermarked.size
        font_size = max(20, min(width, height) // 20)

        font = None
        for font_path in [
            "arial.ttf",
            "Arial.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/System/Library/Fonts/Helvetica.ttc",
            "C:/Windows/Fonts/arial.ttf",
        ]:
            try:
                font = ImageFont.truetype(font_path, font_size)
                break
            except Exception:
                continue

        if font is None:
            try:
                font = ImageFont.load_default()
            except Exception:
                font = None

        watermark_overlay = Image.new("RGBA", (width, height), (0, 0, 0, 0))
        watermark_draw = ImageDraw.Draw(watermark_overlay)

        if font:
            try:
                bbox = watermark_draw.textbbox((0, 0), watermark_text, font=font)
                text_width = bbox[2] - bbox[0]
                text_height = bbox[3] - bbox[1]
            except Exception:
                text_width = len(watermark_text) * 10
                text_height = 20
        else:
            text_width = len(watermark_text) * 10
            text_height = 20

        x = (width - text_width) // 2
        y = (height - text_height) // 2

        watermark_draw.text(
            (x, y),
            watermark_text,
            font=font,
            fill=(255, 0, 0, 120),
        )

        pattern_spacing = max(60, min(width, height) // 6)
        for offset in range(-height, width + height, pattern_spacing):
            watermark_draw.text(
                (offset, height // 2),
                watermark_text,
                font=font,
                fill=(255, 0, 0, 40),
            )

        if watermarked.mode != "RGBA":
            watermarked = watermarked.convert("RGBA")
        watermarked = Image.alpha_composite(watermarked, watermark_overlay)
        watermarked = watermarked.convert("RGB")

        output = BytesIO()
        if original_format and original_format.upper() in {"PNG", "GIF"}:
            watermarked.save(output, format=original_format)
        else:
            watermarked.save(output, format="JPEG", quality=95)
        return output.getvalue()
    except Exception:
        return image_content


def process_incident_file(
    file_content: bytes,
    filename: str,
    *,
    encrypt: bool = True,
    watermark: bool = True,
) -> Tuple[bytes, Dict[str, object]]:
    """
    Process incident report files. Applies optional watermarking and encryption.
    Returns processed bytes and metadata.
    """
    processed = file_content
    metadata: Dict[str, object] = {
        "encrypted": False,
        "watermarked": False,
        "filename": filename,
    }

    is_image = filename.lower().endswith((".jpg", ".jpeg", ".png", ".gif", ".webp"))

    if watermark and is_image:
        processed = add_watermark_to_image(processed)
        metadata["watermarked"] = True

    if encrypt:
        processed = encrypt_file(processed)
        metadata["encrypted"] = True

    return processed, metadata

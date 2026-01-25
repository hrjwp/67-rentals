"""
File encryption and watermarking utilities for incident report files
Encrypts files at rest and adds watermarks to images for authenticity
"""
import os
import base64
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from io import BytesIO

try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("WARNING: PIL/Pillow not available. Watermarking will be skipped.")


def _load_encryption_key() -> bytes:
    """Load encryption key from environment"""
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


def encrypt_file(file_content: bytes) -> bytes:
    """
    Encrypt file content using AES-GCM
    Returns: encrypted bytes (nonce + ciphertext)
    """
    key = _load_encryption_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    ciphertext = aesgcm.encrypt(nonce, file_content, associated_data=None)
    return nonce + ciphertext


def decrypt_file(encrypted_content: bytes) -> bytes:
    """
    Decrypt file content
    Returns: decrypted bytes
    """
    key = _load_encryption_key()
    aesgcm = AESGCM(key)
    nonce = encrypted_content[:12]
    ciphertext = encrypted_content[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext


def add_watermark_to_image(image_content: bytes, watermark_text: str = "67 RENTALS - CONFIDENTIAL") -> bytes:
    """
    Add watermark to image to prevent tampering and ensure authenticity
    Returns: watermarked image as bytes
    """
    if not PIL_AVAILABLE:
        # If PIL not available, return original image
        print("WARNING: PIL/Pillow not available. Watermarking skipped.")
        return image_content
    
    try:
        # Open image from bytes
        image = Image.open(BytesIO(image_content))
        original_format = image.format
        
        # Convert to RGB if necessary (handles RGBA, P, etc.)
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        # Create a copy for watermarking
        watermarked = image.copy()
        
        # Get image dimensions
        width, height = watermarked.size
        
        # Calculate font size (adaptive to image size)
        font_size = max(20, min(width, height) // 20)
        
        # Try to load a font
        font = None
        try:
            # Try common font paths
            font_paths = [
                "arial.ttf",
                "Arial.ttf",
                "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
                "/System/Library/Fonts/Helvetica.ttc",
                "C:/Windows/Fonts/arial.ttf"
            ]
            for font_path in font_paths:
                try:
                    font = ImageFont.truetype(font_path, font_size)
                    break
                except:
                    continue
        except:
            pass
        
        if font is None:
            # Fallback to default font
            try:
                font = ImageFont.load_default()
            except:
                font = None
        
        # Create overlay for watermark
        watermark_overlay = Image.new('RGBA', (width, height), (0, 0, 0, 0))
        watermark_draw = ImageDraw.Draw(watermark_overlay)
        
        # Draw center watermark
        if font:
            try:
                bbox = watermark_draw.textbbox((0, 0), watermark_text, font=font)
                text_width = bbox[2] - bbox[0]
                text_height = bbox[3] - bbox[1]
            except:
                # Fallback for older PIL versions
                try:
                    text_width, text_height = watermark_draw.textsize(watermark_text, font=font)
                except:
                    # Ultimate fallback
                    text_width = len(watermark_text) * 10
                    text_height = 20
        else:
            # Estimate size without font
            text_width = len(watermark_text) * 10
            text_height = 20
        
        # Center position
        x = (width - text_width) // 2
        y = (height - text_height) // 2
        
        # Draw main watermark with transparency
        watermark_draw.text(
            (x, y),
            watermark_text,
            font=font,
            fill=(255, 0, 0, 120)  # Red with transparency
        )
        
        # Add diagonal repeating watermarks
        pattern_spacing = min(width, height) // 6
        for offset in range(-height, width + height, pattern_spacing):
            watermark_draw.text(
                (offset, height // 2),
                watermark_text,
                font=font,
                fill=(255, 0, 0, 40),  # Very transparent
            )
        
        # Composite watermark onto image
        if watermarked.mode != 'RGBA':
            watermarked = watermarked.convert('RGBA')
        watermarked = Image.alpha_composite(watermarked, watermark_overlay)
        watermarked = watermarked.convert('RGB')
        
        # Save to bytes
        output = BytesIO()
        # Determine format from original
        if original_format and original_format.upper() in ['PNG', 'GIF']:
            watermarked.save(output, format=original_format)
        else:
            # Default to JPEG for photos
            watermarked.save(output, format='JPEG', quality=95)
        
        return output.getvalue()
    
    except Exception as e:
        print(f"WARNING: Failed to watermark image: {e}")
        import traceback
        print(traceback.format_exc())
        # Return original if watermarking fails
        return image_content


def process_incident_file(file_content: bytes, filename: str, encrypt: bool = True, watermark: bool = True) -> Tuple[bytes, dict]:
    """
    Process incident report file: validate, watermark (if image), and encrypt
    Returns: (processed_file_content, metadata_dict)
    """
    metadata = {
        'original_size': len(file_content),
        'encrypted': False,
        'watermarked': False,
        'file_type': None
    }
    
    # Detect if it's an image
    is_image = False
    if filename.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.webp')):
        is_image = True
        metadata['file_type'] = 'image'
    
    # Step 1: Add watermark if it's an image
    if watermark and is_image:
        try:
            file_content = add_watermark_to_image(file_content)
            metadata['watermarked'] = True
            metadata['watermarked_size'] = len(file_content)
        except Exception as e:
            print(f"WARNING: Watermarking failed: {e}")
    
    # Step 2: Encrypt file
    if encrypt:
        try:
            file_content = encrypt_file(file_content)
            metadata['encrypted'] = True
            metadata['encrypted_size'] = len(file_content)
        except Exception as e:
            print(f"ERROR: File encryption failed: {e}")
            raise
    
    return file_content, metadata

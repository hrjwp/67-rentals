"""
Enhanced file upload security: magic number verification and image validation
Prevents malicious file uploads even if file extension is spoofed
"""
import os
import struct
from io import BytesIO

# Magic numbers (file signatures) for common file types
MAGIC_NUMBERS = {
    # Images
    b'\xFF\xD8\xFF': 'jpg',
    b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': 'png',
    b'\x47\x49\x46\x38': 'gif',
    b'\x42\x4D': 'bmp',
    b'\x52\x49\x46\x46': 'webp',  # RIFF header, need to check more
    
    # Documents
    b'%PDF': 'pdf',
    
    # Video (if needed later)
    b'\x00\x00\x00\x18ftyp': 'mp4',
}

# Reverse lookup for validation
EXTENSION_TO_MAGIC = {
    'jpg': [b'\xFF\xD8\xFF'],
    'jpeg': [b'\xFF\xD8\xFF'],
    'png': [b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'],
    'gif': [b'\x47\x49\x46\x38\x37\x61', b'\x47\x49\x46\x38\x39\x61'],  # GIF87a and GIF89a
    'bmp': [b'\x42\x4D'],
    'webp': [b'\x52\x49\x46\x46'],  # RIFF (WebP starts with RIFF)
    'pdf': [b'%PDF'],
}


def verify_file_magic_number(file_content, expected_extension):
    """
    Verify file content matches its extension using magic numbers
    Returns: (is_valid, detected_type)
    """
    if not file_content or len(file_content) < 4:
        return False, None
    
    # Normalize extension
    expected_extension = expected_extension.lower().lstrip('.')
    
    # Get expected magic numbers for this extension
    expected_magics = EXTENSION_TO_MAGIC.get(expected_extension, [])
    
    if not expected_magics:
        # Extension not in our list - reject unknown types
        return False, None
    
    # Check if file content starts with any expected magic number
    for magic in expected_magics:
        if file_content.startswith(magic):
            return True, expected_extension
    
    # Special case for WebP (RIFF with WEBP in it)
    if expected_extension == 'webp':
        if file_content.startswith(b'RIFF') and b'WEBP' in file_content[:12]:
            return True, 'webp'
    
    # No match found
    return False, None


def detect_file_type(file_content):
    """
    Detect file type from magic number (regardless of extension)
    Returns: detected_type or None
    """
    if not file_content or len(file_content) < 4:
        return None
    
    # Check each magic number
    for magic, file_type in MAGIC_NUMBERS.items():
        if file_content.startswith(magic):
            # Special check for WebP
            if file_type == 'webp':
                if b'WEBP' in file_content[:12]:
                    return 'webp'
                continue
            return file_type
    
    return None


def validate_image_file(file_content):
    """
    Validate that uploaded file is actually an image
    Checks magic number and basic image structure
    Returns: (is_valid, error_message)
    """
    if not file_content:
        return False, "File is empty"
    
    # Check minimum size (very small files are likely not valid images)
    if len(file_content) < 100:
        return False, "File too small to be a valid image"
    
    # Check file type from magic number
    detected_type = detect_file_type(file_content)
    
    if not detected_type:
        return False, "File does not match any known image format"
    
    # Verify it's actually an image type
    if detected_type not in ['jpg', 'png', 'gif', 'bmp', 'webp']:
        return False, f"File type '{detected_type}' is not a supported image format"
    
    # Additional validation for specific formats
    if detected_type == 'jpg':
        # JPEG should end with FF D9 (JPEG end marker)
        if not file_content.endswith(b'\xFF\xD9'):
            return False, "JPEG file appears to be corrupted or incomplete"
    
    elif detected_type == 'png':
        # PNG should have IEND chunk at the end
        if b'IEND' not in file_content[-20:]:
            return False, "PNG file appears to be corrupted or incomplete"
    
    elif detected_type == 'gif':
        # GIF should have ; (semicolon) near the end
        if b';' not in file_content[-10:]:
            return False, "GIF file appears to be corrupted or incomplete"
    
    return True, None


def validate_uploaded_file(file_object, allowed_extensions=None):
    """
    Comprehensive file validation:
    1. Check file extension
    2. Verify magic number matches extension
    3. Validate file content structure (for images)
    
    Returns: (is_valid, error_message, detected_type)
    """
    if not file_object:
        return False, "No file provided", None
    
    # Get filename and extension
    filename = file_object.filename
    if not filename:
        return False, "Filename is missing", None
    
    # Check extension
    if '.' not in filename:
        return False, "File must have an extension", None
    
    extension = filename.rsplit('.', 1)[1].lower()
    
    # Default allowed extensions from config
    if allowed_extensions is None:
        from config import Config
        allowed_extensions = Config.ALLOWED_EXTENSIONS
    
    if extension not in allowed_extensions:
        return False, f"File extension '.{extension}' is not allowed", None
    
    # Read file content (reset to beginning)
    file_object.seek(0)
    file_content = file_object.read()
    file_object.seek(0)  # Reset for actual save
    
    if not file_content:
        return False, "File is empty", None
    
    # Verify magic number matches extension
    is_valid_magic, detected_type = verify_file_magic_number(file_content, extension)
    
    if not is_valid_magic:
        return False, f"File content does not match extension '.{extension}'. Possible file spoofing attempt.", None
    
    # If it's an image, do additional validation
    if extension in ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp']:
        is_valid_image, error_msg = validate_image_file(file_content)
        if not is_valid_image:
            return False, error_msg or "Invalid image file", None
    
    return True, None, detected_type


def sanitize_filename(filename):
    """
    Sanitize filename to prevent directory traversal and other attacks
    Returns: sanitized filename
    """
    if not filename:
        return "file"
    
    # Remove path components
    filename = os.path.basename(filename)
    
    # Remove null bytes
    filename = filename.replace('\x00', '')
    
    # Remove dangerous characters
    dangerous_chars = ['<', '>', ':', '"', '|', '?', '*', '\\', '/']
    for char in dangerous_chars:
        filename = filename.replace(char, '_')
    
    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:250] + ext
    
    return filename


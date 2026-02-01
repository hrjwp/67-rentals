import re
from config import Config


def validate_name(name):
    """
    Validate name format
    - Must be at least 2 characters
    - Only letters, spaces, hyphens, and apostrophes allowed
    """
    if not name or len(name) < 2:
        return False

    pattern = r"^[a-zA-Z\s\-']+$"
    return re.match(pattern, name) is not None


def validate_email(email):
    """Validate email format"""
    if not email:
        return False

    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_phone(phone):
    """
    Validate Singapore phone number
    - Must be 8 digits
    - Must start with 6, 8, or 9
    """
    if not phone:
        return False

    pattern = r'^[689]\d{7}$'
    return re.match(pattern, phone) is not None


def validate_nric(nric):
    """
    Validate Singapore NRIC/FIN with checksum
    - Must start with S, T, F, G, or M
    - Followed by 7 digits
    - Ends with a checksum letter
    """
    if not nric or len(nric) != 9:
        return False

    # Check format
    pattern = r'^[STFGM]\d{7}[A-Z]$'
    if not re.match(pattern, nric):
        return False

    # Validate checksum
    prefix = nric[0]
    digits = nric[1:8]
    checksum = nric[8]

    # Weight array
    weights = [2, 7, 6, 5, 4, 3, 2]

    # Calculate weighted sum
    total = sum(int(digits[i]) * weights[i] for i in range(7))

    # Add offset for different prefix types
    if prefix in ['T', 'G']:
        total += 4
    elif prefix == 'M':
        total += 3

    # Checksum letters for different prefixes
    if prefix in ['S', 'T']:
        st_array = ['J', 'Z', 'I', 'H', 'G', 'F', 'E', 'D', 'C', 'B', 'A']
        expected_checksum = st_array[total % 11]
    elif prefix in ['F', 'G']:
        fg_array = ['X', 'W', 'U', 'T', 'R', 'Q', 'P', 'N', 'M', 'L', 'K']
        expected_checksum = fg_array[total % 11]
    elif prefix == 'M':
        m_array = ['K', 'L', 'J', 'N', 'P', 'Q', 'R', 'T', 'U', 'W', 'X']
        expected_checksum = m_array[total % 11]
    else:
        return False

    return checksum == expected_checksum


def extract_age_from_nric(nric: str) -> dict:
    """
    Extract approximate age from Singapore NRIC/FIN.
    
    For persons born on or after 1 Jan 1968:
    - S/T/F/G prefix: first 2 digits after prefix = birth year
    - S: born 1900-1999 (e.g., S71 = 1971)
    - T: born 2000-2099 (e.g., T02 = 2002)
    - F: foreigner born 1900-1999
    - G: foreigner born 2000-2099
    
    For persons born before 1968: digits are sequential, not birth year.
    
    Returns dict with:
    - age: int or None
    - birth_year: int or None  
    - is_minor: bool (True if age < 18)
    - confidence: 'high' | 'low' | 'unknown'
    - message: str
    """
    from datetime import datetime
    
    result = {
        "age": None,
        "birth_year": None,
        "is_minor": None,
        "confidence": "unknown",
        "message": "Unable to determine age"
    }
    
    if not nric or len(nric) < 3:
        return result
    
    nric = nric.upper().strip()
    prefix = nric[0]
    
    # Check if NRIC format is valid
    if prefix not in ['S', 'T', 'F', 'G', 'M']:
        result["message"] = "Invalid NRIC prefix"
        return result
    
    try:
        year_digits = int(nric[1:3])
    except (ValueError, IndexError):
        result["message"] = "Cannot parse birth year digits"
        return result
    
    current_year = datetime.now().year
    
    # Determine birth year based on prefix
    if prefix in ['S', 'F']:
        # Born 1900-1999
        birth_year = 1900 + year_digits
        # If birth year > current year - 18, could be misparse
        if birth_year < 1968:
            # Before 1968, digits were sequential, not birth year
            result["confidence"] = "low"
            result["message"] = f"NRIC issued before 1968 system - age detection unreliable"
            return result
    elif prefix in ['T', 'G']:
        # Born 2000-2099
        birth_year = 2000 + year_digits
    elif prefix == 'M':
        # M prefix (newer format) - similar to T
        birth_year = 2000 + year_digits
    else:
        return result
    
    # Sanity check: birth year shouldn't be in the future
    if birth_year > current_year:
        result["confidence"] = "low"
        result["message"] = "Birth year appears invalid"
        return result
    
    age = current_year - birth_year
    
    # Sanity check: age should be reasonable (0-120)
    if age < 0 or age > 120:
        result["confidence"] = "low"
        result["message"] = f"Calculated age ({age}) seems unreasonable"
        return result
    
    result["age"] = age
    result["birth_year"] = birth_year
    result["is_minor"] = age < 18
    result["confidence"] = "high"
    
    if result["is_minor"]:
        result["message"] = f"⚠️ MINOR: Approximately {age} years old (born ~{birth_year})"
    else:
        result["message"] = f"Adult: Approximately {age} years old (born ~{birth_year})"
    
    return result


def validate_license(license_number):
    """
    Validate Singapore driver's license number
    Format examples: S1234567A, S12345678
    """
    if not license_number:
        return False

    # Singapore license format: Letter followed by 7-8 digits and optional letter
    pattern = r'^[A-Z]\d{7,8}[A-Z]?$'
    return re.match(pattern, license_number) is not None


def validate_password(password):
    """
    Validate password strength
    Requirements:
    - At least 8 characters
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one number
    - Contains at least one special character
    """
    if not password:
        return False, "Password is required"

    if len(password) < 8:
        return False, "Password must be at least 8 characters long"

    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"

    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"

    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"

    return True, "Password is valid"


def validate_file_size(file):
    """
    Validate file size
    Maximum size: 5MB
    """
    if not file:
        return False

    # Save current position
    file.seek(0, 2)  # Seek to end
    size = file.tell()  # Get size
    file.seek(0)  # Reset to beginning

    return size <= Config.MAX_FILE_SIZE


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS
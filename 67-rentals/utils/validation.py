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
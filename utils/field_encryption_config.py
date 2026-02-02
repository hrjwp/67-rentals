"""
Configuration for AES encryption of sensitive database fields.
Tables and columns listed here are encrypted on write and decrypted on read.
Uses utils.encryption encrypt_value/decrypt_value (AES-GCM).
"""
from typing import Dict, List, Tuple

# Map of table_name -> list of column names that store encrypted values
# Email is excluded from users table (needed for login lookup)
SENSITIVE_FIELDS: Dict[str, List[str]] = {
    "users": ["first_name", "last_name", "phone_number", "nric", "license_number"] ,
    "incident_reports": [
        "full_name", "contact_number", "email", "booking_id",
        "incident_location", "incident_description"
    ],
}

# When SELECT uses aliases (e.g. phone_number AS phone), map logical column -> alias keys
COLUMN_ALIASES: Dict[str, Dict[str, List[str]]] = {
    "users": {"phone_number": ["phone"]},
}

def get_encrypted_columns(table_name: str) -> List[str]:
    """Return list of encrypted column names for a table."""
    return SENSITIVE_FIELDS.get(table_name, [])


def get_column_keys_for_decrypt(table_name: str, column: str) -> List[str]:
    """Return list of dict keys that may hold this column's value (including aliases)."""
    keys = [column]
    aliases = COLUMN_ALIASES.get(table_name, {}).get(column, [])
    return keys + aliases

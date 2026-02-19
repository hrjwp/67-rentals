"""
Data Classification System Configuration (Simplified)
======================================================
Classification and enforcement
Uses existing audit_log system for tracking access.
"""

import json
import os

# Classification Levels
class ClassificationLevel:
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"

# User Roles
class UserRole:
    GUEST = "guest"
    USER = "user"
    SELLER = "seller"
    ADMIN = "admin"

# Role Permissions
ROLE_PERMISSIONS = {
    UserRole.GUEST: [ClassificationLevel.PUBLIC],
    UserRole.USER: [ClassificationLevel.PUBLIC, ClassificationLevel.INTERNAL],
    UserRole.SELLER: [ClassificationLevel.PUBLIC, ClassificationLevel.INTERNAL],
    UserRole.ADMIN: [
        ClassificationLevel.PUBLIC,
        ClassificationLevel.INTERNAL,
        ClassificationLevel.CONFIDENTIAL,
        ClassificationLevel.RESTRICTED
    ]
}

# Data Classification Mapping
DATA_CLASSIFICATION = {
    # USERS TABLE
    "users.user_id": ClassificationLevel.INTERNAL,
    "users.email": ClassificationLevel.CONFIDENTIAL,
    "users.password_hash": ClassificationLevel.RESTRICTED,
    "users.first_name": ClassificationLevel.CONFIDENTIAL,
    "users.last_name": ClassificationLevel.CONFIDENTIAL,
    "users.phone_number": ClassificationLevel.CONFIDENTIAL,
    "users.nric": ClassificationLevel.RESTRICTED,
    "users.license_number": ClassificationLevel.CONFIDENTIAL,
    "users.verified": ClassificationLevel.INTERNAL,
    "users.user_type": ClassificationLevel.INTERNAL,
    
    # VEHICLES TABLE
    "vehicles.id": ClassificationLevel.PUBLIC,
    "vehicles.name": ClassificationLevel.PUBLIC,
    "vehicles.type": ClassificationLevel.PUBLIC,
    "vehicles.price_per_day": ClassificationLevel.PUBLIC,
    "vehicles.pickup_location": ClassificationLevel.PUBLIC,
    "vehicles.status": ClassificationLevel.INTERNAL,
    
    # Booking – safe display fields
    'bookings.vehicle_image': ClassificationLevel.PUBLIC,
    'bookings.vehicle_name': ClassificationLevel.PUBLIC,
    'bookings.vehicle_type': ClassificationLevel.PUBLIC,
    'bookings.pickup_location': ClassificationLevel.PUBLIC,
    'bookings.pickup_date': ClassificationLevel.INTERNAL,
    'bookings.return_date': ClassificationLevel.INTERNAL,
    'bookings.days': ClassificationLevel.INTERNAL,
    'bookings.total_amount': ClassificationLevel.CONFIDENTIAL,
    'bookings.status': ClassificationLevel.PUBLIC,
    
    # INCIDENT REPORTS
    "incident_reports.full_name": ClassificationLevel.CONFIDENTIAL,
    "incident_reports.contact_number": ClassificationLevel.CONFIDENTIAL,
    "incident_reports.email": ClassificationLevel.CONFIDENTIAL,
    
    # AUDIT/SECURITY LOGS
    "audit_logs.ip_address": ClassificationLevel.RESTRICTED,
    "audit_logs.user_id": ClassificationLevel.RESTRICTED,
    "audit_logs.previous_values": ClassificationLevel.RESTRICTED,
    "audit_logs.new_values": ClassificationLevel.RESTRICTED,
    "security_logs.ip_address": ClassificationLevel.RESTRICTED,
    "security_logs.user_id": ClassificationLevel.RESTRICTED,

    # BACKUP LOGS
    "backup_logs.backup_path": ClassificationLevel.RESTRICTED,

    # USER DOCUMENTS
    "user_documents.file_data": ClassificationLevel.RESTRICTED,

    # FRAUD LOGS
    "vehicle_fraud_logs.user_id": ClassificationLevel.RESTRICTED,
    "booking_fraud_logs.user_id": ClassificationLevel.RESTRICTED,
}

# Table-Level Classifications
TABLE_CLASSIFICATIONS = {
    "users": ClassificationLevel.CONFIDENTIAL,
    "vehicles": ClassificationLevel.PUBLIC,
    "bookings": ClassificationLevel.CONFIDENTIAL,
    "incident_reports": ClassificationLevel.CONFIDENTIAL,
    "audit_logs": ClassificationLevel.RESTRICTED,
    "security_logs": ClassificationLevel.RESTRICTED,
    "vehicle_fraud_logs": ClassificationLevel.RESTRICTED,
    "booking_fraud_logs": ClassificationLevel.RESTRICTED,
    "backup_logs": ClassificationLevel.RESTRICTED,
    "user_documents": ClassificationLevel.RESTRICTED,
}

# Ownership Rules (users can access their own data)
OWNERSHIP_RULES = {
    "users": "user_id",
    "bookings": "user_id",
    "incident_reports": "user_id",
}

# Redaction Templates
REDACTION_TEMPLATES = {
    ClassificationLevel.PUBLIC: "{value}",
    ClassificationLevel.INTERNAL: "***INTERNAL***",
    ClassificationLevel.CONFIDENTIAL: "***CONFIDENTIAL***",
    ClassificationLevel.RESTRICTED: "***RESTRICTED***",
}

# Metadata for Dashboard Display
CLASSIFICATION_METADATA = {
    ClassificationLevel.PUBLIC: {
        "description": "Publicly accessible information",
        "examples": "Vehicle names, public listings",
        "risk_level": "Low",
        "color": "#28a745",  # Green
        "badge_class": "badge-success"
    },
    ClassificationLevel.INTERNAL: {
        "description": "Internal use only, authenticated users",
        "examples": "User IDs, booking statuses",
        "risk_level": "Medium",
        "color": "#17a2b8",  # Blue
        "badge_class": "badge-info"
    },
    ClassificationLevel.CONFIDENTIAL: {
        "description": "Sensitive personal information",
        "examples": "Names, emails, phone numbers",
        "risk_level": "High",
        "color": "#ffc107",  # Yellow/Warning
        "badge_class": "badge-warning"
    },
    ClassificationLevel.RESTRICTED: {
        "description": "Highly sensitive, admin only",
        "examples": "Passwords, NRICs, payment tokens",
        "risk_level": "Critical",
        "color": "#dc3545",  # Red
        "badge_class": "badge-danger"
    }
}

# ============================================================================
# PERSISTENCE FUNCTIONS
# ============================================================================

# Path to store classification overrides
OVERRIDE_FILE = 'classification_overrides.json'

def load_overrides():
    """Load classification overrides from file"""
    if os.path.exists(OVERRIDE_FILE):
        try:
            with open(OVERRIDE_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading classification overrides: {e}")
            return {'columns': {}, 'tables': {}}
    return {'columns': {}, 'tables': {}}

def save_classification_override(key, new_level, is_table=False):
    """
    Save a classification override to file and update in-memory dictionaries
    
    Args:
        key: Column name (e.g., 'users.email') or table name (e.g., 'users')
        new_level: New classification level (PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED)
        is_table: True if updating a table, False if updating a column
    """
    # Load existing overrides
    overrides = load_overrides()
    
    # Update the override
    if is_table:
        overrides['tables'][key] = new_level
        # Update in-memory dictionary
        TABLE_CLASSIFICATIONS[key] = new_level
    else:
        overrides['columns'][key] = new_level
        # Update in-memory dictionary
        DATA_CLASSIFICATION[key] = new_level
    
    # Save to file
    try:
        with open(OVERRIDE_FILE, 'w') as f:
            json.dump(overrides, f, indent=2)
        print(f"✅ Saved classification override: {key} -> {new_level}")
    except Exception as e:
        raise Exception(f"Failed to save classification override: {str(e)}")

def apply_overrides():
    """Apply saved overrides on module load"""
    overrides = load_overrides()
    
    # Apply column overrides
    for key, level in overrides.get('columns', {}).items():
        DATA_CLASSIFICATION[key] = level
    
    # Apply table overrides
    for key, level in overrides.get('tables', {}).items():
        TABLE_CLASSIFICATIONS[key] = level
    
    if overrides.get('columns') or overrides.get('tables'):
        print(f"✅ Applied {len(overrides.get('columns', {}))} column and {len(overrides.get('tables', {}))} table classification overrides")

# Apply overrides when module is imported
apply_overrides()

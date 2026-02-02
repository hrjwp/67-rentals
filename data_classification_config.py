"""
Data Classification System Configuration (Simplified)
======================================================
Classification and enforcement
Uses existing audit_log system for tracking access.
"""

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
    "audit_logs.previous_values": ClassificationLevel.RESTRICTED,
    "audit_logs.new_values": ClassificationLevel.RESTRICTED,
    "security_logs.ip_address": ClassificationLevel.RESTRICTED,
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

"""
Data Classification Enforcement Module (Simplified)
===================================================
Pure classification and access control - uses existing audit_log for tracking.
"""

from typing import Optional, Dict, Any, List
from data_classification_config import (
    ClassificationLevel,
    UserRole,
    ROLE_PERMISSIONS,
    DATA_CLASSIFICATION,
    TABLE_CLASSIFICATIONS,
    OWNERSHIP_RULES,
    REDACTION_TEMPLATES
)


# ============================================================================
# EXCEPTIONS
# ============================================================================

class AccessDeniedException(Exception):
    """Raised when user attempts to access data they don't have permission for"""
    def __init__(self, column: str, classification: str, user_role: str):
        self.column = column
        self.classification = classification
        self.user_role = user_role
        super().__init__(
            f"Access denied to {column} (Classification: {classification}). "
            f"Role '{user_role}' lacks permission."
        )


# ============================================================================
# CORE FUNCTIONS
# ============================================================================

def get_classification(column_name: str) -> str:
    """Get classification level for a column. Defaults to CONFIDENTIAL if not defined."""
    return DATA_CLASSIFICATION.get(column_name, ClassificationLevel.CONFIDENTIAL)


def check_access(column_name: str, user_role: str, user_id: Optional[int] = None, 
                 data_owner_id: Optional[int] = None) -> bool:
    """
    Check if user can access a column.
    
    Args:
        column_name: Format "table_name.column_name"
        user_role: User's role (guest, user, seller, admin)
        user_id: Current user's ID (for ownership checks)
        data_owner_id: Owner of the data record
        
    Returns:
        True if access allowed, False otherwise
    """
    classification = get_classification(column_name)
    allowed_levels = ROLE_PERMISSIONS.get(user_role, [])
    
    # Check role permissions
    if classification in allowed_levels:
        return True
    
    # Special case: Users can access their own CONFIDENTIAL data
    if classification == ClassificationLevel.CONFIDENTIAL and user_id and data_owner_id:
        return user_id == data_owner_id
    
    return False


def enforce_classification(column_name: str, user_role: str, user_id: Optional[int] = None,
                          data_owner_id: Optional[int] = None) -> None:
    """
    Enforce access control. Raises AccessDeniedException if access denied.
    
    Usage:
        enforce_classification('users.email', user_role, user_id, owner_id)
    """
    if not check_access(column_name, user_role, user_id, data_owner_id):
        classification = get_classification(column_name)
        raise AccessDeniedException(column_name, classification, user_role)


def redact_data(value: Any, column_name: str, user_role: str, 
                user_id: Optional[int] = None, data_owner_id: Optional[int] = None) -> Any:
    """
    Redact data if user doesn't have permission.
    
    Returns:
        Original value if allowed, redacted string if not
    """
    if check_access(column_name, user_role, user_id, data_owner_id):
        return value
    
    classification = get_classification(column_name)
    return REDACTION_TEMPLATES.get(classification, "***REDACTED***")


def redact_dict(data: Dict[str, Any], table_name: str, user_role: str,
                user_id: Optional[int] = None, data_owner_id: Optional[int] = None) -> Dict[str, Any]:
    """
    Redact sensitive fields in a dictionary.
    
    Usage:
        safe_user = redact_dict(user, 'users', role, user_id, owner_id)
    """
    redacted = {}
    for key, value in data.items():
        column_name = f"{table_name}.{key}"
        redacted[key] = redact_data(value, column_name, user_role, user_id, data_owner_id)
    return redacted


def redact_list(data_list: List[Dict[str, Any]], table_name: str, user_role: str,
                user_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """Redact sensitive fields in a list of dictionaries."""
    redacted_list = []
    for data in data_list:
        data_owner_id = get_data_owner_id(table_name, data)
        redacted_list.append(redact_dict(data, table_name, user_role, user_id, data_owner_id))
    return redacted_list


def can_access_table(table_name: str, user_role: str) -> bool:
    """Check if user can access an entire table."""
    classification = TABLE_CLASSIFICATIONS.get(table_name, ClassificationLevel.RESTRICTED)
    allowed_levels = ROLE_PERMISSIONS.get(user_role, [])
    return classification in allowed_levels


def get_data_owner_id(table_name: str, data: Dict[str, Any]) -> Optional[int]:
    """Extract owner's user_id from data record."""
    if table_name not in OWNERSHIP_RULES:
        return None
    owner_column = OWNERSHIP_RULES[table_name]
    return data.get(owner_column)


def get_classification_stats() -> Dict[str, Any]:
    """Get statistics about classifications for dashboard."""
    stats = {
        'total_columns': len(DATA_CLASSIFICATION),
        'by_level': {},
        'by_table': {},
        'tables_count': len(TABLE_CLASSIFICATIONS)
    }
    
    # Count by classification level
    for classification in [ClassificationLevel.PUBLIC, ClassificationLevel.INTERNAL,
                          ClassificationLevel.CONFIDENTIAL, ClassificationLevel.RESTRICTED]:
        count = sum(1 for c in DATA_CLASSIFICATION.values() if c == classification)
        stats['by_level'][classification] = count
    
    # Count by table
    for column, classification in DATA_CLASSIFICATION.items():
        table = column.split('.')[0]
        if table not in stats['by_table']:
            stats['by_table'][table] = {
                'PUBLIC': 0,
                'INTERNAL': 0,
                'CONFIDENTIAL': 0,
                'RESTRICTED': 0
            }
        stats['by_table'][table][classification] += 1
    
    return stats


def get_columns_by_table(table_name: str) -> List[Dict[str, str]]:
    """Get all classified columns for a specific table."""
    columns = []
    for column_full, classification in DATA_CLASSIFICATION.items():
        table, column = column_full.split('.', 1)
        if table == table_name:
            columns.append({
                'column': column,
                'classification': classification,
                'full_name': column_full
            })
    return columns


# ============================================================================
# DECORATOR FOR ROUTE PROTECTION
# ============================================================================

def require_classification(column_name: str, allow_owner: bool = True):
    """
    Decorator to enforce classification on Flask routes.
    
    The exception will naturally propagate to Flask's @app.errorhandler(AccessDeniedException)
    where it can be logged to the audit trail.
    
    Usage:
        @app.route('/admin/users')
        @require_classification('users.nric')
        def admin_users():
            # Only accessible if user can access users.nric
            pass
    """
    def decorator(func):
        from functools import wraps
        from flask import session
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            user_role = session.get('user_type', UserRole.GUEST)
            user_id = session.get('user_id')
            data_owner_id = kwargs.get('user_id') if allow_owner else None
            
            # This will raise AccessDeniedException if access is denied
            # The exception will bubble up to Flask's error handler
            enforce_classification(column_name, user_role, user_id, data_owner_id)
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator

from functools import wraps
from flask import request, session
from database import add_audit_log

def audit_log(entity_type: str, action_arg=None, entity_id_arg=None, previous_arg=None, new_arg=None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            response = func(*args, **kwargs)

            user_id = session.get('user_id', 0)
            ip_address = request.remote_addr
            device_info = request.headers.get("User-Agent")

            # Get local variables from the route function
            local_vars = func.__globals__.copy()
            try:
                action_name = locals().get(action_arg) if action_arg else 'Unknown'
                entity_id = locals().get(entity_id_arg) if entity_id_arg else None
                previous_values = locals().get(previous_arg) if previous_arg else None
                new_values = locals().get(new_arg) if new_arg else None
            except Exception:
                action_name = 'Unknown'
                entity_id = None
                previous_values = None
                new_values = None

            add_audit_log(
                user_id=user_id,
                action=action_name,
                entity_type=entity_type,
                entity_id=entity_id,
                previous_values=previous_values,
                new_values=new_values,
                result='Success'
            )

            return response
        return wrapper
    return decorator

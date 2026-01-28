"""
Automatic encryption key and secret key setup.
This module automatically creates .env file with required keys if they don't exist.
Works seamlessly on any device with the same folder.
"""
import os
import secrets
import base64


def ensure_env_file():
    """
    Automatically create .env file with encryption keys if it doesn't exist.
    Preserves existing keys if .env already exists.
    Returns True if keys were created/loaded successfully.
    """
    env_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
    
    # Check if .env exists and read existing values
    existing_vars = {}
    if os.path.exists(env_file):
        try:
            with open(env_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        existing_vars[key.strip()] = value.strip()
        except Exception:
            # If reading fails, we'll create a new one
            existing_vars = {}
    
    # Generate keys if they don't exist
    encryption_key = existing_vars.get('DATA_ENCRYPTION_KEY')
    secret_key = existing_vars.get('SECRET_KEY')
    
    # Backup configuration (set defaults if not present)
    auto_backup_enabled = existing_vars.get('AUTO_BACKUP_ENABLED', 'true')  # Default to enabled
    auto_backup_interval = existing_vars.get('AUTO_BACKUP_INTERVAL_HOURS', '24')
    backup_retention = existing_vars.get('BACKUP_RETENTION_DAYS', '30')
    
    needs_update = False
    needs_backup_config = False
    
    # Generate encryption key if missing
    if not encryption_key:
        # Generate 32 random bytes (256-bit key for AES-256)
        key_bytes = secrets.token_bytes(32)
        encryption_key = base64.urlsafe_b64encode(key_bytes).decode('utf-8')
        needs_update = True
    
    # Generate secret key if missing
    if not secret_key:
        secret_key = secrets.token_urlsafe(32)  # 32 bytes = 256-bit key
        needs_update = True
    
    # Check if backup settings need to be added
    if 'AUTO_BACKUP_ENABLED' not in existing_vars:
        needs_backup_config = True
        needs_update = True
    
    # Write .env file if needed
    if needs_update:
        try:
            with open(env_file, 'w') as f:
                f.write(f"DATA_ENCRYPTION_KEY={encryption_key}\n")
                f.write(f"SECRET_KEY={secret_key}\n")
                
                # Add backup configuration if it was missing
                if needs_backup_config:
                    f.write(f"\n# Automated Backup Configuration\n")
                    f.write(f"AUTO_BACKUP_ENABLED={auto_backup_enabled}\n")
                    f.write(f"AUTO_BACKUP_INTERVAL_HOURS={auto_backup_interval}\n")
                    f.write(f"BACKUP_RETENTION_DAYS={backup_retention}\n")
                    print("✅ Automated backup configuration added to .env (enabled by default)")
            
            return True
        except Exception as e:
            print(f"Warning: Could not create .env file: {e}")
            return False
    
    return True

import os


def _env(key: str, default: str = "") -> str:
    """Read from environment. Real values must be in .env or system env (see .env.example)."""
    return os.environ.get(key, default).strip()
class Config:
    """Application configuration"""

    # Flask
    SECRET_KEY = _env("SECRET_KEY")
    # AES data encryption key (URL-safe base64, 16/24/32 bytes when decoded)
    DATA_ENCRYPTION_KEY = _env("DATA_ENCRYPTION_KEY")
    # Session cookie settings - will be overridden by app.py based on HTTPS usage
    SESSION_COOKIE_SECURE = True  # Will be set dynamically based on HTTPS
    SESSION_COOKIE_HTTPONLY = True     # block JS access to cookies
    SESSION_COOKIE_SAMESITE = 'Lax'    # CSRF-hardening for most flows
    PREFERRED_URL_SCHEME = 'http'  # Will be set dynamically

    # Stripe
    STRIPE_API_KEY = _env("STRIPE_API_KEY")
    STRIPE_PUBLIC_KEY = _env("STRIPE_PUBLIC_KEY")
    # Email (SMTP)
    SMTP_HOST = ''
    SMTP_PORT = 587
    SMTP_USER = ''
    SMTP_PASS = ''
    SMTP_FROM = ''

    # File Upload
    UPLOAD_FOLDER = 'static/uploads'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
    
    # Backup Configuration
    BACKUP_DIR = 'backups'  # local encrypted backups
    CLOUD_BACKUP_DIR = None
    BACKUP_RETENTION_DAYS = 2  # Keep backups for 30 days
    AUTO_BACKUP_ENABLED = True
    AUTO_BACKUP_INTERVAL_HOURS = 24  # Daily backups
    RETENTION_CHECK_INTERVAL_HOURS = 24  # Data retention scheduler interval

    # Stripe
    STRIPE_WEBHOOK_SECRET = ''

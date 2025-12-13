import os


class Config:
    """Application configuration"""

    # Flask
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-here-change-in-production')
    # AES data encryption key (URL-safe base64, 16/24/32 bytes when decoded)
    DATA_ENCRYPTION_KEY = os.environ.get('DATA_ENCRYPTION_KEY')
    SESSION_COOKIE_SECURE = False  # Disable for local HTTP; enable True in production
    SESSION_COOKIE_HTTPONLY = True     # block JS access to cookies
    SESSION_COOKIE_SAMESITE = 'Lax'    # CSRF-hardening for most flows
    PREFERRED_URL_SCHEME = 'http'

    # Stripe
    STRIPE_API_KEY = 'sk_test_51SVUC6Cddk4teDLIfl8dquKj8ZAFQYyyuKQ7Oizda4SampGMLUENpCpIG3r33VnHV8zER3vqBZelZclbeCy76bGp00gXIme9XE'
    STRIPE_PUBLIC_KEY = 'pk_test_51SVUC6Cddk4teDLIlq20hYCe9zbzZw1pUExM6fFGMTQCUZajqdyIaJbdSdRQD5gKibRmXYhQ0EochV9WKwYyUVwP00Ww3hpFsJ'

    # File Upload
    UPLOAD_FOLDER = 'static/uploads'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
    
    # Backup Configuration
    BACKUP_DIR = os.environ.get('BACKUP_DIR', 'backups')
    CLOUD_BACKUP_DIR = os.environ.get('CLOUD_BACKUP_DIR')  # Set to cloud storage path (e.g., AWS S3, Google Drive)
    BACKUP_RETENTION_DAYS = int(os.environ.get('BACKUP_RETENTION_DAYS', '30'))  # Keep backups for 30 days
    AUTO_BACKUP_ENABLED = os.environ.get('AUTO_BACKUP_ENABLED', 'False').lower() == 'true'
    AUTO_BACKUP_INTERVAL_HOURS = int(os.environ.get('AUTO_BACKUP_INTERVAL_HOURS', '24'))  # Daily backups

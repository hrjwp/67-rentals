import os


class Config:
    """Application configuration"""

    # Flask
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-here-change-in-production')
    # AES data encryption key (URL-safe base64, 16/24/32 bytes when decoded)
    DATA_ENCRYPTION_KEY = os.environ.get('DATA_ENCRYPTION_KEY')
    # Session cookie settings - will be overridden by app.py based on HTTPS usage
    SESSION_COOKIE_SECURE = False  # Will be set dynamically based on HTTPS
    SESSION_COOKIE_HTTPONLY = True     # block JS access to cookies
    SESSION_COOKIE_SAMESITE = 'Lax'    # CSRF-hardening for most flows
    PREFERRED_URL_SCHEME = 'http'  # Will be set dynamically

    # Stripe
    STRIPE_API_KEY = 'sk_test_51Qt62CEu3QerzS1yLWYhnwyX9UfVX2joIEDmUghjcCI1rY1mfscebN6bKttdNw0N446QucqKwOGoNGYZsVaYffx800HM2RGjR1'
    STRIPE_PUBLIC_KEY = 'pk_test_51Qt62CEu3QerzS1yyA1sCZ5WXb4gimBa6RrAOiqzUkb2H4CvEda5qs2d1VNU7yPh6L5kS4XaE5BJwJJtGxPWhdZ100WgIyODq8'

    # Email (SMTP)
    SMTP_HOST = os.environ.get('SMTP_HOST', '')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
    SMTP_USER = os.environ.get('SMTP_USER', '')
    SMTP_PASS = os.environ.get('SMTP_PASS', '')
    SMTP_FROM = os.environ.get('SMTP_FROM', '')

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

class Config:
    """Application configuration"""

    # Flask
    SECRET_KEY = "ApwndeZdD93PE8mPTua_q_oATzzyNd5wBkdSgmyl39U"
    # AES data encryption key (URL-safe base64, 16/24/32 bytes when decoded)
    DATA_ENCRYPTION_KEY = "cjqqek7dDkmj-fv3OXWvCZvDDsG5HRApJZ9oTb7zvNo="
    # Session cookie settings - will be overridden by app.py based on HTTPS usage
    SESSION_COOKIE_SECURE = False  # Will be set dynamically based on HTTPS
    SESSION_COOKIE_HTTPONLY = True     # block JS access to cookies
    SESSION_COOKIE_SAMESITE = 'Lax'    # CSRF-hardening for most flows
    PREFERRED_URL_SCHEME = 'https'  # Will be set dynamically

    # Stripe
    STRIPE_API_KEY = 'sk_test_51Qt62CEu3QerzS1yLWYhnwyX9UfVX2joIEDmUghjcCI1rY1mfscebN6bKttdNw0N446QucqKwOGoNGYZsVaYffx800HM2RGjR1'
    STRIPE_PUBLIC_KEY = 'pk_test_51Qt62CEu3QerzS1yyA1sCZ5WXb4gimBa6RrAOiqzUkb2H4CvEda5qs2d1VNU7yPh6L5kS4XaE5BJwJJtGxPWhdZ100WgIyODq8'

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
    BACKUP_RETENTION_DAYS = 30  # Keep backups for 30 days
    AUTO_BACKUP_ENABLED = True
    AUTO_BACKUP_INTERVAL_HOURS = 24  # Daily backups
    RETENTION_CHECK_INTERVAL_HOURS = 24  # Data retention scheduler interval

    # Stripe
    STRIPE_WEBHOOK_SECRET = ''

import os


class Config:
    """Application configuration"""

    # Flask
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-here-change-in-production')
    # AES data encryption key (URL-safe base64, 16/24/32 bytes when decoded)
    DATA_ENCRYPTION_KEY = os.environ.get('DATA_ENCRYPTION_KEY')
    SESSION_COOKIE_SECURE = True  # Requires HTTPS
    SESSION_COOKIE_HTTPONLY = True     # block JS access to cookies
    SESSION_COOKIE_SAMESITE = 'Lax'    # CSRF-hardening for most flows
    PREFERRED_URL_SCHEME = 'https'

    # Stripe
    STRIPE_API_KEY = 'sk_test_51SVUC6Cddk4teDLIfl8dquKj8ZAFQYyyuKQ7Oizda4SampGMLUENpCpIG3r33VnHV8zER3vqBZelZclbeCy76bGp00gXIme9XE'
    STRIPE_PUBLIC_KEY = 'pk_test_51SVUC6Cddk4teDLIlq20hYCe9zbzZw1pUExM6fFGMTQCUZajqdyIaJbdSdRQD5gKibRmXYhQ0EochV9WKwYyUVwP00Ww3hpFsJ'

    # File Upload
    UPLOAD_FOLDER = 'static/uploads'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

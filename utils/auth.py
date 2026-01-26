from functools import wraps
from flask import session, redirect, url_for, flash
import hashlib
import secrets
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.utils import parseaddr

from config import Config


def login_required(f):
    """
    Decorator to require login for routes
    Usage: @login_required
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Please login to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def seller_required(f):
    """
    Decorator to require seller privileges
    Usage: @seller_required
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Please login to access this page', 'error')
            return redirect(url_for('login'))

        # Add your seller check logic here
        # For example, check if user has seller role
        # if not session.get('is_seller'):
        #     flash('Access denied. Seller privileges required.', 'error')
        #     return redirect(url_for('index'))

        return f(*args, **kwargs)

    return decorated_function


def generate_reset_token():
    """Generate a secure random token for password reset"""
    return secrets.token_urlsafe(32)


def generate_otp() -> str:
    """Generate a 6-digit numeric OTP."""
    return f"{secrets.randbelow(1000000):06d}"


def hash_otp(otp: str, salt: str) -> str:
    """Hash OTP with salt."""
    return hashlib.sha256(f"{salt}{otp}".encode()).hexdigest()


def _get_smtp_config():
    host = Config.SMTP_HOST
    user = Config.SMTP_USER
    password = Config.SMTP_PASS
    if not host or not user or not password:
        return None
    port_raw = Config.SMTP_PORT
    port = int(port_raw) if str(port_raw).isdigit() else 587
    from_email = Config.SMTP_FROM or user
    return host, port, user, password, from_email


def _send_via_smtp(to_email: str, subject: str, html: str) -> None:
    config = _get_smtp_config()
    if not config:
        raise RuntimeError("SMTP is not configured")
    host, port, user, password, from_email = config
    msg = MIMEText(html, "html")
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email
    from_addr = parseaddr(from_email)[1] or from_email
    with smtplib.SMTP(host, port, timeout=10) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(user, password)
        server.sendmail(from_addr, [to_email], msg.as_string())


def send_password_reset_otp_email(email: str, otp: str):
    """Send password reset OTP via SMTP."""
    subject = "Your 67 Rentals password reset code"
    html = f"""
    <div style="font-family: 'DM Sans', Arial, sans-serif; max-width: 520px; margin: 0 auto;">
      <h2 style="color:#3D405B;">Reset your 67 Rentals password</h2>
      <p style="color:#717275;">Use the code below to reset your password. This code expires in 10 minutes.</p>
      <div style="background:#F4F1DE;padding:16px;border-radius:12px;text-align:center;font-size:24px;font-weight:700;letter-spacing:4px;color:#3D405B;">
        {otp}
      </div>
      <p style="color:#717275;margin-top:16px;">If you didn’t request this, you can ignore this email.</p>
      <p style="color:#717275;">— 67 Rentals Team</p>
    </div>
    """
    _send_via_smtp(email, subject, html)

def send_password_reset_email(email, reset_token, base_url: str = None):
    """
    Send password reset email to user
    In production, integrate with email service like SendGrid, AWS SES, or SMTP
    """
    # For development, just print the reset link
    base = base_url.rstrip("/") if base_url else "http://localhost:5001"
    reset_link = f"{base}/reset-password/{reset_token}"
    print(f"\n{'=' * 60}")
    print(f"PASSWORD RESET EMAIL")
    print(f"{'=' * 60}")
    print(f"To: {email}")
    print(f"Subject: Reset Your 67 Rentals Password")
    print(f"\nClick the link below to reset your password:")
    print(f"{reset_link}")
    print(f"\nThis link will expire in 1 hour.")
    print(f"{'=' * 60}\n")

    # TODO: In production, replace with actual email sending:
    # import smtplib
    # from email.mime.text import MIMEText
    # msg = MIMEText(f"Reset your password: {reset_link}")
    # msg['Subject'] = 'Reset Your 67 Rentals Password'
    # msg['From'] = 'noreply@67rentals.com'
    # msg['To'] = email
    # with smtplib.SMTP('smtp.gmail.com', 587) as server:
    #     server.starttls()
    #     server.login('your-email@gmail.com', 'your-password')
    #     server.send_message(msg)

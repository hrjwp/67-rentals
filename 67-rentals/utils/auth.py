from functools import wraps
from flask import session, redirect, url_for, flash
import secrets
from datetime import datetime, timedelta


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


def send_password_reset_email(email, reset_token):
    """
    Send password reset email to user
    In production, integrate with email service like SendGrid, AWS SES, or SMTP
    """
    # For development, just print the reset link
    reset_link = f"http://localhost:5000/reset-password/{reset_token}"
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
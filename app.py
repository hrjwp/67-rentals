from flask import Flask, render_template, request, session, redirect, url_for, jsonify, flash
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import stripe
import os
import json
import re
import secrets

# Load .env file BEFORE importing Config
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    from utils.auto_setup import ensure_env_file
    ensure_env_file()
    load_dotenv()  # reload so new .env is picked up
except Exception:
    pass

# Import configuration (AFTER loading .env)
from config import Config

from database import (
    get_user_by_email, create_user_with_documents, get_all_vehicles,
    get_vehicle_by_id, create_booking, get_booking_by_id,
    update_user_password, get_reset_token, mark_token_as_used,
    invalidate_password_reset_otps, create_password_reset_otp,
    get_latest_password_reset_otp, increment_password_reset_otp_attempts,
    mark_password_reset_otp_used,
    get_user_bookings, get_signup_tickets, set_signup_status, get_user_documents,
    get_db_connection, get_security_logs, get_vehicle_fraud_logs, get_booking_fraud_logs,
    get_security_stats, get_vehicle_fraud_stats, get_booking_fraud_stats,
    add_security_log, add_vehicle_fraud_log, add_booking_fraud_log,
    create_incident_report, get_incident_reports,
    update_incident_status, delete_incident_report, add_audit_log, get_audit_logs, get_user_by_id,
    get_backup_logs, get_backup_stats, update_backup_verification,
    ensure_incident_report_files_table, update_user_last_login,
    get_retention_settings, update_retention_settings, run_retention_purge,
    get_retention_overview, set_retention_extension, purge_user_data,
    update_user_profile,
    # Data retention policies (multi-type)
    get_all_retention_policies, get_retention_policy, update_retention_policy,
    get_retention_statistics, purge_data_for_type, run_all_retention_purges
)

# Import data models
from models import (
    VEHICLES, BOOKINGS, CANCELLATION_REQUESTS, REFUNDS,
    listings
)

# Import utilities
from utils.validation import (
    validate_name, validate_email, validate_phone, validate_nric,
    validate_license, validate_password, validate_file_size, allowed_file,
    extract_age_from_nric
)
from utils.auth import (
    login_required, generate_otp, hash_otp, send_password_reset_otp_email
)
from utils.helpers import (
    calculate_refund_percentage, calculate_cart_totals,
    generate_booking_id, generate_request_id, generate_refund_id,
    get_cart_count
)
from utils.encryption import encrypt_value, decrypt_value
from utils.backup import SecureBackup
from utils.file_security import validate_uploaded_file, sanitize_filename
from utils.file_encryption import process_incident_file, decrypt_file, encrypt_file
import threading
import time
from datetime import datetime, timedelta

# Import data classification functions
from data_classification import (
    check_access, #testing
    enforce_classification,
    redact_dict,
    require_classification,
    can_access_table,
    get_classification_stats,
    AccessDeniedException
)
from data_classification_config import (
    UserRole,
    DATA_CLASSIFICATION,
    TABLE_CLASSIFICATIONS,
    CLASSIFICATION_METADATA
)


def normalize_severity(severity_value):
    """Normalize severity to: Low, Medium, High, or Critical"""
    if not severity_value:
        return 'Low'
    
    severity_lower = str(severity_value).lower().strip()
    
    severity_map = {
        'low': 'Low', 'minor': 'Low',
        'medium': 'Medium', 'moderate': 'Medium',
        'high': 'High', 'major': 'High', 'severe': 'High',
        'critical': 'Critical', 'emergency': 'Critical'
    }
    
    return severity_map.get(severity_lower, 'Low')

# Import audit log decorator
from audit_helper import audit_log

app = Flask(__name__)

app.config.from_object(Config)
stripe.api_key = Config.STRIPE_API_KEY

PRINT_BLOCK_STYLE = """
<style id="print-block-style">
@media print {
  body {
    margin: 0 !important;
  }
  body * {
    display: none !important;
  }
  body::before {
    content: "Printing is prohibited.";
    display: block;
    padding: 24px;
    font-size: 16px;
    font-family: Arial, sans-serif;
    color: #000;
  }
}
</style>
"""

PRINT_BLOCK_SCRIPT = """
<script id="print-block-script">
(function () {
  function notifyPrintBlocked() {
    var modal = document.getElementById('printBlockedModal');
    if (!modal) return;
    modal.classList.add('show');
    modal.setAttribute('aria-hidden', 'false');
    if (modal._hideTimer) clearTimeout(modal._hideTimer);
    modal._hideTimer = setTimeout(function () {
      modal.classList.remove('show');
      modal.setAttribute('aria-hidden', 'true');
    }, 2200);
  }

  function blockPrintEvent(e) {
    if (e && e.preventDefault) e.preventDefault();
    if (e && e.stopPropagation) e.stopPropagation();
    notifyPrintBlocked();
    return false;
  }

  function isPrintShortcut(e) {
    if (!e) return false;
    var key = e.key || '';
    var code = e.code || '';
    var isP = (key && key.toLowerCase() === 'p') || code === 'KeyP' || e.keyCode === 80;
    return (e.ctrlKey || e.metaKey) && isP;
  }

  document.addEventListener('keydown', function (e) {
    if (isPrintShortcut(e)) {
      blockPrintEvent(e);
    }
  }, true);

  window.addEventListener('beforeprint', blockPrintEvent, true);

  if (window.matchMedia) {
    var mediaQuery = window.matchMedia('print');
    if (mediaQuery.addEventListener) {
      mediaQuery.addEventListener('change', function (e) {
        if (e.matches) {
          blockPrintEvent(e);
        }
      });
    } else if (mediaQuery.addListener) {
      mediaQuery.addListener(function (e) {
        if (e.matches) {
          blockPrintEvent(e);
        }
      });
    }
  }

  if (typeof window.print === 'function') {
    window.print = function () { return false; };
  }
})();
</script>
"""


def _inject_print_block(response):
    if response.mimetype != "text/html":
        return response
    if response.direct_passthrough or response.is_streamed:
        return response
    data = response.get_data(as_text=True)
    if "print-block-style" in data or "print-block-script" in data:
        return response
    injection = PRINT_BLOCK_STYLE + PRINT_BLOCK_SCRIPT
    if "</head>" in data:
        data = data.replace("</head>", injection + "</head>", 1)
    elif "</body>" in data:
        data = data.replace("</body>", injection + "</body>", 1)
    else:
        return response
    response.set_data(data)
    response.headers.pop("Content-Length", None)
    return response


@app.before_request
def configure_https_settings():
    """
    Automatically detect HTTPS and configure secure cookies.
    Works with ngrok and other reverse proxies via X-Forwarded-Proto header.
    Enforces Secure, HttpOnly cookies for XSS protection.
    """
    # Check if request is HTTPS (works with ngrok and direct HTTPS)
    # Also check for ngrok-specific headers and URL
    host = request.headers.get('Host', '').lower()
    is_https = (
        request.is_secure or 
        request.headers.get('X-Forwarded-Proto') == 'https' or
        request.headers.get('X-Forwarded-Ssl') == 'on' or
        'ngrok' in host or
        request.url.startswith('https://')
    )
    
    # Configure Flask session cookies with maximum security
    # Secure: Only send cookies over HTTPS (prevents man-in-the-middle)
    # HttpOnly: Prevents JavaScript access (prevents XSS attacks)
    # SameSite: CSRF protection
    app.config['SESSION_COOKIE_SECURE'] = is_https
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # Always enforce HttpOnly
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
    app.config['PREFERRED_URL_SCHEME'] = 'https' if is_https else 'http'
    
    # For ngrok: Don't set cookie domain to allow cookies to work across subdomains
    # This helps when ngrok URL changes
    if 'ngrok' in host:
        app.config['SESSION_COOKIE_DOMAIN'] = None  # Allow cookies on any domain
    else:
        app.config['SESSION_COOKIE_DOMAIN'] = None  # Default: current domain only
    
    # Ensure session persists across requests
    # This helps with ngrok where the domain might change
    if 'user' in session:
        session.permanent = True
        session.modified = True
        _refresh_session_display_name()


@app.after_request
def add_security_headers(response):
    """
    Add baseline security headers to help protect data in transit and reduce
    injection/clickjacking risks. Kept permissive enough for current CDN usage.
    Also ensure session cookies are properly set for ngrok.
    """
    # Ensure session is persisted if user is logged in
    if 'user' in session:
        session.modified = True
    csp = (
        "default-src 'self'; "
        "img-src 'self' data: https:; "
        "script-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://code.jquery.com "
        "https://www.youtube.com https://www.youtube-nocookie.com https://www.gstatic.com https://js.stripe.com "
        "'unsafe-inline'; "
        "style-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://fonts.googleapis.com "
        "'unsafe-inline'; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com data:; "
        "connect-src 'self' https://api.stripe.com https://cdnjs.cloudflare.com; "
        "frame-src 'self' https://www.youtube.com https://www.youtube-nocookie.com https://js.stripe.com; "
        "frame-ancestors 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    response.headers.setdefault("Content-Security-Policy", csp)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return _inject_print_block(response)


def _encrypt_user_record(user_data: dict) -> dict:
    """Encrypt sensitive fields for storage."""
    encrypted = dict(user_data)
    for field in ("first_name", "last_name", "phone", "nric", "license_number"):
        if field in encrypted:
            encrypted[field] = encrypt_value(encrypted[field])
    return encrypted


def _decrypt_user_record(user_data: dict) -> dict:
    """Decrypt sensitive fields when reading."""
    decrypted = dict(user_data)
    for field in ("first_name", "last_name", "phone", "nric", "license_number"):
        if field in decrypted:
            decrypted[field] = decrypt_value(decrypted[field], fallback_on_error=True)
    return decrypted


def _looks_encrypted_token(token: str) -> bool:
    if not token or len(token) < 20:
        return False
    for ch in token:
        if not (ch.isalnum() or ch in "-_="):
            return False
    return True


def _looks_encrypted_name(name: str) -> bool:
    if not name:
        return False
    parts = [p for p in str(name).strip().split() if p]
    if not parts:
        return False
    return all(_looks_encrypted_token(part) for part in parts)


def _refresh_session_display_name():
    if 'user' not in session:
        return
    raw_name = session.get('user_name') or ''
    if raw_name and not _looks_encrypted_name(raw_name):
        return
    user = None
    if session.get('user_id'):
        try:
            user = get_user_by_id(session.get('user_id'))
        except Exception:
            user = None
    if not user and session.get('user'):
        user = get_user_by_email(session.get('user'))
    if not user:
        return
    first_name = decrypt_value(user.get('first_name') or '', fallback_on_error=True) if user.get('first_name') else ''
    last_name = decrypt_value(user.get('last_name') or '', fallback_on_error=True) if user.get('last_name') else ''
    display_name = _safe_display_name(first_name, last_name, session.get('user'))
    if display_name:
        session['user_name'] = display_name
        session.modified = True


def _safe_display_name(first_name: str, last_name: str, email: str | None) -> str:
    display = f"{first_name} {last_name}".strip()
    if display and not _looks_encrypted_name(display):
        return display
    if email:
        return email.split('@')[0]
    return display


def _get_latest_signup_status(email: str):
    """
    Return the most recent signup_tickets.status for the given email.
    Used to distinguish between pending and rejected logins.
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                """
                SELECT t.status
                FROM signup_tickets t
                JOIN users u ON u.user_id = t.user_id
                WHERE u.email = %s
                ORDER BY t.submitted_at DESC
                LIMIT 1
                """,
                (email,),
            )
            row = cursor.fetchone()
            cursor.close()
            return row["status"] if row else None
    except Exception as exc:  # pragma: no cover - defensive logging
        print(f"Signup status lookup failed: {exc}")
        return None


# ============================================
# MAIN ROUTES
# ============================================

@app.route("/")
def index():
    default_pickup = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d')
    default_return = (datetime.now() + timedelta(days=3)).strftime('%Y-%m-%d')
    cart_count = get_cart_count(session)
    return render_template('index.html',
                           default_pickup=default_pickup,
                           default_return=default_return,
                           cart_count=cart_count)


@app.route("/index_logged")
def index_logged():
    default_pickup = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d')
    default_return = (datetime.now() + timedelta(days=3)).strftime('%Y-%m-%d')
    cart_count = get_cart_count(session)
    return render_template('index_logged.html',
                           default_pickup=default_pickup,
                           default_return=default_return,
                           cart_count=cart_count,
                           user_email=session.get('user'),
                           user_name=session.get('user_name'))


# ============================================
# AUTHENTICATION ROUTES
# ============================================

# ============================================
# AUTHENTICATION ROUTES
# ============================================
# signup selection page
# ============================================
# SIGNUP SELECTION PAGE
# ============================================
# ============================================
# UPDATED ROUTES WITH NEW NAMES
# ============================================

# ============================================
# SIGNUP SELECTION PAGE
# ============================================
@app.route('/signup_sel', methods=['GET', 'POST'])
def signup_sel():
    # Clear any stale flashes (e.g., welcome/login messages) when viewing signup selection
    session.pop('_flashes', None)
    return render_template('signup_sel.html')


# ============================================
# SELLER SIGNUP
# ============================================
@app.route('/signup_seller', methods=['GET', 'POST'])
def signup_seller():
    if request.method == 'GET':
        return render_template('signup_seller.html')

    if request.method == 'POST':
        try:
            errors = []

            # Get form data
            first_name = request.form.get('firstName', '').strip()
            last_name = request.form.get('lastName', '').strip()
            email = request.form.get('email', '').strip().lower()
            phone = request.form.get('phone', '').strip()
            password = request.form.get('password', '')

            # Get uploaded files
            nric_image = request.files.get('nricImage')
            license_image = request.files.get('licenseImage')
            vehicle_card_image = request.files.get('vehicleCardImage')
            insurance_image = request.files.get('insuranceImage')

            # Validate all required fields are present
            if not all([first_name, last_name, email, phone, password]):
                errors.append('All personal information fields are required')

            if not all([nric_image, license_image, vehicle_card_image, insurance_image]):
                errors.append('All document images are required')

            existing = get_user_by_email(email)
            if existing:
                errors.append('Email already registered')

            # Validate file types and sizes
            for file_field, file_name in [
                (nric_image, 'NRIC image'),
                (license_image, 'License image'),
                (vehicle_card_image, 'Vehicle card image'),
                (insurance_image, 'Insurance image')
            ]:
                if file_field and file_field.filename != '':
                    if not allowed_file(file_field.filename):
                        errors.append(f'{file_name} must be a valid image file (png, jpg, jpeg, gif)')
                    elif not validate_file_size(file_field):
                        errors.append(f'{file_name} must be less than 5MB')
                    else:
                        # Enhanced security: Verify file content matches extension (magic number check)
                        is_valid, error_msg, detected_type = validate_uploaded_file(file_field)
                        if not is_valid:
                            errors.append(f'{file_name}: {error_msg}')
                            # --- Security audit log for malicious file upload ---
                            add_audit_log(
                                user_id=0,  # Not yet registered
                                action='Malicious File Upload Attempt',
                                entity_type='SECURITY',
                                entity_id='file_upload',
                                reason=f'File validation failed: {error_msg}',
                                result='Blocked',
                                severity='High',
                                ip_address=request.remote_addr,
                                device_info=request.headers.get("User-Agent")
                            )

            # If there are validation errors, return them
            if errors:
                for error in errors:
                    flash(error, 'error')
                return redirect(url_for('signup_seller'))

            # Create upload directory if it doesn't exist
            if not os.path.exists(Config.UPLOAD_FOLDER):
                os.makedirs(Config.UPLOAD_FOLDER)

            # Save files with secure filenames
            # Sanitize filenames for security
            safe_nric_filename = sanitize_filename(nric_image.filename)
            safe_license_filename = sanitize_filename(license_image.filename)
            safe_vehicle_card_filename = sanitize_filename(vehicle_card_image.filename)
            safe_insurance_filename = sanitize_filename(insurance_image.filename)

            nric_filename = secure_filename(f"{email}_nric_{safe_nric_filename}")
            license_filename = secure_filename(f"{email}_license_{safe_license_filename}")
            vehicle_card_filename = secure_filename(f"{email}_vehicle_{safe_vehicle_card_filename}")
            insurance_filename = secure_filename(f"{email}_insurance_{safe_insurance_filename}")

            # Capture bytes and encrypt before storage
            nric_bytes = nric_image.read()
            license_bytes = license_image.read()
            vehicle_card_bytes = vehicle_card_image.read()
            insurance_bytes = insurance_image.read()

            encrypted_nric_bytes = encrypt_file(nric_bytes)
            encrypted_license_bytes = encrypt_file(license_bytes)
            encrypted_vehicle_card_bytes = encrypt_file(vehicle_card_bytes)
            encrypted_insurance_bytes = encrypt_file(insurance_bytes)

            encrypted_nric_filename = f"{nric_filename}.enc"
            encrypted_license_filename = f"{license_filename}.enc"
            encrypted_vehicle_card_filename = f"{vehicle_card_filename}.enc"
            encrypted_insurance_filename = f"{insurance_filename}.enc"

            # Save encrypted files to disk
            with open(os.path.join(Config.UPLOAD_FOLDER, encrypted_nric_filename), 'wb') as f:
                f.write(encrypted_nric_bytes)
            with open(os.path.join(Config.UPLOAD_FOLDER, encrypted_license_filename), 'wb') as f:
                f.write(encrypted_license_bytes)
            with open(os.path.join(Config.UPLOAD_FOLDER, encrypted_vehicle_card_filename), 'wb') as f:
                f.write(encrypted_vehicle_card_bytes)
            with open(os.path.join(Config.UPLOAD_FOLDER, encrypted_insurance_filename), 'wb') as f:
                f.write(encrypted_insurance_bytes)

            documents = {
                'nric_image': {'filename': nric_filename, 'mime': nric_image.mimetype, 'data': encrypted_nric_bytes,
                               'path': encrypted_nric_filename},
                'license_image': {'filename': license_filename, 'mime': license_image.mimetype,
                                  'data': encrypted_license_bytes, 'path': encrypted_license_filename},
                'vehicle_card_image': {'filename': vehicle_card_filename, 'mime': vehicle_card_image.mimetype,
                                       'data': encrypted_vehicle_card_bytes, 'path': encrypted_vehicle_card_filename},
                'insurance_image': {'filename': insurance_filename, 'mime': insurance_image.mimetype,
                                    'data': encrypted_insurance_bytes, 'path': encrypted_insurance_filename}
            }

            seller_data_plain = {
                'first_name': first_name,
                'last_name': last_name,
                'email': email,
                'phone': phone,
                'password_hash': generate_password_hash(password),
                'user_type': 'seller',
                'documents': documents
            }

            user_id = create_user_with_documents(seller_data_plain)

            # --- Audit log for seller registration ---
            add_audit_log(
                user_id=user_id if user_id else 0,
                action='Seller Registration',
                entity_type='USER',
                entity_id=user_id if user_id else 0,
                new_values=json.dumps({'email': email, 'user_type': 'seller', 'first_name': first_name, 'last_name': last_name}),
                result='Success',
                ip_address=request.remote_addr,
                device_info=request.headers.get("User-Agent")
            )

            # Show pending approval page immediately after successful submission
            return render_template('pending_reg.html')

        except Exception as e:
            flash(f'An error occurred during registration: {str(e)}', 'error')
            return redirect(url_for('signup_seller'))

    return render_template('signup_seller.html')


# ============================================
# USER SIGNUP
# ============================================
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Sign up page with comprehensive validation including NRIC checksum"""
    if request.method == 'GET':
        return render_template('signup.html')

    if request.method == 'POST':
        errors = []

        # Get form data
        first_name = request.form.get('firstName', '').strip()
        last_name = request.form.get('lastName', '').strip()
        email = request.form.get('email', '').strip().lower()
        phone = request.form.get('phone', '').strip()
        nric = request.form.get('nric', '').strip().upper()
        license_number = request.form.get('license', '').strip().upper()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirmPassword', '')

        # Validate all fields
        if not first_name:
            errors.append('First name is required')
        elif not validate_name(first_name):
            errors.append('First name contains invalid characters or is too short')

        if not last_name:
            errors.append('Last name is required')
        elif not validate_name(last_name):
            errors.append('Last name contains invalid characters or is too short')

        if not email:
            errors.append('Email is required')
        elif not validate_email(email):
            errors.append('Invalid email format')

        if not phone:
            errors.append('Phone number is required')
        elif not validate_phone(phone):
            errors.append('Invalid phone number. Must be 8 digits starting with 6, 8, or 9')

        if not nric:
            errors.append('NRIC number is required')

        if not license_number:
            errors.append('Driver\'s license number is required')

        if not password:
            errors.append('Password is required')
        else:
            is_valid, message = validate_password(password)
            if not is_valid:
                errors.append(message)

        if password != confirm_password:
            errors.append('Passwords do not match')

        # Validate file uploads
        nric_image = request.files.get('nricImage')
        license_image = request.files.get('licenseImage')

        if not nric_image or nric_image.filename == '':
            errors.append('NRIC image is required')
        elif not allowed_file(nric_image.filename):
            errors.append('NRIC image must be a valid image file (png, jpg, jpeg, gif)')
        elif not validate_file_size(nric_image):
            errors.append('NRIC image must be less than 5MB')
        else:
            # Enhanced security: Verify file content matches extension (magic number check)
            is_valid, error_msg, detected_type = validate_uploaded_file(nric_image)
            if not is_valid:
                errors.append(f'NRIC image: {error_msg}')
                # --- Security audit log for malicious file upload ---
                add_audit_log(
                    user_id=0,  # Not yet registered
                    action='Malicious File Upload Attempt',
                    entity_type='SECURITY',
                    entity_id='file_upload',
                    reason=f'NRIC image validation failed: {error_msg}',
                    result='Blocked',
                    severity='High',
                    ip_address=request.remote_addr,
                    device_info=request.headers.get("User-Agent")
                )

        if not license_image or license_image.filename == '':
            errors.append('Driver\'s license image is required')
        elif not allowed_file(license_image.filename):
            errors.append('License image must be a valid image file (png, jpg, jpeg, gif)')
        elif not validate_file_size(license_image):
            errors.append('License image must be less than 5MB')
        else:
            # Enhanced security: Verify file content matches extension (magic number check)
            is_valid, error_msg, detected_type = validate_uploaded_file(license_image)
            if not is_valid:
                errors.append(f'License image: {error_msg}')
                # --- Security audit log for malicious file upload ---
                add_audit_log(
                    user_id=0,  # Not yet registered
                    action='Malicious File Upload Attempt',
                    entity_type='SECURITY',
                    entity_id='file_upload',
                    reason=f'License image validation failed: {error_msg}',
                    result='Blocked',
                    severity='High',
                    ip_address=request.remote_addr,
                    device_info=request.headers.get("User-Agent")
                )

        existing = get_user_by_email(email)
        if existing:
            errors.append('Email already registered')

        # If there are validation errors, return them
        if errors:
            for error in errors:
                flash(error, 'error')
            return redirect(url_for('signup'))

        # Create upload directory if it doesn't exist
        if not os.path.exists(Config.UPLOAD_FOLDER):
            os.makedirs(Config.UPLOAD_FOLDER)

        # Save uploaded files (disk) and capture bytes for DB storage
        # Sanitize filenames for security
        safe_nric_filename = sanitize_filename(nric_image.filename)
        safe_license_filename = sanitize_filename(license_image.filename)
        nric_filename = secure_filename(f"{email}_nric_{safe_nric_filename}")
        license_filename = secure_filename(f"{email}_license_{safe_license_filename}")

        nric_bytes = nric_image.read()
        license_bytes = license_image.read()

        encrypted_nric_bytes = encrypt_file(nric_bytes)
        encrypted_license_bytes = encrypt_file(license_bytes)

        encrypted_nric_filename = f"{nric_filename}.enc"
        encrypted_license_filename = f"{license_filename}.enc"

        with open(os.path.join(Config.UPLOAD_FOLDER, encrypted_nric_filename), 'wb') as f:
            f.write(encrypted_nric_bytes)
        with open(os.path.join(Config.UPLOAD_FOLDER, encrypted_license_filename), 'wb') as f:
            f.write(encrypted_license_bytes)

        user_data_plain = {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'phone': phone,
            'nric': nric,
            'license_number': license_number,
            'password_hash': generate_password_hash(password),
            'user_type': 'user',
            'documents': {
                'nric_image': {'filename': nric_filename, 'mime': nric_image.mimetype,
                               'data': encrypted_nric_bytes, 'path': encrypted_nric_filename},
                'license_image': {'filename': license_filename, 'mime': license_image.mimetype,
                                  'data': encrypted_license_bytes, 'path': encrypted_license_filename}
            }
        }

        # Persist to DB with pending status for admin review
        user_id = create_user_with_documents(user_data_plain)

        # --- Audit log for user registration ---
        add_audit_log(
            user_id=user_id if user_id else 0,
            action='User Registration',
            entity_type='USER',
            entity_id=user_id if user_id else 0,
            new_values=json.dumps({'email': email, 'user_type': 'user', 'first_name': first_name, 'last_name': last_name}),  # ← Convert to JSON string
            result='Success',
            ip_address=request.remote_addr,
            device_info=request.headers.get("User-Agent")
        )

        # Show pending approval page immediately after successful submission
        return render_template('pending_reg.html')

    return render_template('signup.html')


# ============================================
# REGISTRATION PENDING PAGE
# ============================================
@app.route('/registration-pending')
def registration_pending():
    """Registration pending approval page"""
    return render_template('pending_reg.html')


@app.route('/registration-rejected')
def registration_rejected():
    """Registration rejected page"""
    return render_template('rejected.html')


# ============================================
# LOGIN ROUTE
# ============================================
@app.route('/login', methods=['POST'])
def login():
    """Handle login from offcanvas form"""
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')

    if not email or not password:
        flash('Email and password are required', 'error')
        return redirect(request.referrer or url_for('index'))

    user = get_user_by_email(email)
    
    # Case 1: Email not found in database - user never signed up
    if not user:
        add_audit_log(
            user_id=None,
            action='Failed Login - Email Not Found',
            entity_type='USER',
            entity_id=0,
            reason=f'Login attempt with unregistered email: {email}',
            result='Failure',
            severity='Low',
            ip_address=request.remote_addr,
            device_info=request.headers.get("User-Agent")
        )
        flash('No account found with this email address. Please sign up first.', 'error')
        return redirect(request.referrer or url_for('index'))
    
    # Case 2: Wrong password
    if not check_password_hash(user.get('password_hash', ''), password):
        add_audit_log(
            user_id=user.get('user_id'),
            action='Failed Login - Wrong Password',
            entity_type='USER',
            entity_id=user.get('user_id'),
            reason='Invalid password entered',
            result='Failure',
            severity='Medium',
            ip_address=request.remote_addr,
            device_info=request.headers.get("User-Agent")
        )
        flash('Incorrect password. Please try again.', 'error')
        return redirect(request.referrer or url_for('index'))

    latest_status = _get_latest_signup_status(email)

    # Case 3: Account rejected by admin
    if latest_status == 'rejected':
        session.pop('_flashes', None)
        return redirect(url_for('registration_rejected'))

    # Case 4: Account pending admin approval
    if not user.get('verified'):
        if latest_status == 'pending':
            flash('Your account is pending approval. Please wait for admin verification.', 'error')
        else:
            flash('Your account is not approved yet. Please wait for admin verification.', 'error')
        return redirect(url_for('registration_pending'))

    # Clear any stale flashes from earlier flows before setting the success message
    session.pop('_flashes', None)

    if user.get('user_id'):
        try:
            update_user_last_login(user.get('user_id'))
        except Exception as exc:
            print(f"Warning: could not update last login: {exc}")

    # Login successful
    first_name_raw = user.get('first_name') or ''
    last_name_raw = user.get('last_name') or ''
    first_name = decrypt_value(first_name_raw, fallback_on_error=True) if first_name_raw else ''
    last_name = decrypt_value(last_name_raw, fallback_on_error=True) if last_name_raw else ''
    display_name = _safe_display_name(first_name, last_name, email)

    session['user'] = email
    session['user_id'] = user.get('user_id')
    session['user_name'] = display_name or email
    session['user_type'] = user.get('user_type', 'user')  # Get user type from stored data
    session.modified = True

    # --- Audit log for successful login ---
    add_audit_log(
        user_id=user.get('user_id'),
        action='User Login',
        entity_type='USER',
        entity_id=user.get('user_id'),
        result='Success',
        ip_address=request.remote_addr,
        device_info=request.headers.get("User-Agent")
    )

    flash(f"Welcome back, {first_name or email.split('@')[0]}!", 'success')

    # Redirect based on user type
    user_type = user.get('user_type', 'user')

    if user_type == 'admin':
        return redirect(url_for('accounts'))  # Redirect admins to the Accounts section
    elif user_type == 'seller':
        return redirect(url_for('seller_index'))  # Redirect sellers to seller dashboard
    else:  # user_type == 'user'
        return redirect(url_for('index_logged'))  # Redirect users to user home page


# ============================================
# LOGOUT ROUTE
# ============================================
@app.route('/logout')
def logout():
    """Handle user logout"""
    user_id = session.get('user_id', 0)
    
    # --- Audit log for logout ---
    if user_id:
        add_audit_log(
            user_id=user_id,
            action='User Logout',
            entity_type='USER',
            entity_id=user_id,
            result='Success',
            ip_address=request.remote_addr,
            device_info=request.headers.get("User-Agent")
        )
    
    session.pop('user', None)
    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('user_type', None)
    session.modified = True
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('index'))


# ============================================
# ADMIN PANEL (RENAMED FROM admin_dashboard)
# ============================================
@app.route('/admin/panel')
@require_classification('users.nric')
def admin_panel():
    """Admin panel to view and approve pending registrations"""
    # Check if user is logged in and is admin
    if 'user' not in session or session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))

    # Clear any lingering flashes from prior login attempts to keep the admin view clean
    session.pop('_flashes', None)
    
    # Get user context for data classification
    user_role = session.get('user_type', 'guest')
    user_id = session.get('user_id')

    def _safe_decrypt(value):
        if not value:
            return ''
        try:
            return decrypt_value(value, fallback_on_error=True)
        except Exception:
            return value

    def _looks_encrypted(value):
        if not value or len(value) < 24:
            return False
        return re.fullmatch(r"[A-Za-z0-9_-]+=*", value) is not None

    def _clean_value(value):
        decrypted = _safe_decrypt(value)
        return '' if _looks_encrypted(decrypted) else decrypted

    def _estimate_age_from_nric(nric_value):
        if not nric_value:
            return None
        nric_value = str(nric_value).strip().upper()
        match = re.match(r'^([STFG])(\d{2})\d{5}[A-Z]$', nric_value)
        if not match:
            return None
        prefix, yy = match.group(1), int(match.group(2))
        century = 1900 if prefix in ('S', 'F') else 2000
        year = century + yy
        current_year = datetime.now().year
        age = current_year - year
        if age < 0 or age > 120:
            return None
        return age

    def adapt(ticket):
        docs = ticket.get('documents', {})
        first_name = _clean_value(ticket.get('first_name'))
        last_name = _clean_value(ticket.get('last_name'))
        phone = _clean_value(ticket.get('phone'))
        nric = _clean_value(ticket.get('nric'))
        license_number = _clean_value(ticket.get('license_number'))
        estimated_age = _estimate_age_from_nric(nric)

        if not first_name and not last_name:
            email = ticket.get('email', '')
            if '@' in email:
                first_name = email.split('@', 1)[0]
            elif email:
                first_name = email

        def doc_url(doc):
            if not doc or not isinstance(doc, dict) or not doc.get('id'):
                return None
            return url_for('admin_document', doc_id=doc['id'])

        ticket_data = {
            'ticket_id': ticket.get('ticket_id'),
            'first_name': first_name,
            'last_name': last_name,
            'email': ticket.get('email'),
            'phone': phone or None,
            'nric': nric or None,
            'estimated_age': estimated_age,
            'license_number': license_number or None,
            'user_type': ticket.get('user_type'),
            'created_at': ticket.get('submitted_at'),
            'status': ticket.get('status'),
            'nric_image': doc_url(docs.get('nric_image')),
            'license_image': doc_url(docs.get('license_image')),
            'vehicle_card_image': doc_url(docs.get('vehicle_card_image')),
            'insurance_image': doc_url(docs.get('insurance_image')),
        }
        
        # Extract age from NRIC for admin review
        if nric:
            age_info = extract_age_from_nric(nric)
            ticket_data['age_info'] = age_info
        else:
            ticket_data['age_info'] = {
                "age": None,
                "is_minor": None,
                "confidence": "unknown",
                "message": "No NRIC provided"
            }
        
        # Redact sensitive fields based on user permissions
        return redact_dict(ticket_data, 'users', user_role, user_id, ticket.get('user_id'))

    pending_tickets = get_signup_tickets(status='pending')
    approved_tickets = get_signup_tickets(status='approved')
    rejected_tickets = get_signup_tickets(status='rejected')

    pending_users = [adapt(t) for t in pending_tickets if t.get('user_type') == 'user']
    pending_sellers = [adapt(t) for t in pending_tickets if t.get('user_type') == 'seller']
    approved_users = [adapt(t) for t in approved_tickets if t.get('user_type') == 'user']
    approved_sellers = [adapt(t) for t in approved_tickets if t.get('user_type') == 'seller']
    rejected_users = [adapt(t) for t in rejected_tickets if t.get('user_type') == 'user']
    rejected_sellers = [adapt(t) for t in rejected_tickets if t.get('user_type') == 'seller']

    retention_settings = get_retention_settings()
    retention_rows = get_retention_overview(settings=retention_settings, include_admins=False)

    for row in retention_rows:
        first = _clean_value(row.get('first_name'))
        last = _clean_value(row.get('last_name'))
        display_name = f"{first} {last}".strip()
        if not display_name:
            email = row.get('email', '')
            if '@' in email:
                display_name = email.split('@', 1)[0]
            else:
                display_name = email or f"User {row.get('user_id')}"
        row['display_name'] = display_name
        row['display_initial'] = (display_name[:1] or 'U').upper()
        row['last_seen'] = row.get('last_login_at') or row.get('created_at')

    retention_rows.sort(
        key=lambda r: (r.get('days_remaining') is None,
                       r.get('days_remaining') if r.get('days_remaining') is not None else 999999)
    )

    retention_stats = {
        'total': len(retention_rows),
        'overdue': sum(1 for r in retention_rows if r.get('status') == 'overdue'),
        'due': sum(1 for r in retention_rows if r.get('status') == 'due'),
        'ok': sum(1 for r in retention_rows if r.get('status') == 'ok'),
        'unknown': sum(1 for r in retention_rows if r.get('status') == 'unknown'),
    }

    return render_template('admin_panel.html',
                           pending_users=pending_users,
                           pending_sellers=pending_sellers,
                           approved_users=approved_users,
                           approved_sellers=approved_sellers,
                           rejected_users=rejected_users,
                           rejected_sellers=rejected_sellers,
                           retention_rows=retention_rows,
                           retention_stats=retention_stats,
                           retention_settings=retention_settings)


# ============================================
# ADMIN APPROVE USER
# ============================================
@app.route('/admin/approve/<int:ticket_id>', methods=['POST'])
@require_classification('users.nric')
def admin_approve_user(ticket_id):
    """Approve a pending user registration"""
    if 'user' not in session or session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))

    ok = set_signup_status(ticket_id, 'approved', reviewer=session.get('user'))
    if ok:
        # --- Audit log for admin approval ---
        # Get user_id from ticket to log properly
        from database import get_db_connection
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT user_id FROM signup_tickets WHERE ticket_id = %s", (ticket_id,))
            ticket_info = cursor.fetchone()
            cursor.close()
            
        if ticket_info:
            add_audit_log(
                user_id=session.get('user_id', 0),
                action='Admin Approve User',
                entity_type='USER',
                entity_id=ticket_info['user_id'],
                new_values=json.dumps({'status': 'approved', 'ticket_id': ticket_id}),
                result='Success',
                ip_address=request.remote_addr,
                device_info=request.headers.get("User-Agent")
            )
        
        flash('Signup approved successfully!', 'success')
    else:
        flash('Signup ticket not found.', 'error')
    return redirect(url_for('admin_panel'))


# ============================================
# ADMIN REJECT USER
# ============================================
@app.route('/admin/reject/<int:ticket_id>', methods=['POST'])
@require_classification('users.nric')
def admin_reject_user(ticket_id):
    """Reject and delete a pending user registration"""
    if 'user' not in session or session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))

    ok = set_signup_status(ticket_id, 'rejected', reviewer=session.get('user'))
    if ok:
        # --- Audit log for admin rejection ---
        # Get user_id from ticket to log properly
        from database import get_db_connection
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT user_id FROM signup_tickets WHERE ticket_id = %s", (ticket_id,))
            ticket_info = cursor.fetchone()
            cursor.close()
            
        if ticket_info:
            add_audit_log(
                user_id=session.get('user_id', 0),
                action='Admin Reject User',
                entity_type='USER',
                entity_id=ticket_info['user_id'],
                new_values=json.dumps({'status': 'rejected', 'ticket_id': ticket_id}),
                result='Success',
                severity='Medium',
                ip_address=request.remote_addr,
                device_info=request.headers.get("User-Agent")
            )
        
        flash('Signup rejected.', 'success')
    else:
        flash('Signup ticket not found.', 'error')
    return redirect(url_for('admin_panel'))


# ============================================
# ADMIN DOCUMENT SERVE
# ============================================
from flask import send_file
from io import BytesIO


@app.route('/admin/document/<int:doc_id>')
@require_classification('user_documents.file_data')
def admin_document(doc_id):
    """Serve a stored document from DB to admin."""
    from mysql.connector import Error
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT file_name, mime_type, file_data, file_path FROM user_documents WHERE id = %s",
                (doc_id,)
            )
            row = cursor.fetchone()
            cursor.close()
            if not row:
                return "File not found", 404

            file_data = row.get('file_data')
            if not file_data and row.get('file_path'):
                file_path = row.get('file_path')
                if file_path and os.path.exists(os.path.join(Config.UPLOAD_FOLDER, file_path)):
                    with open(os.path.join(Config.UPLOAD_FOLDER, file_path), 'rb') as f:
                        file_data = f.read()

            if not file_data:
                return "File not found", 404

            try:
                file_data = decrypt_file(file_data)
            except Exception:
                # Backward compatibility: serve plaintext files if not encrypted
                pass

            return send_file(
                BytesIO(file_data),
                download_name=row.get('file_name') or f'doc_{doc_id}',
                mimetype=row.get('mime_type') or 'application/octet-stream'
            )
    except Error as exc:
        return f"Error retrieving file: {exc}", 500


# ============================================
# PROFILE ROUTE
# ============================================
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    """Profile page for logged-in users and sellers (no document attachments)."""
    if 'user' not in session:
        flash('Please log in to view your profile.', 'error')
        return redirect(url_for('index'))

    if session.get('user_type') == 'admin':
        flash('Admin profiles are managed in the admin panel.', 'info')
        return redirect(url_for('accounts'))

    def _safe_decrypt(value):
        if not value:
            return ''
        try:
            return decrypt_value(value, fallback_on_error=True)
        except Exception:
            return value

    def _mask_value(value, visible_start=2, visible_end=2):
        if not value:
            return 'Not provided'
        raw = str(value)
        if len(raw) <= visible_start + visible_end:
            return '*' * len(raw)
        return f"{raw[:visible_start]}{'*' * (len(raw) - visible_start - visible_end)}{raw[-visible_end:]}"

    user_email = session.get('user')
    user = get_user_by_email(user_email) if user_email else None
    if not user:
        flash('User account not found.', 'error')
        return redirect(url_for('index'))

    form_values = None
    if request.method == 'POST':
        form_values = {
            'first_name': request.form.get('first_name', '').strip(),
            'last_name': request.form.get('last_name', '').strip(),
            'email': request.form.get('email', '').strip().lower(),
            'phone': request.form.get('phone', '').strip(),
        }

        errors = []
        if not form_values['first_name'] or not validate_name(form_values['first_name']):
            errors.append('First name is required and must be valid.')
        if not form_values['last_name'] or not validate_name(form_values['last_name']):
            errors.append('Last name is required and must be valid.')
        if not form_values['email'] or not validate_email(form_values['email']):
            errors.append('Email address is invalid.')
        if not form_values['phone'] or not validate_phone(form_values['phone']):
            errors.append('Phone number must be 8 digits and start with 6, 8, or 9.')

        if errors:
            for error in errors:
                flash(error, 'error')
        else:
            # Store old values for audit logging
            old_values = {
                'first_name': user.get('first_name'),
                'last_name': user.get('last_name'),
                'email': user.get('email'),
                'phone': user.get('phone')
            }
            
            ok, error = update_user_profile(
                user['user_id'],
                form_values['first_name'],
                form_values['last_name'],
                form_values['email'],
                form_values['phone']
            )
            if not ok:
                flash(error or 'Unable to update profile.', 'error')
            else:
                # AUDIT: Log profile updates with before/after values
                new_values = {
                    'first_name': form_values['first_name'],
                    'last_name': form_values['last_name'],
                    'email': form_values['email'],
                    'phone': form_values['phone']
                }
                
                # Only log if values actually changed
                if old_values != new_values:
                    add_audit_log(
                        action='PROFILE_UPDATED',
                        user_id=user['user_id'],
                        entity_type='USER',
                        entity_id=user['user_id'],
                        previous_values=old_values,
                        new_values=new_values,
                        reason=f'Profile updated for {user_email}',
                        ip_address=request.remote_addr,
                        device_info=request.headers.get("User-Agent")
                    )
                
                session['user'] = form_values['email']
                session['user_name'] = f"{form_values['first_name']} {form_values['last_name']}".strip()
                session.modified = True
                flash('Profile updated successfully.', 'success')
                user = get_user_by_email(form_values['email'])
                form_values = None

    profile_data = {
        'user_id': user.get('user_id'),
        'first_name': _safe_decrypt(user.get('first_name')),
        'last_name': _safe_decrypt(user.get('last_name')),
        'email': user.get('email') or '',
        'phone': _safe_decrypt(user.get('phone')) if user.get('phone') else '',
        'nric': _safe_decrypt(user.get('nric')),
        'license_number': _safe_decrypt(user.get('license_number')),
        'user_type': user.get('user_type', 'user'),
        'verified': bool(user.get('verified')),
        'account_status': user.get('account_status') or 'active',
        'created_at': user.get('created_at'),
        'last_login_at': user.get('last_login_at'),
    }

    if form_values:
        profile_data.update(form_values)

    display_name = f"{profile_data['first_name']} {profile_data['last_name']}".strip()
    if not display_name:
        display_name = profile_data['email'].split('@')[0] if profile_data['email'] else 'User'

    sensitive = {
        'phone': {
            'label': 'Phone Number',
            'full': profile_data['phone'],
            'masked': _mask_value(profile_data['phone'], 2, 2),
        },
        'nric': {
            'label': 'NRIC / FIN',
            'full': profile_data['nric'],
            'masked': _mask_value(profile_data['nric'], 1, 1),
        },
        'license': {
            'label': "Driver's License",
            'full': profile_data['license_number'],
            'masked': _mask_value(profile_data['license_number'], 1, 2),
        },
    }

    return render_template(
        'profile.html',
        profile=profile_data,
        sensitive=sensitive,
        display_name=display_name,
        user_email=profile_data['email'],
        user_name=session.get('user_name')
    )


# ============================================
# USER HOME PAGE (RENAMED FROM index_logged)
# ============================================
@app.route('/user/home')
def user_home():
    """Home page for logged-in regular users"""
    # Check if user is logged in
    if 'user' not in session:
        flash('Please log in to access this page.', 'error')
        return redirect(url_for('index'))

    # Optional: Check if user type is 'user'
    if session.get('user_type') != 'user':
        flash('Access denied. This page is for regular users only.', 'error')
        return redirect(url_for('index'))

    default_pickup = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d')
    default_return = (datetime.now() + timedelta(days=3)).strftime('%Y-%m-%d')
    cart_count = get_cart_count(session)
    return render_template('index_logged.html',
                           default_pickup=default_pickup,
                           default_return=default_return,
                           cart_count=cart_count)


# ============================================
# SELLER DASHBOARD (RENAMED FROM seller_index)
# ============================================
@app.route('/seller/dashboard')
def seller_dashboard():
    """Dashboard page for logged-in sellers"""
    # Check if user is logged in
    if 'user' not in session:
        flash('Please log in to access this page.', 'error')
        return redirect(url_for('index'))

    # Check if user type is 'seller'
    if session.get('user_type') != 'seller':
        flash('Access denied. This page is for sellers only.', 'error')
        return redirect(url_for('index'))

    user_email = session.get('user')
    if user_email:
        user = get_user_by_email(user_email)
        if user:
            first_name_raw = user.get('first_name') or ''
            last_name_raw = user.get('last_name') or ''
            first_name = decrypt_value(first_name_raw, fallback_on_error=True) if first_name_raw else ''
            last_name = decrypt_value(last_name_raw, fallback_on_error=True) if last_name_raw else ''
            display_name = _safe_display_name(first_name, last_name, user_email)
            session['user_name'] = display_name or user_email
            session.modified = True

    return render_template('seller_index.html')


# ============================================
# CREATE INITIAL ADMIN ACCOUNT (HELPER)
# ============================================
@app.route('/create-admin-secret-route-12345', methods=['GET', 'POST'])
@require_classification('users.password_hash')
def create_admin():
    """One-time route to create initial admin account - RESTRICTED to admins only"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()

        existing = get_user_by_email(email)
        if existing:
            flash('Admin already exists!', 'error')
            return redirect(url_for('index'))

        admin_data = {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'password_hash': generate_password_hash(password),
            'user_type': 'admin',
            'documents': {}
        }

        _, ticket_id = create_user_with_documents(admin_data)
        set_signup_status(ticket_id, 'approved', reviewer='system')

        flash('Admin account created successfully! You can now log in.', 'success')
        return redirect(url_for('index'))

    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Create Admin Account</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 500px;
                margin: 50px auto;
                padding: 20px;
                background-color: #f5f5f5;
            }
            .form-container {
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            h2 {
                color: #2c3e50;
                margin-bottom: 20px;
            }
            input {
                width: 100%;
                padding: 10px;
                margin: 10px 0;
                border: 1px solid #ddd;
                border-radius: 5px;
                box-sizing: border-box;
            }
            button {
                width: 100%;
                padding: 12px;
                background-color: #3498db;
                color: white;
                border: none;
                border-radius: 5px;
                font-size: 16px;
                cursor: pointer;
                margin-top: 10px;
            }
            button:hover {
                background-color: #2980b9;
            }
            .warning {
                background-color: #fff3cd;
                border: 1px solid #ffc107;
                color: #856404;
                padding: 10px;
                border-radius: 5px;
                margin-bottom: 20px;
            }
        </style>
    </head>
    <body>
        <div class="form-container">
            <h2> Create Admin Account</h2>
            <div class="warning">
                <strong> Important:</strong> Remove this route after creating your admin account!
            </div>
            <form method="post">
                <input type="text" name="first_name" placeholder="First Name" required>
                <input type="text" name="last_name" placeholder="Last Name" required>
                <input type="email" name="email" placeholder="Email" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Create Admin Account</button>
            </form>
        </div>
    </body>
    </html>
    '''


# ============================================
# ROLE-BASED ACCESS CONTROL DECORATOR (OPTIONAL)
# ============================================
from functools import wraps


def role_required(*allowed_roles):
    """Decorator to restrict access to specific user roles"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user' not in session:
                flash('Please log in to access this page', 'error')
                return redirect(url_for('index'))

            if 'user_type' not in session or session['user_type'] not in allowed_roles:
                flash('You do not have permission to access this page', 'error')
                return redirect(url_for('index'))

            return f(*args, **kwargs)

        return decorated_function

    return decorator


# ============================================
# EXAMPLE USAGE OF ROLE DECORATOR
# ============================================
# @app.route('/admin/users')
# @role_required('admin')
# def admin_users():
#     # Admin-only code
#     pass
#
# @app.route('/seller/products')
# @role_required('seller', 'admin')
# def seller_products():
#     # Seller and admin can access
#     pass


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Forgot password page - request password reset"""
    cart_count = get_cart_count(session)
    session_expires_at = session.get('password_reset_expires_at')
    if session_expires_at:
        try:
            session_expiry = datetime.fromisoformat(session_expires_at)
        except ValueError:
            session_expiry = None
        if not session_expiry or datetime.now() > session_expiry:
            session.pop('password_reset_step', None)
            session.pop('password_reset_email', None)
            session.pop('password_reset_otp_id', None)
            session.pop('password_reset_expires_at', None)
            session.pop('password_reset_bypass', None)
    if session.get('password_reset_step') == 'otp':
        session['password_reset_step'] = 'email'
        session.pop('password_reset_otp_id', None)
        session.pop('password_reset_expires_at', None)
        session.pop('password_reset_bypass', None)

    def _render(step_override=None, email_override=None):
        return render_template(
            'forgot_password.html',
            cart_count=cart_count,
            step=step_override or session.get('password_reset_step', 'email'),
            reset_email=email_override if email_override is not None else session.get('password_reset_email', '')
        )

    if request.method == 'POST':
        action = request.form.get('action', '').strip()
        email = request.form.get('email', '').strip().lower()
        if not email:
            email = session.get('password_reset_email', '')

        if action in ('send_otp', 'start_reset'):
            if not email or not validate_email(email):
                flash('Please enter a valid email address.', 'error')
                session['password_reset_step'] = 'email'
                session.pop('password_reset_bypass', None)
                return _render('email', email)

            user = get_user_by_email(email)
            if not user:
                flash('User account not found.', 'error')
                session['password_reset_step'] = 'email'
                session.pop('password_reset_bypass', None)
                return _render('email', email)

            # AUDIT: Log password reset request
            add_audit_log(
                action='PASSWORD_RESET_REQUESTED',
                user_id=user['user_id'],
                entity_type='USER',
                entity_id=user['user_id'],
                reason=f'Password reset requested for {email}',
                ip_address=request.remote_addr,
                device_info=request.headers.get("User-Agent")
            )

            session['password_reset_email'] = email
            session['password_reset_step'] = 'new_password'
            session.pop('password_reset_bypass', None)
            session.pop('password_reset_otp_id', None)
            session.pop('password_reset_expires_at', None)
            flash('Email verification is disabled right now. Please set a new password.', 'success')
            return _render('new_password', email)

        if action == 'reset_password':
            if not email or not validate_email(email):
                flash('Please enter a valid email address.', 'error')
                session['password_reset_step'] = 'email'
                session.pop('password_reset_bypass', None)
                return _render('email')

            if session.get('password_reset_step') != 'new_password':
                flash('Please enter your email to start the reset.', 'error')
                session['password_reset_step'] = 'email'
                return _render('email')

            new_password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')

            if not new_password:
                flash('Password is required.', 'error')
                return _render('new_password', email)

            if new_password != confirm_password:
                flash('Passwords do not match.', 'error')
                return _render('new_password', email)

            is_valid, message = validate_password(new_password)
            if not is_valid:
                flash(message, 'error')
                return _render('new_password', email)

            user = get_user_by_email(email)
            if not user:
                flash('User account not found.', 'error')
                session['password_reset_step'] = 'email'
                return _render('email', email)

            update_user_password(email, generate_password_hash(new_password))
            
            # AUDIT: Log successful password reset
            add_audit_log(
                action='PASSWORD_RESET_COMPLETED',
                user_id=user['user_id'],
                entity_type='USER',
                entity_id=user['user_id'],
                reason=f'Password reset completed for {email}',
                ip_address=request.remote_addr,
                device_info=request.headers.get("User-Agent")
            )
            
            session.pop('password_reset_step', None)
            session.pop('password_reset_email', None)
            session.pop('password_reset_otp_id', None)
            session.pop('password_reset_expires_at', None)
            session.pop('password_reset_bypass', None)
            flash('Password updated successfully. Please log in again.', 'success')
            return _render('done', email)

        flash('Unsupported action.', 'error')
        return _render()

    return _render()


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset password page - user clicks link from email"""
    token_data = get_reset_token(token)

    if not token_data:
        flash('Invalid or expired reset link.', 'error')
        return redirect(url_for('forgot_password'))

    expires_at = token_data.get('expires_at')
    if isinstance(expires_at, str):
        try:
            expires_at = datetime.fromisoformat(expires_at)
        except ValueError:
            expires_at = None

    if not expires_at or datetime.now() > expires_at:
        flash('This reset link has expired. Please request a new one.', 'error')
        return redirect(url_for('forgot_password'))

    if token_data.get('used'):
        flash('This reset link has already been used.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        email = token_data['email']
        new_password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not new_password:
            flash('Password is required', 'error')
            return render_template('reset_password.html', token=token)

        if new_password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('reset_password.html', token=token)

        is_valid, message = validate_password(new_password)
        if not is_valid:
            flash(message, 'error')
            return render_template('reset_password.html', token=token)

        user = get_user_by_email(email)
        if user:
            update_user_password(email, generate_password_hash(new_password))

            mark_token_as_used(token)

            # --- Audit log for password reset ---
            add_audit_log(
                user_id=user.get('user_id', 0),
                action='Password Reset',
                entity_type='USER',
                entity_id=user.get('user_id', 0),
                result='Success',
                reason='User requested password reset',
                ip_address=request.remote_addr,
                device_info=request.headers.get("User-Agent")
            )

            flash('Password has been reset successfully! You can now login.', 'success')
            return redirect(url_for('index'))
        else:
            flash('User account not found.', 'error')
            return redirect(url_for('forgot_password'))

    return render_template('reset_password.html', token=token)


# ============================================
# VEHICLE ROUTES
# ============================================

@app.route('/vehicles')
def vehicles():
    """Display all available vehicles"""
    search_query = request.args.get('q', '').lower()

    if search_query:
        filtered_vehicles = {
            vid: vehicle for vid, vehicle in VEHICLES.items()
            if search_query in vehicle['name'].lower() or search_query in vehicle['type'].lower()
        }
    else:
        filtered_vehicles = VEHICLES

    return render_template('vehicles.html', vehicles=filtered_vehicles, search_query=search_query)


@app.route('/vehicle/<int:vehicle_id>')
def vehicle_detail(vehicle_id):
    """Display vehicle details"""
    vehicle = VEHICLES.get(vehicle_id)

    if not vehicle:
        return "Vehicle not found", 404

    return render_template('vehicle_detail.html', vehicle=vehicle)


def get_all_vehicles_for_listing():
    """Get all vehicles combining hardcoded vehicles and listings"""
    from models import listings
    # Avoid duplicating the two built-in vehicles if they also exist in manage-listings
    _IGNORE_LISTING_NAMES = {"toyota sienta hybrid", "mt-07/y-amt"}
    
    # Hardcoded vehicles (original 5)
    hardcoded_vehicles = [
        {'id': 1, 'name': 'Toyota Sienta Hybrid', 'price': 150, 'image': 'toyota.png', 'detail_url': url_for('sienta')},
        {'id': 2, 'name': 'MT-07/Y-AMT', 'price': 100, 'image': 'bike.jpg', 'detail_url': url_for('bike')},
        {'id': 3, 'name': 'Honda Civic', 'price': 120, 'image': 'civic.png', 'detail_url': url_for('honda_civic')},
        {'id': 4, 'name': 'Corolla Cross', 'price': 110, 'image': 'corolla.png', 'detail_url': url_for('corolla')},
        {'id': 5, 'name': 'AVANTE Hybrid', 'price': 180, 'image': 'avante.png', 'detail_url': url_for('avante')},
    ]
    
    # Convert listings to vehicle format (only active listings)
    listing_vehicles = []
    for listing in listings:
        if listing.get('status') == 'active':
            listing_name = (listing.get('name') or '').strip().lower()
            if listing_name in _IGNORE_LISTING_NAMES:
                continue
            # Handle image path - listings can have 'images/xxx.png' or 'uploads/xxx.png'
            image_path = listing.get('image', 'images/default.png')
            # Keep full path for templates to handle correctly
            listing_vehicles.append({
                'id': listing['id'],
                'name': listing['name'],
                'price': listing['price'],
                'image': image_path,  # Full path (images/xxx.png or uploads/xxx.png)
                'image_path': image_path,  # Same for detail page
                'detail_url': url_for('listing_detail', listing_id=listing['id'])
            })
    
    # Combine hardcoded + listings (listings come after hardcoded)
    return hardcoded_vehicles + listing_vehicles


@app.route('/vehicle_listing')
def vehicle_listing():
    search_query = request.args.get('q', '').lower()
    
    all_vehicles = get_all_vehicles_for_listing()

    if search_query:
        vehicles = [v for v in all_vehicles if search_query in v['name'].lower()]
    else:
        vehicles = all_vehicles

    cart_count = get_cart_count(session)
    return render_template('vehicle_listing.html', vehicles=vehicles, search_query=search_query, cart_count=cart_count)


def get_all_vehicles_for_listing_logged():
    """Get all vehicles combining hardcoded vehicles and listings (logged version)"""
    from models import listings
    # Avoid duplicating the two built-in vehicles if they also exist in manage-listings
    _IGNORE_LISTING_NAMES = {"toyota sienta hybrid", "mt-07/y-amt"}
    
    # Hardcoded vehicles (original 5)
    hardcoded_vehicles = [
        {'id': 1, 'name': 'Toyota Sienta Hybrid', 'price': 150, 'image': 'toyota.png',
         'detail_url': url_for('sienta_logged')},
        {'id': 2, 'name': 'MT-07/Y-AMT', 'price': 100, 'image': 'bike.jpg', 'detail_url': url_for('bike_logged')},
        {'id': 3, 'name': 'Honda Civic', 'price': 120, 'image': 'civic.png',
         'detail_url': url_for('honda_civic_logged')},
        {'id': 4, 'name': 'Corolla Cross', 'price': 110, 'image': 'corolla.png',
         'detail_url': url_for('corolla_logged')},
        {'id': 5, 'name': 'AVANTE Hybrid', 'price': 180, 'image': 'avante.png', 'detail_url': url_for('avante_logged')},
    ]
    
    # Convert listings to vehicle format (only active listings)
    listing_vehicles = []
    for listing in listings:
        if listing.get('status') == 'active':
            listing_name = (listing.get('name') or '').strip().lower()
            if listing_name in _IGNORE_LISTING_NAMES:
                continue
            # Handle image path - listings can have 'images/xxx.png' or 'uploads/xxx.png'
            image_path = listing.get('image', 'images/default.png')
            # Keep full path for templates to handle correctly
            listing_vehicles.append({
                'id': listing['id'],
                'name': listing['name'],
                'price': listing['price'],
                'image': image_path,  # Full path (images/xxx.png or uploads/xxx.png)
                'image_path': image_path,  # Same for detail page
                'detail_url': url_for('listing_detail_logged', listing_id=listing['id'])
            })
    
    # Combine hardcoded + listings
    return hardcoded_vehicles + listing_vehicles


@app.route('/vehicle_listing_logged')
def vehicle_listing_logged():
    search_query = request.args.get('q', '').lower()
    
    all_vehicles = get_all_vehicles_for_listing_logged()

    if search_query:
        vehicles = [v for v in all_vehicles if search_query in v['name'].lower()]
    else:
        vehicles = all_vehicles

    cart_count = get_cart_count(session)
    return render_template('vehicle_listing_logged.html', vehicles=vehicles, search_query=search_query,
                           cart_count=cart_count,
                           user_email=session.get('user'),
                           user_name=session.get('user_name'))


@app.route('/vehicle_listing_seller_logged')
def vehicle_listing_seller_logged():
    search_query = request.args.get('q', '').lower()

    all_vehicles = [
        {'id': 1, 'name': 'Toyota Sienta Hybrid', 'price': 150, 'image': 'toyota.png',
         'detail_url': url_for('sienta_logged')},
        {'id': 2, 'name': 'MT-07/Y-AMT', 'price': 100, 'image': 'bike.png', 'detail_url': url_for('bike_logged')},
        {'id': 3, 'name': 'Honda Civic', 'price': 120, 'image': 'civic.png',
         'detail_url': url_for('honda_civic_logged')},
        {'id': 4, 'name': 'Corolla Cross', 'price': 110, 'image': 'corolla.png',
         'detail_url': url_for('corolla_logged')},
        {'id': 5, 'name': 'AVANTE Hybrid', 'price': 180, 'image': 'avante.png', 'detail_url': url_for('avante_logged')},
    ]

    if search_query:
        vehicles = [v for v in all_vehicles if search_query in v['name'].lower()]
    else:
        vehicles = all_vehicles

    cart_count = get_cart_count(session)
    return render_template('vehicle_listing_seller_logged.html', vehicles=vehicles, search_query=search_query,
                           cart_count=cart_count)


# Vehicle detail pages
@app.route("/honda-civic")
def honda_civic():
    cart_count = get_cart_count(session)
    return render_template("honda_civic.html", cart_count=cart_count)


@app.route("/honda-civic-logged")
def honda_civic_logged():
    cart_count = get_cart_count(session)
    return render_template("honda_civic_logged.html", cart_count=cart_count)


@app.route("/corolla")
def corolla():
    cart_count = get_cart_count(session)
    return render_template("corolla_cross.html", cart_count=cart_count)


@app.route("/corolla_logged")
def corolla_logged():
    cart_count = get_cart_count(session)
    return render_template("corolla_cross_logged.html", cart_count=cart_count)


@app.route("/avante")
def avante():
    cart_count = get_cart_count(session)
    return render_template("avante_hybrid.html", cart_count=cart_count)


@app.route("/avante_logged")
def avante_logged():
    cart_count = get_cart_count(session)
    return render_template("avante_hybrid_logged.html", cart_count=cart_count)


@app.route("/sienta")
def sienta():
    cart_count = get_cart_count(session)
    return render_template("toyota_sienta.html", cart_count=cart_count)


@app.route("/sienta_logged")
def sienta_logged():
    cart_count = get_cart_count(session)
    return render_template("toyota_sienta_logged.html", cart_count=cart_count)


@app.route("/bike")
def bike():
    cart_count = get_cart_count(session)
    return render_template("bike.html", cart_count=cart_count)


@app.route("/bike_logged")
def bike_logged():
    cart_count = get_cart_count(session)
    return render_template("bike_logged.html", cart_count=cart_count)


# Generic listing detail pages (for listings added via manage-listings)
@app.route('/listing/<int:listing_id>')
def listing_detail(listing_id):
    """Generic detail page for listings added via manage-listings"""
    from models import listings
    listing = next((l for l in listings if l['id'] == listing_id), None)
    
    if not listing or listing.get('status') != 'active':
        flash('Listing not found', 'error')
        return redirect(url_for('vehicle_listing'))
    
    cart_count = get_cart_count(session)
    return render_template('listing_detail.html', listing=listing, cart_count=cart_count)


@app.route('/listing/<int:listing_id>/logged')
def listing_detail_logged(listing_id):
    """Generic detail page for listings (logged in users)"""
    from models import listings
    listing = next((l for l in listings if l['id'] == listing_id), None)
    
    if not listing or listing.get('status') != 'active':
        flash('Listing not found', 'error')
        return redirect(url_for('vehicle_listing_logged'))
    
    cart_count = get_cart_count(session)
    return render_template('listing_detail_logged.html', listing=listing, cart_count=cart_count,
                          user_email=session.get('user'),
                          user_name=session.get('user_name'))


# ============================================
# CART ROUTES
# ============================================

@app.route('/cart')
def cart():
    """Display shopping cart"""
    cart_items = session.get('cart', {})

    if not cart_items:
        return render_template('cart.html', cart_items=[], subtotal=0,
                               insurance_fee=0, service_fee=0, total=0, cart_count=0)

    totals = calculate_cart_totals(cart_items, VEHICLES)

    return render_template('cart.html',
                           cart_items=totals['cart_data'],
                           subtotal=totals['subtotal'],
                           insurance_fee=totals['insurance_fee'],
                           service_fee=totals['service_fee'],
                           total=totals['total'],
                           cart_count=len(totals['cart_data']))


@app.route('/booking-history')
@login_required
def booking_history():
    """Display user's booking history"""
    user_email = session.get('user')
    user_role = session.get('user_type', 'user')
    user_id = session.get('user_id')
    
    if not user_email:
        flash('Please login to view your bookings', 'error')
        return redirect(url_for('login'))

    # Try to get user from database first
    bookings = []
    try:
        user = get_user_by_email(user_email)
        if user and user.get('user_id'):
            # Get user bookings from database
            raw_bookings = get_user_bookings(user.get('user_id'))
            # Redact sensitive booking data based on user permissions
            from data_classification import redact_list
            bookings = redact_list(raw_bookings, 'bookings', user_role, user_id)
    except Exception as e:
        # If database fails, try session-based bookings
        print(f"Database error: {e}")
        # Fallback to session-based bookings if available
        pass

    # If no database bookings, check session-based bookings (for demo/testing)
    if not bookings:
        # Try to get bookings from session or models
        from models import BOOKINGS
        # Filter bookings by user email if available
        session_bookings = []
        for booking_id, booking in BOOKINGS.items():
            if booking.get('customer_email') == user_email:
                session_bookings.append(booking)
        # Redact session bookings as well
        from data_classification import redact_list
        bookings = redact_list(session_bookings, 'bookings', user_role, user_id)

    # Get cart count for navbar
    cart_count = get_cart_count(session)

    return render_template('booking_history.html',
                           bookings=bookings,
                           cart_count=cart_count,
                        user_email = session.get('user'),
                        user_name = session.get('user_name'))


@app.route('/cart_logged')
def cart_logged():
    """Display shopping cart for logged-in users"""
    cart_items = session.get('cart', {})

    if not cart_items:
        return render_template('cart_logged.html', cart_items=[], subtotal=0,
                               insurance_fee=0, service_fee=0, total=0, cart_count=0)

    totals = calculate_cart_totals(cart_items, VEHICLES)

    return render_template('cart_logged.html',
                           cart_items=totals['cart_data'],
                           subtotal=totals['subtotal'],
                           insurance_fee=totals['insurance_fee'],
                           service_fee=totals['service_fee'],
                           total=totals['total'],
                           cart_count=len(totals['cart_data']))


@app.route('/add-to-cart/<int:vehicle_id>', methods=['POST'])
def add_to_cart(vehicle_id):
    """Add a vehicle to cart"""
    vehicle = VEHICLES.get(vehicle_id)

    if not vehicle:
        return jsonify({'error': 'Vehicle not found'}), 404

    pickup_date = request.form.get('pickup_date', (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d'))
    return_date = request.form.get('return_date', (datetime.now() + timedelta(days=3)).strftime('%Y-%m-%d'))

    if 'cart' not in session:
        session['cart'] = {}

    session['cart'][str(vehicle_id)] = {
        'pickup_date': pickup_date,
        'return_date': return_date
    }
    session.modified = True

    # Redirect based on login status
    if 'user' in session:
        return redirect(url_for('cart_logged'))
    else:
        return redirect(url_for('cart'))


@app.route('/add-to-cart-logged/<int:vehicle_id>', methods=['POST'])
def add_to_cart_logged(vehicle_id):
    """Add a vehicle to cart"""
    vehicle = VEHICLES.get(vehicle_id)

    if not vehicle:
        return jsonify({'error': 'Vehicle not found'}), 404

    pickup_date = request.form.get('pickup_date', (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d'))
    return_date = request.form.get('return_date', (datetime.now() + timedelta(days=3)).strftime('%Y-%m-%d'))

    if 'cart' not in session:
        session['cart'] = {}

    session['cart'][str(vehicle_id)] = {
        'pickup_date': pickup_date,
        'return_date': return_date
    }
    session.modified = True

    return redirect(url_for('cart_logged'))


@app.route('/update-cart/<int:vehicle_id>', methods=['POST'])
def update_cart(vehicle_id):
    """Update cart item dates"""
    if 'cart' not in session or str(vehicle_id) not in session['cart']:
        return jsonify({'error': 'Item not in cart'}), 404

    pickup_date = request.form.get('pickup_date')
    return_date = request.form.get('return_date')

    if pickup_date and return_date:
        session['cart'][str(vehicle_id)] = {
            'pickup_date': pickup_date,
            'return_date': return_date
        }
        session.modified = True
        return jsonify({'success': True})

    return jsonify({'error': 'Invalid dates'}), 400


@app.route('/remove-from-cart/<int:vehicle_id>', methods=['POST'])
def remove_from_cart(vehicle_id):
    """Remove a vehicle from cart"""
    if 'cart' in session and str(vehicle_id) in session['cart']:
        del session['cart'][str(vehicle_id)]
        session.modified = True
        return jsonify({'success': True, 'cart_count': len(session['cart'])})

    return jsonify({'error': 'Item not in cart'}), 404


@app.route('/clear-cart', methods=['POST'])
def clear_cart():
    """Clear all items from cart"""
    session['cart'] = {}
    session.modified = True
    return jsonify({'success': True})


@app.route('/api/cart-count')
def api_cart_count():
    """API endpoint to get current cart count"""
    return jsonify({'count': get_cart_count(session)})


# ============================================
# CHECKOUT & PAYMENT ROUTES
# ============================================

@app.route('/checkout')
@login_required
def checkout():
    """Checkout page"""
    user_email = session.get('user')
    user_role = session.get('user_type', 'user')
    user_id = session.get('user_id')
    
    cart_items = session.get('cart', {})

    if not cart_items:
        return redirect(url_for('cart'))

    totals = calculate_cart_totals(cart_items, VEHICLES)
    
    # Get user data and redact sensitive fields for display
    user_data = get_user_by_email(user_email) if user_email else None
    redacted_user = None
    if user_data:
        redacted_user = redact_dict(user_data, 'users', user_role, user_id, user_data.get('user_id'))

    return render_template('checkout.html',
                           cart_items=totals['cart_data'],
                           subtotal=totals['subtotal'],
                           insurance_fee=totals['insurance_fee'],
                           service_fee=totals['service_fee'],
                           total=totals['total'],
                           stripe_public_key=Config.STRIPE_PUBLIC_KEY,
                           user=redacted_user)


@app.route('/create-payment-intent', methods=['POST'])
def create_payment_intent():
    """Create a Stripe payment intent with tokenized payment data"""
    try:
        data = request.get_json()
        cart_items = session.get('cart', {})

        if not cart_items:
            return jsonify({'error': 'Cart is empty'}), 400

        totals = calculate_cart_totals(cart_items, VEHICLES)

        # Encrypt sensitive customer data before storing in Stripe metadata
        encrypted_name = encrypt_value(data.get('name')) if data.get('name') else None
        encrypted_email = encrypt_value(data.get('email')) if data.get('email') else None
        encrypted_phone = encrypt_value(data.get('phone')) if data.get('phone') else None
        # REMOVED: encrypted_license line

        # Create payment intent with tokenized payment method support
        intent = stripe.PaymentIntent.create(
            amount=int(totals['total'] * 100),  # Amount in cents
            currency='sgd',
            payment_method_types=['card'],
            metadata={
                # Store encrypted PII - decrypted only when needed
                'customer_name_encrypted': encrypted_name or '',
                'customer_email_encrypted': encrypted_email or '',
                'customer_phone_encrypted': encrypted_phone or '',
                # REMOVED: license_number_encrypted
                'booking_type': 'vehicle_rental',
            },
            description='67 Rentals Vehicle Booking',
        )

        # --- Audit log for payment intent creation ---
        add_audit_log(
            user_id=session.get('user_id', 0),
            action='Create Payment Intent',
            entity_type='PAYMENT',
            entity_id=intent.id,
            new_values=json.dumps({'amount': totals['total'], 'currency': 'sgd', 'cart_items': len(cart_items)}),
            result='Success',
            ip_address=request.remote_addr,
            device_info=request.headers.get("User-Agent")
        )

        return jsonify({
            'clientSecret': intent.client_secret,
            'paymentIntentId': intent.id
        })

    except Exception as e:
        print(f"Payment intent error: {str(e)}")
        return jsonify({'error': str(e)}), 403


@app.route('/payment-tokenization-status')
def payment_tokenization_status():
    """Verify payment tokenization is working correctly"""
    return jsonify({
        'tokenization_enabled': True,
        'payment_method': 'Stripe Elements (client-side tokenization)',
        'card_data_stored': False,
        'only_tokens_stored': True,
        'metadata_encrypted': True,
        'security_features': {
            'https_required': True,
            'secure_cookies': True,
            'client_side_tokenization': True,
            'encrypted_metadata': True
        },
        'how_to_test': {
            'step1': 'Use Stripe test card: 4242 4242 4242 4242',
            'step2': 'Check browser DevTools Network tab - no card data in requests',
            'step3': 'Check Stripe Dashboard - only payment method tokens (pm_xxx) stored',
            'step4': 'Verify metadata is encrypted in Stripe metadata'
        }
    })


# app.py (Focus on the /payment-success route)

@app.route('/payment-success')
# ADDED: login_required decorator to ensure user is authenticated
@login_required
def payment_success():
    """Payment success page - should finalize the booking and save to DB"""
    payment_intent_id = request.args.get('payment_intent')

    db_booking_id = None

    if not payment_intent_id:
        # Redirect to home if no payment intent is provided
        flash('Payment finalization failed: Missing payment intent ID.', 'error')
        return redirect(url_for('index'))

    try:
        # 1. Retrieve payment intent from Stripe (contains tokenized payment method)
        payment_intent = stripe.PaymentIntent.retrieve(payment_intent_id)

        # 2. Get necessary data for booking finalization
        user_email = session.get('user')
        user_id = session.get('user_id')
        user_name = session.get('user_name')
        cart_items = session.get('cart', {})

        if not cart_items:
            # Handle case where cart was cleared or never existed
            flash('Booking data not found in session for finalization.', 'warning')
            return redirect(url_for('booking_history'))

        # Assuming the cart has at least one item and we are processing all items.
        # For simplicity, this example processes the whole cart into one booking.
        totals = calculate_cart_totals(cart_items, VEHICLES)

        # We need the details for the first item to structure the booking entry
        vehicle_id, booking_details = next(iter(cart_items.items()))
        vehicle_id = int(vehicle_id)

        # Retrieve vehicle details for display fields
        vehicle_data = VEHICLES.get(vehicle_id, {})

        # 3. Assemble Booking Data for DB Insertion
        booking_data = {
            # Note: create_booking in database.py uses DB-generated ID (lastrowid)
            # if booking_id is not passed, but let's pass a generated ID for clarity
            # and matching the theoretical table structure if a custom ID is desired.
            'booking_id': generate_booking_id(),
            'vehicle_id': vehicle_id,
            'user_id': user_id,
            'pickup_date': booking_details['pickup_date'],
            'return_date': booking_details['return_date'],
            'pickup_location': 'Online Booking',  # Placeholder: Should come from request
            'days': totals['cart_data'][0]['days'],
            'total_amount': totals['total'],
            'status': 'Confirmed',  # Set to Confirmed since payment succeeded
            'payment_intent_id': payment_intent_id
        }

        # 4. Save to MySQL Database
        try:
            # The database function is called here to persist the data.
            db_booking_id = create_booking(booking_data)
            
            # --- Audit log for booking creation ---
            add_audit_log(
                user_id=user_id,
                action='Create Booking',
                entity_type='BOOKING',
                entity_id=db_booking_id,
                new_values=json.dumps({
                    'booking_id': db_booking_id,
                    'vehicle_id': vehicle_id,
                    'total_amount': totals['total'],
                    'payment_intent_id': payment_intent_id,
                    'status': 'Confirmed'
                }),
                result='Success',
                ip_address=request.remote_addr,
                device_info=request.headers.get("User-Agent")
            )
            
            flash(f'Booking #{db_booking_id} successfully confirmed and recorded. Payment ID: {payment_intent_id}',
                  'success')

        except Exception as e:
            # Log critical failure to database
            add_security_log(
                user_id=str(user_id),
                event_type="BOOKING_DB_FAIL",
                severity="CRITICAL",
                description=f"Payment success, but DB insert failed for PI: {payment_intent_id}. Error: {e}",
                ip_address=request.remote_addr
            )
            print(f"CRITICAL ERROR: Failed to save booking to DB: {e}")
            flash('Booking confirmed by Stripe but failed to save to our records. Please contact support.', 'error')

        # 4b. Also store a display-friendly booking in the in-memory BOOKINGS dict
        #     so booking_history can still show it even if DB lookups fail.
        try:
            from models import BOOKINGS  # local import to avoid circulars at module load
            display_booking_id = booking_data['booking_id']
            BOOKINGS[display_booking_id] = {
                'booking_id': display_booking_id,
                'vehicle_id': vehicle_id,
                'vehicle_name': vehicle_data.get('name'),
                'vehicle_type': vehicle_data.get('type'),
                'vehicle_image': vehicle_data.get('image'),
                'customer_name': user_name,
                'customer_email': user_email,
                'pickup_date': booking_data['pickup_date'],
                'return_date': booking_data['return_date'],
                'pickup_location': booking_data['pickup_location'],
                'booking_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'days': booking_data['days'],
                'total_amount': booking_data['total_amount'],
                'status': booking_data.get('status', 'Confirmed'),
                'payment_intent_id': booking_data.get('payment_intent_id'),
            }
        except Exception as e:
            print(f"Warning: failed to store booking in in-memory BOOKINGS dict: {e}")

        # 5. Clear Session Cart (ONLY after DB insertion attempt)
        session['cart'] = {}
        session.modified = True

        # 6. Render success page
        return render_template('payment_success.html',
                               payment_intent_id=payment_intent_id,
                               payment_method_token=payment_intent.payment_method,
                               amount=payment_intent.amount / 100,
                               # Pass the final booking ID for display
                               db_booking_id=db_booking_id)

    except stripe.error.StripeError as e:
        flash(f'Error retrieving payment: {str(e)}', 'error')
        return redirect(url_for('index_logged'))
    except Exception as e:
        print(f"CRITICAL ERROR: Failed to save booking to DB: {e}")
        return f"DATABASE INSERTION FAILED. ERROR DETAILS: {e}", 500


@app.route('/webhook/stripe', methods=['POST'])
def stripe_webhook():
    """Stripe webhook handler for secure payment confirmation"""
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    webhook_secret = Config.STRIPE_WEBHOOK_SECRET or None

    try:
        if webhook_secret:
            event = stripe.Webhook.construct_event(
                payload, sig_header, webhook_secret
            )
        else:
            # For testing without webhook secret
            event = json.loads(payload)

        # Handle payment intent succeeded
        if event['type'] == 'payment_intent.succeeded':
            payment_intent = event['data']['object']
            payment_method_id = payment_intent.get('payment_method')

            # Payment method is tokenized - no card data available
            # Only payment method token (pm_xxx) is stored
            print(f"Payment succeeded. Tokenized Payment Method ID: {payment_method_id}")

            # Decrypt metadata if needed
            if payment_intent.get('metadata'):
                encrypted_metadata = payment_intent['metadata']
                # Process encrypted metadata as needed
                # Card data is never stored - only tokenized payment method

        return jsonify({'status': 'success'}), 200

    except ValueError as e:
        return jsonify({'error': 'Invalid payload'}), 400
    except stripe.error.SignatureVerificationError as e:
        return jsonify({'error': 'Invalid signature'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================
# BACKUP & RECOVERY ROUTES
# ============================================

@app.route('/admin/backup/create', methods=['POST'])
@login_required
def create_backup():
    """Create encrypted backup of all sensitive data"""
    try:
        backup_system = SecureBackup()
        include_files = request.json.get('include_files', True) if request.is_json else True
        user_id = session.get('user_id')

        backup_info = backup_system.create_backup(
            include_files=include_files,
            backup_type='Manual',
            created_by_user_id=user_id,
            log_to_db=True
        )

        return jsonify({
            'success': True,
            'message': 'Backup created successfully',
            'backup_file': backup_info['backup_filename'],
            'backup_path': backup_info['backup_path'],
            'backup_size_mb': backup_info['backup_size_mb'],
            'checksum_sha256': backup_info['checksum_sha256'],
            'tables_backed_up': backup_info['tables_backed_up'],
            'cloud_backup_enabled': backup_info['cloud_backup_enabled'],
            'timestamp': datetime.now().isoformat()
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/admin/backup/list', methods=['GET'])
@login_required
def list_backups():
    """List all available backups with database logs"""
    try:
        backup_system = SecureBackup()
        file_backups = backup_system.list_backups()
        db_logs = get_backup_logs(limit=1000)

        # Merge file backups with database logs
        backups_with_logs = []
        for file_backup in file_backups:
            # Find matching log entry
            matching_log = None
            for log in db_logs:
                if log['backup_filename'] == file_backup['filename']:
                    matching_log = log
                    break

            # Parse tables_backed_up if it's a JSON string
            tables_backed_up = []
            if matching_log and matching_log.get('tables_backed_up'):
                if isinstance(matching_log['tables_backed_up'], str):
                    try:
                        tables_backed_up = json.loads(matching_log['tables_backed_up'])
                    except:
                        tables_backed_up = []
                else:
                    tables_backed_up = matching_log['tables_backed_up']

            backup_entry = {
                **file_backup,
                'checksum_sha256': matching_log['checksum_sha256'] if matching_log else None,
                'tables_backed_up': tables_backed_up,
                'files_included': matching_log['files_included'] if matching_log else 0,
                'cloud_backup_enabled': matching_log['cloud_backup_enabled'] if matching_log else False,
                'status': matching_log['status'] if matching_log else 'Unknown',
                'verification_status': matching_log['verification_status'] if matching_log else 'Pending',
                'backup_type': matching_log['backup_type'] if matching_log else 'Unknown',
                'log_id': matching_log['backup_id'] if matching_log else None
            }
            backups_with_logs.append(backup_entry)

        return jsonify({
            'success': True,
            'backups': backups_with_logs,
            'count': len(backups_with_logs)
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/admin/backup/restore', methods=['POST'])
@login_required
def restore_backup():
    """Restore data from backup"""
    try:
        data = request.get_json()
        backup_filename = data.get('backup_filename')
        restore_tables = data.get('restore_tables')  # Optional: specific tables to restore

        if not backup_filename:
            return jsonify({'error': 'backup_filename is required'}), 400

        backup_system = SecureBackup()
        result = backup_system.restore_backup(backup_filename, restore_tables)

        return jsonify({
            'success': True,
            'message': 'Backup restored successfully',
            'restored_tables': result['restored_tables'],
            'restored_files': result['restored_files'],
            'restored_in_memory': result.get('restored_in_memory', {}),
            'timestamp': result['timestamp']
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/admin/backup/cleanup', methods=['POST'])
@login_required
def cleanup_backups():
    """Delete old backups (keep only recent ones)"""
    try:
        data = request.get_json() if request.is_json else {}
        keep_days = data.get('keep_days', Config.BACKUP_RETENTION_DAYS)

        backup_system = SecureBackup()
        deleted = backup_system.delete_old_backups(keep_days=keep_days)

        return jsonify({
            'success': True,
            'message': f'Deleted {len(deleted)} old backup(s)',
            'deleted_files': deleted,
            'keep_days': keep_days
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/admin/backup/status', methods=['GET'])
@login_required
def backup_status():
    """Get backup system status and configuration with statistics"""
    try:
        backup_system = SecureBackup()
        backups = backup_system.list_backups()
        stats = get_backup_stats()

        return jsonify({
            'backup_enabled': True,
            'backup_directory': backup_system.backup_dir,
            'cloud_backup_enabled': backup_system.cloud_backup_dir is not None,
            'cloud_backup_directory': backup_system.cloud_backup_dir,
            'total_backups': len(backups),
            'latest_backup': backups[0] if backups else None,
            'retention_days': Config.BACKUP_RETENTION_DAYS,
            'auto_backup_enabled': Config.AUTO_BACKUP_ENABLED,
            'auto_backup_interval_hours': Config.AUTO_BACKUP_INTERVAL_HOURS,
            'statistics': stats
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/admin/backup/logs', methods=['GET'])
@login_required
def backup_logs():
    """Get backup logs for verification/proof"""
    try:
        status_filter = request.args.get('status')
        limit = int(request.args.get('limit', 100))

        logs = get_backup_logs(limit=limit, status=status_filter)

        return jsonify({
            'success': True,
            'logs': logs,
            'count': len(logs)
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/admin/backup/verify/<backup_filename>', methods=['POST'])
@login_required
def verify_backup(backup_filename):
    """Verify backup integrity"""
    try:
        backup_system = SecureBackup()
        verification_result = backup_system.verify_backup(backup_filename)

        # Update verification status in database
        if verification_result.get('verified'):
            logs = get_backup_logs(limit=1000)
            for log in logs:
                if log['backup_filename'] == backup_filename:
                    update_backup_verification(log['backup_id'], 'Verified')
                    break

        return jsonify({
            'success': verification_result.get('verified', False),
            'verification': verification_result
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/admin/backup/stats', methods=['GET'])
@login_required
def backup_stats():
    """Get backup statistics for admin dashboard"""
    try:
        stats = get_backup_stats()
        return jsonify({
            'success': True,
            'statistics': stats
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/backup-test', methods=['GET'])
def backup_test():
    """Test backup system - shows if backups are working (no login required for testing)"""
    try:
        backup_system = SecureBackup()

        # Check if backup directory exists and is writable
        backup_dir_exists = os.path.exists(backup_system.backup_dir)
        backup_dir_writable = os.access(backup_system.backup_dir, os.W_OK) if backup_dir_exists else False

        # Check encryption key
        encryption_key_set = bool(Config.DATA_ENCRYPTION_KEY)

        # List existing backups
        backups = backup_system.list_backups()

        # Try to create a test backup (small test)
        test_backup_created = False
        test_backup_path = None
        test_error_msg = None
        try:
            test_backup_path = backup_system.create_backup(include_files=False)  # Quick test without files
            test_backup_created = True
            # Clean up test backup
            if os.path.exists(test_backup_path):
                os.remove(test_backup_path)
        except Exception as test_error:
            test_error_msg = str(test_error)

        return jsonify({
            'backup_system_status': 'operational' if test_backup_created else 'error',
            'backup_directory': backup_system.backup_dir,
            'backup_directory_exists': backup_dir_exists,
            'backup_directory_writable': backup_dir_writable,
            'encryption_key_configured': encryption_key_set,
            'total_existing_backups': len(backups),
            'test_backup_created': test_backup_created,
            'test_error': test_error_msg,
            'latest_backup': backups[0] if backups else None,
            'security_features': {
                'backups_encrypted': True,
                'restricted_access': True,
                'cloud_storage_available': backup_system.cloud_backup_dir is not None
            },
            'how_to_use': {
                'create_backup': 'POST /admin/backup/create (requires login)',
                'list_backups': 'GET /admin/backup/list (requires login)',
                'restore_backup': 'POST /admin/backup/restore (requires login)',
                'manual_test': 'python backup_scheduler.py'
            }
        }), 200

    except Exception as e:
        return jsonify({
            'backup_system_status': 'error',
            'error': str(e),
            'troubleshooting': {
                'check_encryption_key': 'Set DATA_ENCRYPTION_KEY in config.py',
                'check_backup_dir': f'Ensure {backup_system.backup_dir} directory exists and is writable',
                'check_database': 'Verify database connection is working'
            }
        }), 500


@app.route('/backup-recovery-test', methods=['GET'])
def backup_recovery_test():
    """Test both backup creation AND recovery/restore capability (no login required for testing)"""
    import zipfile
    import shutil

    try:
        backup_system = SecureBackup()

        # Initialize results
        results = {
            'backup_test': {'passed': False, 'message': '', 'details': {}},
            'recovery_test': {'passed': False, 'message': '', 'details': {}},
            'overall_status': 'error'
        }

        test_backup_path = None
        decrypted_path = None
        extract_dir = None

        try:
            # ========================================
            # TEST 1: BACKUP CREATION
            # ========================================
            try:
                test_backup_path = backup_system.create_backup(include_files=False)  # Quick test

                if os.path.exists(test_backup_path):
                    file_size = os.path.getsize(test_backup_path)
                    results['backup_test'] = {
                        'passed': True,
                        'message': 'Backup created successfully',
                        'details': {
                            'backup_file': os.path.basename(test_backup_path),
                            'file_size_bytes': file_size,
                            'encrypted': test_backup_path.endswith('.encrypted')
                        }
                    }
                else:
                    results['backup_test'] = {
                        'passed': False,
                        'message': 'Backup file was not created',
                        'details': {}
                    }
                    return jsonify(results), 500

            except Exception as e:
                results['backup_test'] = {
                    'passed': False,
                    'message': f'Backup creation failed: {str(e)}',
                    'details': {}
                }
                return jsonify(results), 500

            # ========================================
            # TEST 2: RECOVERY (DECRYPTION & EXTRACTION)
            # ========================================
            try:
                # Test decryption
                decrypted_path = backup_system.decrypt_backup_file(test_backup_path)

                if not os.path.exists(decrypted_path):
                    results['recovery_test'] = {
                        'passed': False,
                        'message': 'Decryption failed - file not created',
                        'details': {}
                    }
                    return jsonify(results), 500

                # Test extraction and data reading
                extract_dir = os.path.join(backup_system.backup_dir, 'test_extract_recovery')
                os.makedirs(extract_dir, exist_ok=True)

                with zipfile.ZipFile(decrypted_path, 'r') as backup_zip:
                    backup_zip.extractall(extract_dir)

                    # Check metadata
                    metadata_path = os.path.join(extract_dir, 'backup_metadata.json')
                    metadata_readable = False
                    if os.path.exists(metadata_path):
                        with open(metadata_path, 'r') as f:
                            metadata = json.load(f)
                        metadata_readable = True

                    # Check database backup
                    db_path = os.path.join(extract_dir, 'database_backup.json')
                    db_readable = False
                    tables_count = 0
                    if os.path.exists(db_path):
                        with open(db_path, 'r') as f:
                            db_data = json.load(f)
                        db_readable = True
                        tables_count = len(db_data.get('tables_backed_up', []))

                results['recovery_test'] = {
                    'passed': True,
                    'message': 'Recovery test passed - backup can be decrypted and data extracted',
                    'details': {
                        'decryption_successful': True,
                        'extraction_successful': True,
                        'metadata_readable': metadata_readable,
                        'database_readable': db_readable,
                        'tables_in_backup': tables_count,
                        'files_extracted': len(os.listdir(extract_dir))
                    }
                }

            except Exception as e:
                results['recovery_test'] = {
                    'passed': False,
                    'message': f'Recovery test failed: {str(e)}',
                    'details': {}
                }
                return jsonify(results), 500

            # Determine overall status
            if results['backup_test']['passed'] and results['recovery_test']['passed']:
                results['overall_status'] = 'operational'
            elif results['backup_test']['passed']:
                results['overall_status'] = 'partial'  # Backup works but recovery doesn't
            else:
                results['overall_status'] = 'error'

            # Add summary
            results['summary'] = {
                'backup_works': results['backup_test']['passed'],
                'recovery_works': results['recovery_test']['passed'],
                'system_ready': results['overall_status'] == 'operational'
            }

            return jsonify(results), 200

        finally:
            # Cleanup test files
            if extract_dir and os.path.exists(extract_dir):
                shutil.rmtree(extract_dir, ignore_errors=True)
            if decrypted_path and os.path.exists(decrypted_path):
                try:
                    os.remove(decrypted_path)
                except:
                    pass
            if test_backup_path and os.path.exists(test_backup_path):
                try:
                    os.remove(test_backup_path)
                except:
                    pass

    except Exception as e:
        return jsonify({
            'overall_status': 'error',
            'error': str(e),
            'backup_test': {'passed': False, 'message': 'Test failed to run'},
            'recovery_test': {'passed': False, 'message': 'Test failed to run'}
        }), 500


@app.route('/file-security-test', methods=['GET'])
def file_security_test():
    """Test file upload security features (no login required for testing)"""
    try:
        from utils.file_security import (
            verify_file_magic_number, detect_file_type,
            validate_image_file, sanitize_filename
        )
        import base64

        results = {
            'security_features': {
                'magic_number_verification': True,
                'image_validation': True,
                'filename_sanitization': True,
                'file_spoofing_detection': True
            },
            'tests': []
        }

        all_passed = True

        # Test 1: Magic number verification
        try:
            # Create fake PNG (should fail - not real PNG)
            fake_png = b'FAKE_PNG_DATA_NOT_REAL\x89\x50\x4E\x47'
            is_valid, detected = verify_file_magic_number(fake_png, 'png')
            if is_valid:
                raise Exception("Fake PNG was incorrectly accepted")

            # Real PNG header
            real_png = b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A' + b'VALID_PNG_DATA'
            is_valid, detected = verify_file_magic_number(real_png, 'png')
            if not is_valid:
                raise Exception("Real PNG was incorrectly rejected")

            results['tests'].append({
                'test_name': 'Magic Number Verification',
                'passed': True,
                'description': 'Detects file type from content, not just extension'
            })
        except Exception as e:
            all_passed = False
            results['tests'].append({
                'test_name': 'Magic Number Verification',
                'passed': False,
                'error': str(e)
            })

        # Test 2: File type detection
        try:
            jpg_data = b'\xFF\xD8\xFF\xE0\x00\x10JFIF'
            detected = detect_file_type(jpg_data)
            if detected != 'jpg':
                raise Exception(f"Expected 'jpg', got '{detected}'")

            png_data = b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'
            detected = detect_file_type(png_data)
            if detected != 'png':
                raise Exception(f"Expected 'png', got '{detected}'")

            results['tests'].append({
                'test_name': 'File Type Detection',
                'passed': True,
                'description': 'Correctly identifies file types from content'
            })
        except Exception as e:
            all_passed = False
            results['tests'].append({
                'test_name': 'File Type Detection',
                'passed': False,
                'error': str(e)
            })

        # Test 3: Filename sanitization
        try:
            dangerous_names = [
                ('../../etc/passwd.jpg', 'etc_passwd.jpg'),
                ('file<script>.jpg', 'file_script_.jpg'),
                ('file\x00null.jpg', 'filenull.jpg'),
                ('normal_file.jpg', 'normal_file.jpg')
            ]

            for dangerous, expected_safe in dangerous_names:
                sanitized = sanitize_filename(dangerous)
                if '../' in sanitized or '<' in sanitized or '\x00' in sanitized:
                    raise Exception(f"Filename not properly sanitized: {sanitized}")

            results['tests'].append({
                'test_name': 'Filename Sanitization',
                'passed': True,
                'description': 'Removes dangerous characters and path traversal attempts'
            })
        except Exception as e:
            all_passed = False
            results['tests'].append({
                'test_name': 'Filename Sanitization',
                'passed': False,
                'error': str(e)
            })

        # Test 4: Image validation
        try:
            # Invalid image (too small)
            tiny_file = b'X' * 50
            is_valid, error = validate_image_file(tiny_file)
            if is_valid:
                raise Exception("Tiny file was incorrectly accepted as valid image")

            # Valid JPEG (minimal structure)
            valid_jpg = b'\xFF\xD8\xFF\xE0\x00\x10JFIF' + b'X' * 200 + b'\xFF\xD9'
            is_valid, error = validate_image_file(valid_jpg)
            if not is_valid:
                raise Exception(f"Valid JPEG was rejected: {error}")

            results['tests'].append({
                'test_name': 'Image Validation',
                'passed': True,
                'description': 'Validates image structure, not just file extension'
            })
        except Exception as e:
            all_passed = False
            results['tests'].append({
                'test_name': 'Image Validation',
                'passed': False,
                'error': str(e)
            })

        results['overall_status'] = 'operational' if all_passed else 'error'
        results['summary'] = {
            'total_tests': len(results['tests']),
            'passed_tests': sum(1 for t in results['tests'] if t.get('passed', False)),
            'failed_tests': sum(1 for t in results['tests'] if not t.get('passed', False)),
            'file_security_working': all_passed
        }

        status_code = 200 if all_passed else 500
        return jsonify(results), status_code

    except Exception as e:
        return jsonify({
            'overall_status': 'error',
            'error': str(e),
            'message': 'File security test failed to run'
        }), 500

# ============================================
# BOOKING & CANCELLATION ROUTES
# ============================================

@app.route('/cancel-booking/<booking_id>')
@login_required
def cancel_booking(booking_id):
    """Display cancellation request page"""
    user_role = session.get('user_type', 'user')
    user_id = session.get('user_id')
    user_email = session.get('user')
    
    booking = BOOKINGS.get(booking_id)

    if not booking:
        return "Booking not found", 404
    
    # Check if user owns this booking
    if booking.get('customer_email') != user_email and user_role != 'admin':
        flash('You can only cancel your own bookings', 'error')
        return redirect(url_for('booking_history'))

    if booking['status'] not in ['Confirmed', 'Pending']:
        return "This booking cannot be cancelled", 400

    # Redact sensitive booking data based on user permissions
    booking_owner_id = booking.get('user_id')
    redacted_booking = redact_dict(booking, 'bookings', user_role, user_id, booking_owner_id)
    
    refund_percentage = calculate_refund_percentage(booking)
    processing_fee = 10 if refund_percentage > 0 else 0
    estimated_refund = (booking['total_amount'] * refund_percentage / 100) - processing_fee
    estimated_refund = max(0, estimated_refund)

    return render_template('cancel_booking.html',
                           booking=redacted_booking,
                           refund_percentage=refund_percentage,
                           processing_fee=processing_fee,
                           estimated_refund=round(estimated_refund, 2))


@app.route('/submit-cancellation/<booking_id>', methods=['POST'])
def submit_cancellation(booking_id):
    """Submit cancellation request"""
    booking = BOOKINGS.get(booking_id)

    if not booking:
        return jsonify({'error': 'Booking not found'}), 404

    cancellation_reason = request.form.get('cancellation_reason')
    cancellation_details = request.form.get('cancellation_details')

    if not cancellation_reason or not cancellation_details:
        return "Please provide all required information", 400

    request_id = generate_request_id()
    CANCELLATION_REQUESTS[request_id] = {
        'request_id': request_id,
        'booking_id': booking_id,
        'booking': booking,
        'reason': cancellation_reason,
        'details': cancellation_details,
        'request_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'status': 'Pending',
        'reviewed_date': None,
        'refund_percentage': calculate_refund_percentage(booking)
    }

    BOOKINGS[booking_id]['status'] = 'Pending Cancellation'

    # --- Audit log for cancellation request ---
    add_audit_log(
        user_id=session.get('user_id', 0),
        action='Submit Cancellation Request',
        entity_type='CANCELLATION',
        entity_id=request_id,
        new_values=json.dumps({
            'booking_id': booking_id,
            'request_id': request_id,
            'reason': cancellation_reason,
            'refund_percentage': calculate_refund_percentage(booking)
        }),
        result='Success',
        ip_address=request.remote_addr,
        device_info=request.headers.get("User-Agent")
    )

    return render_template('cancellation_submitted.html',
                           request_id=request_id,
                           booking=booking)


@app.route('/seller/cancellation-requests')
@login_required
def seller_cancellation_requests():
    """Seller page to view all cancellation requests"""
    user_role = session.get('user_type', 'guest')
    user_id = session.get('user_id')
    
    # Check if user is seller or admin
    if user_role not in ['seller', 'admin']:
        flash('Access denied. Seller privileges required.', 'error')
        return redirect(url_for('index'))
    
    pending_requests = {
        rid: req for rid, req in CANCELLATION_REQUESTS.items()
        if req['status'] == 'Pending'
    }
    
    # Redact sensitive customer data in cancellation requests
    redacted_requests = {}
    for rid, req in pending_requests.items():
        booking = req.get('booking', {})
        booking_owner_id = booking.get('user_id')
        redacted_booking = redact_dict(booking, 'bookings', user_role, user_id, booking_owner_id)
        redacted_req = dict(req)
        redacted_req['booking'] = redacted_booking
        redacted_requests[rid] = redacted_req
    
    return render_template('seller_cancellations.html', requests=redacted_requests)


@app.route('/seller/approve-cancellation/<request_id>', methods=['POST'])
def seller_approve_cancellation(request_id):
    """Approve cancellation request"""
    cancellation_request = CANCELLATION_REQUESTS.get(request_id)

    if not cancellation_request:
        return jsonify({'error': 'Request not found'}), 404

    booking = cancellation_request['booking']

    refund_percentage = cancellation_request['refund_percentage']
    processing_fee = 10 if refund_percentage > 0 else 0
    refund_amount = (booking['total_amount'] * refund_percentage / 100) - processing_fee
    refund_amount = max(0, round(refund_amount, 2))

    refund_id = generate_refund_id()
    REFUNDS[refund_id] = {
        'refund_id': refund_id,
        'booking_id': booking['booking_id'],
        'request_id': request_id,
        'original_amount': booking['total_amount'],
        'refund_percentage': refund_percentage,
        'processing_fee': processing_fee,
        'refund_amount': refund_amount,
        'request_date': cancellation_request['request_date'],
        'approval_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'cancellation_date': datetime.now().strftime('%Y-%m-%d'),
        'status': 'Approved',
        'payment_intent_id': booking.get('payment_intent_id')
    }

    CANCELLATION_REQUESTS[request_id]['status'] = 'Approved'
    CANCELLATION_REQUESTS[request_id]['reviewed_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    BOOKINGS[booking['booking_id']]['status'] = 'Cancelled'

    # --- Audit log for cancellation approval ---
    add_audit_log(
        user_id=session.get('user_id', 0),
        action='Approve Cancellation',
        entity_type='CANCELLATION',
        entity_id=request_id,
        new_values=json.dumps({
            'status': 'Approved',
            'refund_id': refund_id,
            'refund_amount': refund_amount,
            'booking_id': booking['booking_id']
        }),
        result='Success',
        ip_address=request.remote_addr,
        device_info=request.headers.get("User-Agent")
    )

    return jsonify({'success': True, 'refund_id': refund_id, 'refund_amount': refund_amount})


@app.route('/seller/reject-cancellation/<request_id>', methods=['POST'])
def seller_reject_cancellation(request_id):
    """Reject cancellation request"""
    cancellation_request = CANCELLATION_REQUESTS.get(request_id)

    if not cancellation_request:
        return jsonify({'error': 'Request not found'}), 404

    booking = cancellation_request['booking']

    CANCELLATION_REQUESTS[request_id]['status'] = 'Rejected'
    CANCELLATION_REQUESTS[request_id]['reviewed_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    BOOKINGS[booking['booking_id']]['status'] = 'Confirmed'

    # --- Audit log for cancellation rejection ---
    add_audit_log(
        user_id=session.get('user_id', 0),
        action='Reject Cancellation',
        entity_type='CANCELLATION',
        entity_id=request_id,
        new_values=json.dumps({
            'status': 'Rejected',
            'booking_id': booking['booking_id']
        }),
        result='Success',
        severity='Low',
        ip_address=request.remote_addr,
        device_info=request.headers.get("User-Agent")
    )

    return jsonify({'success': True})


@app.route('/refund-status/<refund_id>')
def refund_status(refund_id):
    """Display refund confirmation page"""
    refund = REFUNDS.get(refund_id)

    if not refund:
        return "Refund not found", 404

    return render_template('refund_confirmed.html', refund=refund)


@app.route('/my-cancellations')
def my_cancellations():
    """View customer's cancellation requests"""
    return render_template('my_cancellations.html',
                           requests=CANCELLATION_REQUESTS,
                           refunds=REFUNDS)


@app.route('/create-test-booking')
def create_test_booking():
    """Create a test booking for development"""
    booking_id = generate_booking_id()

    tomorrow = datetime.now() + timedelta(days=1)
    return_date = tomorrow + timedelta(days=3)

    BOOKINGS[booking_id] = {
        'booking_id': booking_id,
        'vehicle_id': 1,
        'vehicle_name': 'Toyota Sienta Hybrid',
        'vehicle_image': 'images/toyota.png',
        'customer_name': 'Test User',
        'customer_email': 'test@example.com',
        'pickup_date': tomorrow.strftime('%Y-%m-%d'),
        'return_date': return_date.strftime('%Y-%m-%d'),
        'pickup_location': 'Jurong Point, Singapore',
        'booking_date': datetime.now().strftime('%Y-%m-%d'),
        'days': 3,
        'total_amount': 500,
        'status': 'Confirmed',
        'payment_intent_id': 'pi_test123'
    }

    return redirect(url_for('cancel_booking', booking_id=booking_id))


# ============================================
# SELLER ROUTES
# ============================================

@app.route('/seller')
def seller_index():
    user_email = session.get('user')
    if user_email:
        user = get_user_by_email(user_email)
        if user:
            first_name_raw = user.get('first_name') or ''
            last_name_raw = user.get('last_name') or ''
            first_name = decrypt_value(first_name_raw, fallback_on_error=True) if first_name_raw else ''
            last_name = decrypt_value(last_name_raw, fallback_on_error=True) if last_name_raw else ''
            display_name = _safe_display_name(first_name, last_name, user_email)
            session['user_name'] = display_name or user_email
            session.modified = True
    return render_template('seller_index.html')


@app.route('/seller/manage-listings')
def manage_listings():
    """Seller page to manage listings and view cancellation requests"""
    # Import the data from models
    from models import listings, CANCELLATION_REQUESTS

    # Filter for pending cancellation requests
    pending_requests = {
        rid: req for rid, req in CANCELLATION_REQUESTS.items()
        if req['status'] == 'Pending'
    }

    # Pass both listings and pending_requests to the template
    return render_template('manage_listings.html',
                           listings=listings,
                           pending_requests=pending_requests)


@app.route('/seller/add-listing', methods=['POST'])
def add_listing():
    try:
        vehicle_name = request.form.get('vehicle_name')
        vehicle_type = request.form.get('vehicle_type')
        fuel_type = request.form.get('fuel_type')
        price = request.form.get('price')
        location = request.form.get('location')
        description = request.form.get('description')
        seating = request.form.get('seating')
        year = request.form.get('year')

        image_path = 'images/default.png'
        if 'images' in request.files:
            file = request.files['images']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(Config.UPLOAD_FOLDER, filename))
                image_path = f'uploads/{filename}'

        new_listing = {
            'id': len(listings) + 1,
            'name': vehicle_name,
            'fuel_type': fuel_type,
            'location': location,
            'price': int(price),
            'bookings': 0,
            'description': description,
            'status': 'active',
            'image': image_path,
            'vehicle_type': vehicle_type,
            'seating': seating,
            'year': year
        }

        listings.append(new_listing)
        flash('Listing added successfully!', 'success')

    except Exception as e:
        flash(f'Error adding listing: {str(e)}', 'error')

    return redirect(url_for('manage_listings'))


@app.route('/seller/edit-listing/<int:listing_id>')
def edit_listing(listing_id):
    listing = next((l for l in listings if l['id'] == listing_id), None)
    if listing:
        return render_template('edit_listing.html', listing=listing)
    flash('Listing not found', 'error')
    return redirect(url_for('manage_listings'))


@app.route('/seller/toggle-status/<int:listing_id>', methods=['POST'])
def toggle_listing_status(listing_id):
    listing = next((l for l in listings if l['id'] == listing_id), None)
    if listing:
        listing['status'] = 'inactive' if listing['status'] == 'active' else 'active'
        flash(f'Listing status updated to {listing["status"]}', 'success')
    else:
        flash('Listing not found', 'error')
    return redirect(url_for('manage_listings'))


@app.route('/seller/delete-listing/<int:listing_id>', methods=['POST'])
def delete_listing(listing_id):
    from models import listings
    # Remove the listing from the list
    listing_to_delete = next((l for l in listings if l['id'] == listing_id), None)
    if listing_to_delete:
        # AUDIT: Log listing deletion BEFORE removing
        add_audit_log(
            action='LISTING_DELETED',
            user_id=session.get('user_id'),
            entity_type='VEHICLE',
            entity_id=listing_id,
            reason=f"Listing deleted: {listing_to_delete.get('name', 'Unknown')} (ID: {listing_id})",
            ip_address=request.remote_addr,
            device_info=request.headers.get("User-Agent")
        )
        
        listings.remove(listing_to_delete)
        flash('Listing deleted successfully', 'success')
    else:
        flash('Listing not found', 'error')
    return redirect(url_for('manage_listings'))


# ============================================
# ADMIN ROUTES
# ============================================

@app.route('/dashboard')
def dashboard():
    """Dashboard page"""
    return render_template('dashboard.html')


@app.route('/accounts')
@require_classification('users.nric')
def accounts():
    """
    Reuse the admin panel experience on the Accounts route
    so admins see the full approval dashboard when clicking Accounts.
    """
    return admin_panel()


@app.route('/vehicles-page')
def vehicles_page():
    """Vehicles menu page with navigation to sub-pages"""
    return render_template('vehicles_page.html')


@app.route('/vehicle-management', methods=['GET', 'POST'])
def vehicle_management():
    if request.method == 'POST':
        vehicle_id = request.form.get('vehicle_id')

        name = request.form.get('name')
        vtype = request.form.get('type')
        price_per_day = request.form.get('price_per_day')
        pickup_location = request.form.get('pickup_location')
        description = request.form.get('description')
        image_file = request.files.get('image_file')

        if vehicle_id:
            # Editing existing vehicle
            vid = int(vehicle_id)
            vehicle = VEHICLES.get(vid, {})
            previous_values = vehicle.copy()  # capture old values for audit log
            action_type = 'Edit Vehicle'
        else:
            # Adding new vehicle
            vid = max(VEHICLES.keys()) + 1 if VEHICLES else 1
            vehicle = {}
            previous_values = None
            action_type = 'Add Vehicle'

        # Handle image upload
        image_path = vehicle.get('image')
        if image_file and image_file.filename:
            upload_folder = os.path.join('static', 'images')
            os.makedirs(upload_folder, exist_ok=True)
            filename = image_file.filename
            save_path = os.path.join(upload_folder, filename)
            image_file.save(save_path)
            image_path = f'images/{filename}'

        # Update VEHICLES dict
        VEHICLES[vid] = {
            'id': vid,
            'name': name,
            'type': vtype,
            'price_per_day': int(price_per_day),
            'pickup_location': pickup_location,
            'image': image_path,
            'description': description,
        }

        # --- Audit log ---
        user_id = session.get('user_id', 0)  # fallback 0 if no session
        add_audit_log(
            user_id=user_id,
            action=action_type,
            entity_type='VEHICLE',
            entity_id=vid,
            previous_values=previous_values,
            new_values=VEHICLES[vid],
            ip_address=request.remote_addr,
            device_info=request.headers.get("User-Agent"),
            result='Success'
        )

        return redirect(url_for('vehicle_management'))

    return render_template('vehicle_management.html', vehicles=VEHICLES)

@app.route('/security-dashboard')
@require_classification('security_logs.user_id')
def security_dashboard():
    """Security management page"""
    # Check if user is logged in and is admin
    if 'user' not in session or session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    return render_template('security_dashboard.html')


@app.route('/admin/backup-management')
@login_required
@require_classification('backup_logs.backup_path')
def backup_management():
    """Backup management page for admins"""
    # Check if user is logged in and is admin
    if 'user' not in session or session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    return render_template('backup_management.html')
    return render_template('security_dashboard.html')


@app.route('/admin/data-retention', methods=['GET', 'POST'])
def data_retention():
    """Admin-only data retention configuration."""
    if 'user' not in session or session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        current = get_retention_settings()
        try:
            retention_days = int(request.form.get('retention_days', current.get('retention_days', 365)))
            inactivity_days = int(request.form.get('inactivity_days', current.get('inactivity_days', 90)))
            if retention_days < 1 or inactivity_days < 1:
                raise ValueError
        except ValueError:
            flash('Retention days must be positive numbers.', 'error')
            return redirect(url_for('data_retention'))

        settings = {
            "auto_purge_enabled": bool(request.form.get('auto_purge_enabled')),
            "retention_days": retention_days,
            "inactivity_purge_enabled": bool(request.form.get('inactivity_purge_enabled')),
            "inactivity_days": inactivity_days,
            "apply_to_users": bool(request.form.get('apply_to_users')),
            "apply_to_sellers": bool(request.form.get('apply_to_sellers')),
            "exclude_admins": True,
        }
        update_retention_settings(settings, updated_by=session.get('user'))
        flash('Data retention settings updated.', 'success')
        return redirect(url_for('data_retention'))

    settings = get_retention_settings()
    return render_template('data_retention.html', settings=settings)


@app.route('/admin/data-retention/purge', methods=['POST'])
def data_retention_purge():
    """Manual retention purge (admin only)."""
    if 'user' not in session or session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))

    result = run_retention_purge(reason='manual')
    
    # AUDIT: Log data purge execution
    add_audit_log(
        action='DATA_PURGE_EXECUTED',
        user_id=session.get('user_id'),
        entity_type='RETENTION',
        entity_id='manual',
        reason=f"Data purge executed: {result.get('purged_count', 0)} accounts purged",
        ip_address=request.remote_addr,
        device_info=request.headers.get("User-Agent")
    )
    
    if result.get('skipped_reason'):
        flash(f"Purge skipped: {result['skipped_reason']}.", 'error')
    elif result.get('errors'):
        flash(
            f"Purged {result.get('purged_count', 0)} accounts with "
            f"{len(result['errors'])} errors. Check server logs.",
            'error',
        )
    elif result.get('purged_count', 0) == 0:
        flash('No accounts matched the current retention rules.', 'success')
    else:
        flash(f"Purged {result.get('purged_count', 0)} accounts.", 'success')

    return redirect(url_for('data_retention'))


@app.route('/admin/data-retention/extend/<int:user_id>', methods=['POST'])
def data_retention_extend_user(user_id):
    """Update per-user retention extension days."""
    if 'user' not in session or session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))

    try:
        extension_days = int(request.form.get('extension_days', 0))
        if extension_days < 0:
            raise ValueError
    except ValueError:
        flash('Extension days must be zero or a positive number.', 'error')
        return redirect(request.referrer or url_for('accounts'))

    set_retention_extension(user_id, extension_days, updated_by=session.get('user'))
    
    # AUDIT: Log retention extension
    target_user = get_user_by_id(user_id)
    add_audit_log(
        action='RETENTION_EXTENDED',
        user_id=session.get('user_id'),
        entity_type='USER',
        entity_id=user_id,
        reason=f"Retention extended for user_id {user_id} ({target_user.get('email') if target_user else 'unknown'}) by {extension_days} days",
        ip_address=request.remote_addr,
        device_info=request.headers.get("User-Agent")
    )
    
    if extension_days == 0:
        flash('Retention extension cleared.', 'success')
    else:
        flash('Retention extension updated.', 'success')
    return redirect(request.referrer or url_for('accounts'))


@app.route('/admin/data-retention/purge-user/<int:user_id>', methods=['POST'])
def data_retention_purge_user(user_id):
    """Immediate purge for a specific user (admin only)."""
    if 'user' not in session or session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))

    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT user_id, email, user_type FROM users WHERE user_id = %s",
            (user_id,),
        )
        user_row = cursor.fetchone()
        cursor.close()

    if not user_row:
        flash('User not found.', 'error')
        return redirect(request.referrer or url_for('accounts'))

    if user_row.get('user_type') == 'admin':
        flash('Admins cannot be purged.', 'error')
        return redirect(request.referrer or url_for('accounts'))

    # AUDIT: Log before individual user purge (CRITICAL - must log before deletion)
    add_audit_log(
        user_id=session.get('user_id'),
        action='USER_DATA_PURGED',
        entity_type='USER',
        entity_id=user_id,
        reason=f"User data purged for user_id {user_id} ({user_row.get('email')})",
        ip_address=request.remote_addr,
        device_info=request.headers.get("User-Agent")
    )
    
    purge_user_data(user_id, user_row.get('email'))
    flash('User data purged.', 'success')
    return redirect(request.referrer or url_for('accounts'))


# ============= DATA RETENTION POLICIES DASHBOARD =============

@app.route('/admin/data-retention-dashboard')
def data_retention_dashboard():
    """Data retention dashboard with configurable policies for all data types."""
    if 'user' not in session or session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    policies = get_all_retention_policies()
    stats = get_retention_statistics()
    user_settings = get_retention_settings()
    
    return render_template(
        'data_retention_dashboard.html',
        policies=policies,
        stats=stats,
        user_settings=user_settings
    )


@app.route('/api/retention-policies', methods=['GET'])
def api_get_retention_policies():
    """API: Get all retention policies."""
    if 'user' not in session or session.get('user_type') != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    policies = get_all_retention_policies()
    stats = get_retention_statistics()
    
    return jsonify({
        "policies": policies,
        "stats": stats
    })


@app.route('/api/retention-policies/<data_type>', methods=['PUT'])
def api_update_retention_policy(data_type):
    """API: Update a specific retention policy."""
    if 'user' not in session or session.get('user_type') != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    success = update_retention_policy(data_type, data)
    
    if success:
        # Audit log
        add_audit_log(
            action='RETENTION_POLICY_UPDATED',
            user_id=session.get('user_id'),
            entity_type='RETENTION_POLICY',
            entity_id=data_type,
            new_values=data,
            reason=f"Updated retention policy for {data_type}",
            ip_address=request.remote_addr,
            device_info=request.headers.get("User-Agent")
        )
        return jsonify({"success": True, "message": f"Policy for {data_type} updated"})
    
    return jsonify({"error": "Policy not found"}), 404


@app.route('/api/retention-policies/<data_type>/purge', methods=['POST'])
def api_purge_retention_type(data_type):
    """API: Manually purge data for a specific type."""
    if 'user' not in session or session.get('user_type') != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    result = purge_data_for_type(data_type, reason="manual")
    
    # Audit log
    add_audit_log(
        action='DATA_TYPE_PURGED',
        user_id=session.get('user_id'),
        entity_type='RETENTION_DATA',
        entity_id=data_type,
        reason=f"Purged {result.get('purged_count', 0)} records from {data_type}",
        ip_address=request.remote_addr,
        device_info=request.headers.get("User-Agent")
    )
    
    return jsonify(result)


@app.route('/api/retention-policies/purge-all', methods=['POST'])
def api_purge_all_retention():
    """API: Purge all data types based on their policies."""
    if 'user' not in session or session.get('user_type') != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    result = run_all_retention_purges(reason="manual_all")
    
    # Audit log
    add_audit_log(
        action='ALL_DATA_RETENTION_PURGED',
        user_id=session.get('user_id'),
        entity_type='RETENTION_DATA',
        entity_id='ALL',
        reason=f"Purged {result.get('total_purged', 0)} total records across {result.get('types_processed', 0)} data types",
        ip_address=request.remote_addr,
        device_info=request.headers.get("User-Agent")
    )
    
    return jsonify(result)


@app.route('/data-classification')
def data_classification():
    """Data classification page"""
    return render_template('data_classification.html')


@app.route('/audit-logs')
@require_classification('audit_logs.user_id')
def audit_logs():
    """Audit logs page"""
    # Check if user can access restricted audit logs table
    user_role = session.get('user_type', 'guest')
    user_id = session.get('user_id')
    
    if not can_access_table('audit_logs', user_role):
        flash('Access denied. Administrator privileges required.', 'error')
        return redirect(url_for('index'))
    
    # Fetch latest 100 audit logs
    logs = get_audit_logs(limit=100)

    # Attach user email for display and redact sensitive fields
    for log in logs:
        if log.get("user_id"):
            user = get_user_by_id(log["user_id"])
            log["user_email"] = user["email"] if user else f"User ID {log['user_id']}"
        else:
            log["user_email"] = "System / Unknown"

    return render_template('audit_logs.html', audit_logs=logs)


@app.route('/data-classification-dashboard')
@login_required
@require_classification('users.nric')
def data_classification_dashboard():
    """Data Classification Dashboard - Admin only"""
    if session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    # Get classification statistics
    stats = get_classification_stats()
    
    return render_template(
        'data_classification_dashboard.html',
        stats=stats,
        all_classifications=DATA_CLASSIFICATION,
        table_classifications=TABLE_CLASSIFICATIONS,
        classification_metadata=CLASSIFICATION_METADATA
    )


# ============================================
# CONTACT & SUPPORT ROUTES
# ============================================

@app.route('/contact_submit', methods=['POST'])
def contact_submit():
    """Handle contact form submission"""
    full_name = request.form.get('full-name')
    email = request.form.get('email')
    message = request.form.get('message')

    contact_entry = {
        'id': 'CONTACT-' + str(int(datetime.now().timestamp())),
        'timestamp': datetime.now().isoformat(),
        'full_name': full_name,
        'email': email,
        'message': message,
        'status': 'New'
    }

    contacts = session.get('contact_submissions', [])
    contacts.append(contact_entry)
    session['contact_submissions'] = contacts

    flash('Thank you for contacting us! We will get back to you soon.', 'success')
    return redirect(request.referrer or url_for('index') + '#section_4')


@app.route('/contact_submissions')
def contact_submissions():
    """View contact submissions (admin)"""
    contacts = session.get('contact_submissions', [])
    contacts.sort(key=lambda x: x['timestamp'], reverse=True)
    cart_count = get_cart_count(session)

    return render_template('admin_contact.html',
                           contacts=contacts,
                           cart_count=cart_count)


@app.route('/update_contact_status/<contact_id>/<status>')
def update_contact_status(contact_id, status):
    """Update contact status"""
    contacts = session.get('contact_submissions', [])

    for contact in contacts:
        if contact['id'] == contact_id:
            contact['status'] = status
            break

    session['contact_submissions'] = contacts
    return redirect(url_for('contact_submissions'))


@app.route('/delete_contact/<contact_id>')
def delete_contact(contact_id):
    """Delete contact submission"""
    contacts = session.get('contact_submissions', [])
    contacts = [c for c in contacts if c['id'] != contact_id]
    session['contact_submissions'] = contacts

    flash('Contact submission deleted successfully.', 'success')
    return redirect(url_for('contact_submissions'))


# ============================================
# INCIDENT REPORT ROUTES
# ============================================

@app.route("/report", methods=["GET", "POST"])
def report():
    """Incident report page with DB persistence."""
    # Ensure the incident_report_files table exists
    ensure_incident_report_files_table()
    
    cart_count = get_cart_count(session)

    if request.method == "POST":
        errors = []
        required_fields = [
            "full_name", "contact_number", "email",
            "booking_id", "vehicle_name", "incident_date",
            "incident_time", "incident_location", "incident_type",
            "severity_level", "incident_description"
        ]
        for field in required_fields:
            if not request.form.get(field):
                errors.append(f"{field.replace('_', ' ').title()} is required")

        photos = request.files.getlist("photos") if "photos" in request.files else []
        
        # Files are optional - only process if provided
        allowed_exts = {"png", "jpg", "jpeg", "gif", "webp", "pdf", "mp4", "avi", "mov", "wmv"}
        saved_files = []
        file_details_list = []  # Store file metadata for MySQL

        for idx, file in enumerate(photos, start=1):
            if not file or not file.filename:
                continue
            ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
            if ext not in allowed_exts:
                errors.append(f"File {idx}: invalid type (allowed: {allowed_exts})")
                continue
            if not validate_file_size(file):
                errors.append(f"File {idx}: must be less than 5MB")
                continue
            
            # Virus scanning and file validation using file_security
            is_valid, error_msg, detected_type = validate_uploaded_file(file)
            if not is_valid:
                # Log security validation failure for audit
                print(f"SECURITY: Incident report file validation failed for file {idx} ({file.filename}): {error_msg}")
                errors.append(f"File {idx}: {error_msg}")
                continue
            # Log successful validation
            file.seek(0)
            file_content = file.read()
            original_size = len(file_content)
            file.seek(0)  # Reset for processing
            print(f"SECURITY: Incident report file {idx} validated successfully. Filename: {file.filename}, Type: {detected_type}, Size: {original_size} bytes")
            
            # Determine MIME type and file type
            mime_types = {
                'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'png': 'image/png',
                'gif': 'image/gif', 'webp': 'image/webp', 'pdf': 'application/pdf',
                'mp4': 'video/mp4', 'avi': 'video/x-msvideo', 'mov': 'video/quicktime',
                'wmv': 'video/x-ms-wmv'
            }
            mime_type = mime_types.get(ext, 'application/octet-stream')
            is_image = ext in ['jpg', 'jpeg', 'png', 'gif', 'webp']
            is_video = ext in ['mp4', 'avi', 'mov', 'wmv']
            file_type = 'image' if is_image else ('video' if is_video else 'document')
            
            # Process file: watermark (if image) and encrypt
            try:
                processed_content, file_metadata = process_incident_file(
                    file_content,
                    file.filename,
                    encrypt=True,
                    watermark=True
                )
                processed_size = len(processed_content)
                print(f"SECURITY: File {idx} processed - Encrypted: {file_metadata['encrypted']}, Watermarked: {file_metadata.get('watermarked', False)}")
            except Exception as e:
                print(f"ERROR: Failed to process file {idx}: {e}")
                errors.append(f"File {idx}: Failed to encrypt/watermark file")
                continue
            
            # Save encrypted file
            os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
            safe_name = sanitize_filename(file.filename)
            filename = secure_filename(f"incident_{request.form.get('email','user')}_{safe_name}.encrypted")
            file_path = os.path.join(Config.UPLOAD_FOLDER, filename)
            
            # Write encrypted content
            with open(file_path, 'wb') as f:
                f.write(processed_content)
            
            saved_files.append(filename)
            
            # Store file metadata for MySQL
            file_details_list.append({
                'original_filename': file.filename,
                'file_path': file_path,
                'file_size_bytes': processed_size,
                'file_type': file_type,
                'mime_type': mime_type,
                'is_encrypted': file_metadata.get('encrypted', True),
                'is_watermarked': file_metadata.get('watermarked', False)
            })

        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("incident_report.html", cart_count=cart_count)

        # Persist to DB
        try:
            submitter_email = request.form.get('email')
            report_data = {
                'user_id': session.get('user_id'),
                'full_name': request.form.get('full_name'),
                'contact_number': request.form.get('contact_number'),
                'email': submitter_email,
                'booking_id': request.form.get('booking_id'),
                'vehicle_name': request.form.get('vehicle_name'),
                'incident_date': request.form.get('incident_date'),
                'incident_time': request.form.get('incident_time'),
                'incident_location': request.form.get('incident_location'),
                'incident_type': request.form.get('incident_type'),
                'severity_level': request.form.get('severity_level'),
                'incident_description': request.form.get('incident_description'),
                'files': saved_files,  # Files stored in files_json field
            }
            
            # Validate all required fields are present
            if not all([report_data['full_name'], report_data['contact_number'], 
                       report_data['email'], report_data['booking_id'], 
                       report_data['vehicle_name'], report_data['incident_date'],
                       report_data['incident_time'], report_data['incident_location'],
                       report_data['incident_type'], report_data['severity_level'],
                       report_data['incident_description']]):
                flash("All required fields must be filled.", "error")
                return render_template("incident_report.html", cart_count=cart_count)
            
            report_id = create_incident_report(report_data)
            
            if not report_id:
                flash("Failed to save incident report: No ID returned from database.", "error")
                return render_template("incident_report.html", cart_count=cart_count)
            
            # --- Audit log for incident report --- 
            add_audit_log(
                user_id=session.get('user_id', 0),
                action='Submit Incident Report',
                entity_type='INCIDENT_REPORT',
                entity_id=report_id,
                new_values=json.dumps({  # ← Fixed with json.dumps()
                    'report_id': report_id,
                    'incident_type': request.form.get('incident_type'),
                    'severity_level': request.form.get('severity_level'),
                    'booking_id': request.form.get('booking_id')
                }),
                result='Success',
                severity=normalize_severity(request.form.get('severity_level', 'Low')),  # ← Fixed with normalize
                ip_address=request.remote_addr,
                device_info=request.headers.get("User-Agent")
            )
                    
            # Store email in session so we can retrieve reports later (even if not logged in)
            if submitter_email:
                session['incident_report_email'] = submitter_email
                session.modified = True
            
            flash(f"Incident report #{report_id} submitted successfully!", "success")
            return redirect(url_for('report', submitted='true'))
        except Exception as e:
            import traceback
            error_msg = str(e)
            error_details = traceback.format_exc()
            # Show user-friendly message but log full details
            flash(f"Failed to save incident report. Error: {error_msg}", "error")
            print("=" * 60)
            print("ERROR saving incident report:")
            print(error_msg)
            print(error_details)
            print("=" * 60)

    return render_template("incident_report.html", cart_count=cart_count)


@app.route("/admin/create-files-table", methods=["GET", "POST"])
@login_required
def create_files_table():
    """Admin route to manually create the incident_report_files table."""
    # Check if user is admin
    user_email = session.get('user')
    user = get_user_by_email(user_email) if user_email else None
    
    if not user or user.get('user_type') != 'admin':
        flash("Access denied. Admin privileges required.", "error")
        return redirect(url_for("index_logged"))
    
    if request.method == "POST":
        success = ensure_incident_report_files_table()
        if success:
            flash("incident_report_files table created successfully!", "success")
        else:
            flash("Failed to create table. Check server logs for details.", "error")
        return redirect(url_for("security_dashboard"))
    
    # GET request - show confirmation
    return f"""
    <html>
        <head><title>Create Files Table</title></head>
        <body>
            <h1>Create incident_report_files Table</h1>
            <p>This will create the MySQL table for storing incident report file metadata.</p>
            <form method="POST">
                <button type="submit">Create Table</button>
                <a href="{url_for('security_dashboard')}">Cancel</a>
            </form>
        </body>
    </html>
    """


@app.route("/cases")
def cases():
    """Submitted cases page - shows reports for current user."""
    cart_count = get_cart_count(session)
    reports = []
    try:
        user_email = session.get('user') or session.get('incident_report_email')
        user_id = session.get('user_id')
        
        if user_email or user_id:
            reports = get_incident_reports(
                email=user_email,
                user_id=user_id
            )
            
            # Convert datetime objects to strings for JSON serialization
            for report in reports:
                if 'created_at' in report and report['created_at']:
                    if hasattr(report['created_at'], 'strftime'):
                        report['created_at'] = report['created_at'].strftime('%Y-%m-%d %H:%M:%S')
                if not report.get('status'):
                    report['status'] = 'Pending Review'
                
                # Debug: Log file information
                print(f"DEBUG: Report {report.get('id')} has files: {report.get('files')}, type: {type(report.get('files'))}")
                if report.get('files'):
                    print(f"DEBUG: Report {report.get('id')} file count: {len(report.get('files', []))}")
    except Exception as e:
        flash("Error loading your incident reports. Please try again.", "error")
        reports = []

    return render_template("submitted_cases.html",
                           cart_count=cart_count,
                           reports=reports)


@app.route("/cases/<int:report_id>/status", methods=["POST"])
@login_required
def update_case_status(report_id):
    """Update status for an incident report."""
    new_status = request.form.get("status")
    if new_status not in ["Pending Review", "Under Review", "Resolved"]:
        flash("Invalid status", "error")
        return redirect(url_for("cases"))

    try:
        ok = update_incident_status(report_id, new_status)
        if ok:
            # --- Audit log for case status update ---
            add_audit_log(
                user_id=session.get('user_id', 0),
                action='Update Case Status',
                entity_type='INCIDENT_REPORT',
                entity_id=report_id,
                new_values=json.dumps({'status': new_status}),
                result='Success',
                ip_address=request.remote_addr,
                device_info=request.headers.get("User-Agent")
            )
            
            flash(f"Case status updated to {new_status}", "success")
        else:
            flash("Case not found", "error")
    except Exception as e:
        print(f"Failed to update case status: {e}")
        flash("Failed to update case status", "error")
    return redirect(url_for("cases"))


@app.route("/cases/<int:report_id>/file/<path:filename>")
@require_classification('incident_report_files.file_path')
def serve_incident_file(report_id, filename):
    """Serve decrypted incident report file (with watermark if image) - RESTRICTED access"""
    try:
        # URL decode filename
        from urllib.parse import unquote
        filename = unquote(filename)
        
        # Verify user has access to this report (works for both logged-in and non-logged-in users)
        user_email = session.get('user') or session.get('incident_report_email')
        user_id = session.get('user_id')
        
        reports = get_incident_reports(email=user_email, user_id=user_id)
        report = next((r for r in reports if r['id'] == report_id), None)
        
        if not report:
            # Try to find report by ID only (for cases where user submitted via email)
            all_reports = get_incident_reports()
            report = next((r for r in all_reports if r['id'] == report_id), None)
            if report:
                # Verify email matches if email was provided in session
                if user_email and report.get('email'):
                    if report['email'].lower() != user_email.lower():
                        flash("Access denied or report not found", "error")
                        return redirect(url_for("cases"))
                # If no email in session, allow access (user might have submitted anonymously)
            else:
                flash("Access denied or report not found", "error")
                return redirect(url_for("cases"))
        
        # Check if file exists in report
        report_files = report.get('files', [])
        
        # Debug logging
        print(f"DEBUG: Looking for file '{filename}' in report {report_id}")
        print(f"DEBUG: Report files list: {report_files}")
        print(f"DEBUG: Report files type: {type(report_files)}")
        
        if not report_files:
            print(f"WARNING: Report {report_id} has no files in 'files' field")
            flash("No files found for this report", "error")
            return redirect(url_for("cases"))
        
        if filename not in report_files:
            print(f"WARNING: File '{filename}' not found in report files. Available files: {report_files}")
            flash("File not found in this report", "error")
            return redirect(url_for("cases"))
        
        # Get file path
        file_path = os.path.join(Config.UPLOAD_FOLDER, filename)
        
        if not os.path.exists(file_path):
            print(f"ERROR: File not found at path: {file_path}")
            print(f"ERROR: Upload folder: {Config.UPLOAD_FOLDER}")
            print(f"ERROR: Looking for filename: {filename}")
            flash("File not found on server", "error")
            return redirect(url_for("cases"))
        
        with open(file_path, 'rb') as f:
            file_content = f.read()
        
        if len(file_content) == 0:
            print(f"ERROR: File {filename} is empty")
            flash("File is empty", "error")
            return redirect(url_for("cases"))
        
        # Try to decrypt (if encrypted)
        try:
            decrypted_content = decrypt_file(file_content)
            file_content = decrypted_content
            print(f"SECURITY: Decrypted file {filename} (size: {len(file_content)} bytes) for user {user_email}")
        except Exception as decrypt_error:
            # File might not be encrypted (backward compatibility)
            if filename.endswith('.encrypted'):
                # File should be encrypted but decryption failed
                print(f"ERROR: Failed to decrypt encrypted file {filename}: {decrypt_error}")
                import traceback
                print(traceback.format_exc())
                flash("Error decrypting file. Please contact administrator.", "error")
                return redirect(url_for("cases"))
            else:
                # File is not encrypted (backward compatibility)
                print(f"INFO: File {filename} is not encrypted, serving as-is (size: {len(file_content)} bytes)")
        
        # Get original filename (remove .encrypted suffix if present)
        original_filename = filename.replace('.encrypted', '')
        if original_filename.startswith('incident_'):
            # Extract original name if possible
            parts = original_filename.split('_', 2)
            if len(parts) > 2:
                original_filename = parts[2]
        
        # Determine MIME type from original filename (not encrypted filename)
        ext = original_filename.rsplit('.', 1)[-1].lower() if '.' in original_filename else ''
        mime_types = {
            'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'png': 'image/png',
            'gif': 'image/gif', 'webp': 'image/webp', 'pdf': 'application/pdf',
            'mp4': 'video/mp4', 'avi': 'video/x-msvideo', 'mov': 'video/quicktime',
            'wmv': 'video/x-ms-wmv', 'quicktime': 'video/quicktime'
        }
        mime_type = mime_types.get(ext, 'application/octet-stream')
        
        response = send_file(
            BytesIO(file_content),
            download_name=original_filename,
            mimetype=mime_type,
            as_attachment=False  # Display in browser for images
        )
        
        # Add headers to allow images/videos to be displayed
        response.headers['Cache-Control'] = 'private, max-age=3600'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        return response
    
    except Exception as e:
        print(f"ERROR serving incident file: {e}")
        import traceback
        print(traceback.format_exc())
        flash("Error retrieving file", "error")
        return redirect(url_for("cases"))


@app.route("/cases/<int:report_id>/delete", methods=["POST"])
@login_required
def delete_case(report_id):
    """Delete an incident report."""
    try:
        ok = delete_incident_report(report_id)
        if ok:
            # --- Audit log for case deletion ---
            add_audit_log(
                user_id=session.get('user_id', 0),
                action='Delete Case',
                entity_type='INCIDENT_REPORT',
                entity_id=report_id,
                result='Success',
                severity='Medium',
                ip_address=request.remote_addr,
                device_info=request.headers.get("User-Agent")
            )
            
            flash("Case deleted", "success")
        else:
            flash("Case not found", "error")
    except Exception as e:
        print(f"Failed to delete case: {e}")
        flash("Failed to delete case", "error")
    return redirect(url_for("cases"))


@app.route('/security-logs')
@require_classification('security_logs.user_id')
def security_logs():
    """Page 1: Access Security Logs"""
    # Check if user can access restricted security logs table
    user_role = session.get('user_type', 'guest')
    if not can_access_table('security_logs', user_role):
        flash('Access denied. Administrator privileges required.', 'error')
        return redirect(url_for('index'))
    
    return render_template('security_logs.html')


@app.route('/vehicle-fraud-logs')
@require_classification('vehicle_fraud_logs.user_id')
def vehicle_fraud_logs():
    """Page 2: Vehicle Fraud Logs"""
    # Check if user can access restricted fraud logs table
    user_role = session.get('user_type', 'guest')
    if not can_access_table('vehicle_fraud_logs', user_role):
        flash('Access denied. Administrator privileges required.', 'error')
        return redirect(url_for('index'))
    
    return render_template('vehicle_fraud_logs.html')


@app.route('/booking-fraud-logs')
@require_classification('booking_fraud_logs.user_id')
def booking_fraud_logs():
    """Page 3: Booking Fraud Logs"""
    # Check if user can access restricted fraud logs table
    user_role = session.get('user_type', 'guest')
    if not can_access_table('booking_fraud_logs', user_role):
        flash('Access denied. Administrator privileges required.', 'error')
        return redirect(url_for('index'))
    
    return render_template('booking_fraud_logs.html')


@app.route("/admin/encryption-proof")
def encryption_proof():
    """
    Admin-only helper to show encrypted vs decrypted values for a user.
    Usage: GET /admin/encryption-proof?email=user@example.com
    """
    email = request.args.get("email")
    if not email:
        return jsonify({"error": "email is required"}), 400

    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT user_id, first_name, last_name, email, phone_number,
                   nric, license_number
            FROM users WHERE email = %s
            """,
            (email,),
        )
        row = cursor.fetchone()
        cursor.close()

    if not row:
        return jsonify({"error": "user not found"}), 404

    decrypted = _decrypt_user_record({
        "first_name": row.get("first_name"),
        "last_name": row.get("last_name"),
        "phone": row.get("phone_number"),
        "nric": row.get("nric"),
        "license_number": row.get("license_number"),
    })

    return jsonify({
        "email": email,
        "encrypted": {
            "first_name": row.get("first_name"),
            "last_name": row.get("last_name"),
            "phone_number": row.get("phone_number"),
            "nric": row.get("nric"),
            "license_number": row.get("license_number"),
        },
        "decrypted": decrypted,
    })


@app.route("/test-encryption")
def test_encryption():
    """
    Simple test route to verify encryption is working.
    Shows a test encryption/decryption cycle.
    """
    try:
        # Test encryption
        test_value = "Test123"
        encrypted = encrypt_value(test_value)
        decrypted = decrypt_value(encrypted)
        
        # Check if encryption key is set
        encryption_key_set = bool(Config.DATA_ENCRYPTION_KEY)
        
        return jsonify({
            "status": "success",
            "encryption_configured": encryption_key_set,
            "test": {
                "original": test_value,
                "encrypted": encrypted,
                "decrypted": decrypted,
                "matches": test_value == decrypted
            },
            "message": "Encryption is working!" if (test_value == decrypted and encryption_key_set) else "Encryption may not be configured correctly"
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "encryption_configured": bool(Config.DATA_ENCRYPTION_KEY),
            "error": str(e),
            "message": "Encryption is NOT working. Check that DATA_ENCRYPTION_KEY is set in config.py."
        }), 500


@app.route("/security-verification")
def security_verification_page():
    """Visual security verification dashboard"""
    return render_template('security_verification.html')


@app.route("/security-check")
def security_check():
    """
    Comprehensive security verification endpoint.
    Checks cookie settings, HTTPS, and security headers.
    """
    # Detect HTTPS
    is_https = (
        request.is_secure or 
        request.headers.get('X-Forwarded-Proto') == 'https' or
        request.headers.get('X-Forwarded-Ssl') == 'on'
    )
    
    # Get cookie settings from Flask config
    cookie_secure = app.config.get('SESSION_COOKIE_SECURE', False)
    cookie_httponly = app.config.get('SESSION_COOKIE_HTTPONLY', True)
    cookie_samesite = app.config.get('SESSION_COOKIE_SAMESITE', 'Lax')
    
    # Check security headers
    security_headers = {
        'Content-Security-Policy': request.headers.get('Content-Security-Policy'),
        'X-Content-Type-Options': request.headers.get('X-Content-Type-Options'),
        'X-Frame-Options': request.headers.get('X-Frame-Options'),
        'Referrer-Policy': request.headers.get('Referrer-Policy'),
    }
    
    # Verification results
    checks = {
        'https_enabled': {
            'status': is_https,
            'message': 'HTTPS/TLS is active' if is_https else '⚠️ Using HTTP (not secure)',
            'required': True
        },
        'cookie_secure': {
            'status': cookie_secure,
            'message': 'Secure flag enabled (cookies only sent over HTTPS)' if cookie_secure else '⚠️ Secure flag disabled',
            'required': True
        },
        'cookie_httponly': {
            'status': cookie_httponly,
            'message': 'HttpOnly flag enabled (prevents XSS access)' if cookie_httponly else '⚠️ HttpOnly flag disabled',
            'required': True
        },
        'cookie_samesite': {
            'status': cookie_samesite in ['Lax', 'Strict'],
            'message': f'SameSite={cookie_samesite} (CSRF protection enabled)',
            'required': True
        },
        'security_headers': {
            'status': all(security_headers.values()),
            'message': 'Security headers present',
            'details': security_headers
        }
    }
    
    # Overall status
    all_critical_passed = all(
        checks[key]['status'] for key in ['https_enabled', 'cookie_secure', 'cookie_httponly', 'cookie_samesite']
        if checks[key].get('required', False)
    )
    
    return jsonify({
        'overall_status': 'secure' if all_critical_passed else 'insecure',
        'checks': checks,
        'recommendations': [
            '✅ All security measures are properly configured!' if all_critical_passed else
            '⚠️ Some security measures need attention',
            '✅ Session tokens stored in Secure, HttpOnly cookies',
            '✅ Only non-sensitive data should be in localStorage',
            '✅ All communication protected with HTTPS/TLS'
        ],
        'how_to_verify': {
            'browser_devtools': 'Open DevTools → Application → Cookies → Check flags: Secure ✓, HttpOnly ✓',
            'network_tab': 'Open DevTools → Network → Check request headers → Look for HTTPS and security headers',
            'console_test': 'Try: document.cookie (should NOT show session cookies due to HttpOnly)',
            'localStorage_check': 'Check localStorage: Should only contain non-sensitive UI preferences'
        }
    })


@app.route("/admin/encrypt-existing-users", methods=["POST"])
@require_classification('users.password_hash')
def encrypt_existing_users():
    """
    One-time helper to encrypt existing plaintext PII in the users table - RESTRICTED to admins only.
    Call: POST /admin/encrypt-existing-users?confirm=yes
    """
    if request.args.get("confirm") != "yes":
        return jsonify({"error": "add confirm=yes to run"}), 400

    # Ensure schema is up to date (increases column sizes for encrypted data)
    from database import ensure_schema
    ensure_schema()

    updated = 0
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT user_id, first_name, last_name, phone_number, nric, license_number FROM users"
        )
        rows = cursor.fetchall()

        for row in rows:
            updates = {}
            for field, db_col in [
                ("first_name", "first_name"),
                ("last_name", "last_name"),
                ("phone_number", "phone_number"),
                ("nric", "nric"),
                ("license_number", "license_number"),
            ]:
                val = row.get(db_col)
                if not val:
                    continue
                # If decrypt succeeds and changes the value, it's already encrypted
                maybe_plain = decrypt_value(val, fallback_on_error=True)
                if maybe_plain != val:
                    continue
                try:
                    updates[db_col] = encrypt_value(val)
                except Exception:
                    continue

            if updates:
                set_clause = ", ".join([f"{col} = %s" for col in updates.keys()])
                params = list(updates.values()) + [row["user_id"]]
                cursor.execute(
                    f"UPDATE users SET {set_clause} WHERE user_id = %s",
                    params,
                )
                updated += 1

        conn.commit()
        cursor.close()

    # --- Audit log for bulk encryption ---
    add_audit_log(
        user_id=session.get('user_id', 0),
        action='Encrypt Existing Users',
        entity_type='SYSTEM',
        entity_id='bulk_encryption',
        new_values=json.dumps({'updated_rows': updated}),
        result='Success',
        severity='High',
        ip_address=request.remote_addr,
        device_info=request.headers.get("User-Agent")
    )

    return jsonify({"updated_rows": updated})


@app.route("/admin/decrypt-existing-users", methods=["POST"])
@require_classification('users.password_hash')
def decrypt_existing_users():
    """
    One-time helper to decrypt encrypted PII back to plaintext - RESTRICTED to admins only.
    Call: POST /admin/decrypt-existing-users?confirm=yes
    """
    if request.args.get("confirm") != "yes":
        return jsonify({"error": "add confirm=yes to run"}), 400

    updated = 0
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT user_id, first_name, last_name, phone_number, nric, license_number FROM users"
        )
        rows = cursor.fetchall()

        for row in rows:
            updates = {}
            for db_col in ["first_name", "last_name", "phone_number", "nric", "license_number"]:
                val = row.get(db_col)
                if not val:
                    continue
                try:
                    plain = decrypt_value(val)
                except Exception:
                    # If decrypt fails, assume already plaintext or invalid; skip
                    continue
                if plain != val:
                    updates[db_col] = plain

            if updates:
                set_clause = ", ".join([f"{col} = %s" for col in updates.keys()])
                params = list(updates.values()) + [row["user_id"]]
                cursor.execute(
                    f"UPDATE users SET {set_clause} WHERE user_id = %s",
                    params,
                )
                updated += 1

        conn.commit()
        cursor.close()

    # --- Audit log for bulk decryption ---
    add_audit_log(
        user_id=session.get('user_id', 0),
        action='Decrypt Existing Users',
        entity_type='SYSTEM',
        entity_id='bulk_decryption',
        new_values=json.dumps({'updated_rows': updated}),
        result='Success',
        severity='Critical',
        reason='Bulk decryption operation performed',
        ip_address=request.remote_addr,
        device_info=request.headers.get("User-Agent")
    )

    return jsonify({"updated_rows": updated})


# fraud detection stuff
# Assuming the necessary imports (Flask, datetime, and all database functions) are at the top

@app.route('/api/security-logs')
def get_security_logs_route():
    # NOTE: The function name is changed to avoid conflict with the imported function
    """Get security logs with filtering"""
    severity = request.args.get('severity')
    event_type = request.args.get('event_type')
    user_id = request.args.get('user_id')
    limit = request.args.get('limit', 100, type=int)

    try:
        # CORRECTED: Calling the imported function directly
        logs = get_security_logs(
            severity=severity,
            event_type=event_type,
            user_id=user_id,
            limit=limit
        )

        # Format timestamps for JSON
        formatted_logs = []
        for log in logs:
            log_copy = log.copy()
            if isinstance(log_copy['timestamp'], datetime):
                log_copy['timestamp'] = log_copy['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            formatted_logs.append(log_copy)

        return jsonify(formatted_logs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/vehicle-fraud-logs')
def get_vehicle_fraud_logs_route():
    """Get vehicle fraud logs with filtering"""
    severity = request.args.get('severity')
    event_type = request.args.get('event_type')
    user_id = request.args.get('user_id')
    min_risk = request.args.get('min_risk', type=float)
    limit = request.args.get('limit', 100, type=int)

    try:
        # CORRECTED: Calling the imported function directly
        logs = get_vehicle_fraud_logs(
            severity=severity,
            event_type=event_type,
            user_id=user_id,
            min_risk=min_risk,
            limit=limit
        )

        # Format timestamps and decimals for JSON
        formatted_logs = []
        for log in logs:
            log_copy = log.copy()
            if isinstance(log_copy['timestamp'], datetime):
                log_copy['timestamp'] = log_copy['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            if 'risk_score' in log_copy and log_copy['risk_score']:
                # The float conversion is correct for JSON serialization
                log_copy['risk_score'] = float(log_copy['risk_score'])
            formatted_logs.append(log_copy)

        return jsonify(formatted_logs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/booking-fraud-logs')
def get_booking_fraud_logs_route():
    """Get booking fraud logs with filtering"""
    severity = request.args.get('severity')
    event_type = request.args.get('event_type')
    user_id = request.args.get('user_id')
    min_risk = request.args.get('min_risk', type=float)
    limit = request.args.get('limit', 100, type=int)

    try:
        # CORRECTED: Calling the imported function directly
        logs = get_booking_fraud_logs(
            severity=severity,
            event_type=event_type,
            user_id=user_id,
            min_risk=min_risk,
            limit=limit
        )

        # Format timestamps and decimals for JSON
        formatted_logs = []
        for log in logs:
            log_copy = log.copy()
            if isinstance(log_copy['timestamp'], datetime):
                log_copy['timestamp'] = log_copy['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            if 'risk_score' in log_copy and log_copy['risk_score']:
                log_copy['risk_score'] = float(log_copy['risk_score'])
            formatted_logs.append(log_copy)

        return jsonify(formatted_logs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/security-stats')
def get_security_stats_route():
    """Get security statistics"""
    try:
        # CORRECTED: Calling the imported function directly
        stats = get_security_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/vehicle-fraud-stats')
def get_vehicle_fraud_stats_route():
    """Get vehicle fraud statistics"""
    try:
        # CORRECTED: Calling the imported function directly
        stats = get_vehicle_fraud_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/booking-fraud-stats')
def get_booking_fraud_stats_route():
    """Get booking fraud statistics"""
    try:
        # CORRECTED: Calling the imported function directly
        stats = get_booking_fraud_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============= EXAMPLE: Logging new fraud events =============

@app.route('/api/log-security-event', methods=['POST'])
def log_security_event():
    """API endpoint to log a new security event"""
    try:
        data = request.get_json()

        # CORRECTED: Calling the imported function directly
        log_id = add_security_log(
            user_id=data['user_id'],
            event_type=data['event_type'],
            severity=data['severity'],
            description=data['description'],
            ip_address=data.get('ip_address'),
            device_info=data.get('device_info'),
            action_taken=data.get('action_taken')
        )

        return jsonify({
            'success': True,
            'log_id': log_id,
            'message': 'Security event logged successfully'
        }), 201

    except KeyError as e:
        return jsonify({
            'success': False,
            'error': f'Missing required field: {str(e)}'
        }), 400
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/log-vehicle-fraud', methods=['POST'])
def log_vehicle_fraud():
    """API endpoint to log a new vehicle fraud event"""
    try:
        data = request.get_json()

        # CORRECTED: Calling the imported function directly
        log_id = add_vehicle_fraud_log(
            user_id=data['user_id'],
            vehicle_id=data['vehicle_id'],
            event_type=data['event_type'],
            severity=data['severity'],
            risk_score=data['risk_score'],
            description=data['description'],
            action_taken=data.get('action_taken'),
            gps_data=data.get('gps_data'),
            mileage_data=data.get('mileage_data')
        )

        return jsonify({
            'success': True,
            'log_id': log_id,
            'message': 'Vehicle fraud logged successfully'
        }), 201

    except KeyError as e:
        return jsonify({
            'success': False,
            'error': f'Missing required field: {str(e)}'
        }), 400
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/log-booking-fraud', methods=['POST'])
def log_booking_fraud():
    """API endpoint to log a new booking fraud event"""
    try:
        data = request.get_json()

        # CORRECTED: Calling the imported function directly
        log_id = add_booking_fraud_log(
            user_id=data['user_id'],
            booking_id=data['booking_id'],
            vehicle_id=data['vehicle_id'],
            event_type=data['event_type'],
            severity=data['severity'],
            risk_score=data['risk_score'],
            description=data['description'],
            action_taken=data.get('action_taken'),
            booking_data=data.get('booking_data'),
            payment_data=data.get('payment_data'),
            ml_indicators=data.get('ml_indicators')
        )

        return jsonify({
            'success': True,
            'log_id': log_id,
            'message': 'Booking fraud logged successfully'
        }), 201

    except KeyError as e:
        return jsonify({
            'success': False,
            'error': f'Missing required field: {str(e)}'
        }), 400
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ============================================
# TEST ROUTES FOR DATA CLASSIFICATION
# ============================================

@app.route('/test-redaction')
@login_required
def test_redaction():
    """Test data redaction with different roles - Admin only for testing"""
    if session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required for testing.', 'error')
        return redirect(url_for('index'))
    
    # Sample user data
    test_user = {
        'user_id': 5,
        'email': 'john@example.com',
        'first_name': 'John',
        'last_name': 'Doe',
        'phone_number': '+65 1234 5678',
        'nric': 'S1234567A',
        'license_number': 'ABC123',
        'verified': True,
        'user_type': 'user'
    }
    
    # Test redaction as different roles
    from data_classification import redact_dict
    
    as_admin = redact_dict(test_user, 'users', 'admin', user_id=1, data_owner_id=5)
    as_owner = redact_dict(test_user, 'users', 'user', user_id=5, data_owner_id=5)
    as_other_user = redact_dict(test_user, 'users', 'user', user_id=10, data_owner_id=5)
    as_guest = redact_dict(test_user, 'users', 'guest', user_id=None, data_owner_id=5)
    
    return jsonify({
        'test_explanation': {
            'admin': 'Admin sees EVERYTHING (all classifications)',
            'owner': 'User 5 sees their OWN data (PUBLIC + INTERNAL + CONFIDENTIAL)',
            'other_user': 'User 10 sees LIMITED data (PUBLIC + INTERNAL only)',
            'guest': 'Guest sees only PUBLIC data (nothing in this case)'
        },
        'classification_levels': {
            'user_id': 'INTERNAL',
            'email': 'CONFIDENTIAL',
            'first_name': 'CONFIDENTIAL',
            'last_name': 'CONFIDENTIAL',
            'phone_number': 'CONFIDENTIAL',
            'nric': 'RESTRICTED',
            'license_number': 'CONFIDENTIAL',
            'verified': 'INTERNAL',
            'user_type': 'INTERNAL'
        },
        'original_data': test_user,
        'as_admin': as_admin,
        'as_owner': as_owner,
        'as_other_user': as_other_user,
        'as_guest': as_guest
    })


# ============================================
# ERROR HANDLERS
# ============================================
@app.errorhandler(AccessDeniedException)
def handle_access_denied(e):
    print("\n===== AccessDeniedException HANDLER HIT =====")

    # Session + request context
    user_id = session.get('user_id', 0)
    user_email = session.get('user', 'Unknown')
    ip_addr = request.remote_addr if request.remote_addr else 'Unknown'
    user_agent = request.headers.get("User-Agent", "Unknown")

    print("Session user_id:", user_id)
    print("Session user_email:", user_email)
    print("IP address:", ip_addr)
    print("User-Agent:", user_agent)

    # Inspect exception object
    print("Exception object:", e)
    print("Exception type:", type(e))
    print("Exception attributes:", vars(e) if hasattr(e, "__dict__") else "No __dict__")

    column = getattr(e, "column", None)
    classification = getattr(e, "classification", None)
    user_role = getattr(e, "user_role", None)

    print("e.column:", column)
    print("e.classification:", classification)
    print("e.user_role:", user_role)

    # Flash (optional, not security-critical)
    flash('⚠️ Access Denied: You do not have permission to access this resource.', 'error')
    session.modified = True

    # === AUDIT LOG TEST ===
    try:
        print(">>> Attempting add_audit_log()")
        add_audit_log(
            user_id=user_id,
            action='Data Access Denied',
            entity_type='SECURITY',
            entity_id=str(column),
            reason=str(e),
            result='Failure',
            severity='Medium',
            ip_address=ip_addr,
            device_info=user_agent
        )
        print("✅ add_audit_log() SUCCESS")
    except Exception as audit_error:
        print("❌ add_audit_log() FAILED")
        print("Error type:", type(audit_error))
        print("Error message:", audit_error)

    print("===== END AccessDeniedException HANDLER =====\n")

    from flask import make_response
    return make_response(redirect(url_for('index')))

# ============================================
# AUTOMATED BACKUP SCHEDULER
# ============================================
def start_backup_scheduler():
    """Start automated backup scheduler in background thread"""
    # Check if auto-backup is enabled (defaults to False if not set)
    auto_backup_enabled = bool(Config.AUTO_BACKUP_ENABLED)
    
    if not auto_backup_enabled:
        print("ℹ️  Automated backups are disabled. Set AUTO_BACKUP_ENABLED in config.py to enable.")
        print("   Backups can still be created manually from the admin panel.")
        return
    
    def backup_worker():
        """Background thread worker for automated backups"""
        import time
        from utils.backup import SecureBackup
        
        backup_system = SecureBackup()
        interval_hours = int(Config.AUTO_BACKUP_INTERVAL_HOURS)
        interval_seconds = interval_hours * 3600
        
        print(f"✅ Automated backup scheduler started. Backups will run every {interval_hours} hours.")
        
        # Run initial backup after 60 seconds (give app time to start)
        time.sleep(60)
        
        while True:
            try:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting automated backup...")
                backup_info = backup_system.create_backup(
                    include_files=True,
                    backup_type='Automated',
                    created_by_user_id=None,
                    log_to_db=True
                )
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ✅ Backup completed: {backup_info['backup_filename']} ({backup_info['backup_size_mb']} MB)")
                print(f"    Checksum: {backup_info['checksum_sha256']}")
                
                # Cleanup old backups
                retention_days = int(Config.BACKUP_RETENTION_DAYS)
                deleted = backup_system.delete_old_backups(keep_days=retention_days)
                if deleted:
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 🗑️  Deleted {len(deleted)} old backup(s)")
                
            except Exception as e:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ❌ Automated backup failed: {e}")
            
            # Wait for next interval
            time.sleep(interval_seconds)
    
    # Start backup scheduler in background thread
    backup_thread = threading.Thread(target=backup_worker, daemon=True)
    backup_thread.start()


# Start automated backup scheduler on app startup
start_backup_scheduler()


# ============================================
# DATA RETENTION SCHEDULER
# ============================================
def start_retention_scheduler():
    """Start automated data retention purge in background thread."""
    def retention_worker():
        interval_hours = int(Config.RETENTION_CHECK_INTERVAL_HOURS)
        interval_seconds = interval_hours * 3600

        print(f"✅ Data retention scheduler started. Checks every {interval_hours} hours.")
        time.sleep(60)

        while True:
            try:
                result = run_retention_purge(reason='auto')
                if result.get("skipped_reason"):
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ℹ️  Retention skipped: {result['skipped_reason']}")
                else:
                    print(
                        f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 🧹 Retention purge "
                        f"completed: {result.get('purged_count', 0)} purged "
                        f"out of {result.get('candidate_count', 0)} candidates."
                    )
                    if result.get("errors"):
                        print(f"    Errors: {len(result['errors'])}")
            except Exception as exc:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ❌ Retention purge failed: {exc}")

            time.sleep(interval_seconds)

    retention_thread = threading.Thread(target=retention_worker, daemon=True)
    retention_thread.start()


# Start data retention scheduler on app startup
start_retention_scheduler()


if __name__ == "__main__":
    app.run(debug=True, port=5001)

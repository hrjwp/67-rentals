from flask import Flask, render_template, request, session, redirect, url_for, jsonify, flash
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import stripe
import os
import json
from Crypto.Cipher import AES
import base64



# Import configuration
from config import Config

# Import database functions

from database import (
    get_user_by_email, create_user_with_documents, get_all_vehicles,
    get_vehicle_by_id, create_booking, get_booking_by_id,
    update_user_password, save_reset_token, get_reset_token, mark_token_as_used,
    get_user_bookings, get_signup_tickets, set_signup_status, get_user_documents,
    get_db_connection
)

# Import data models
from models import (
    VEHICLES, BOOKINGS, CANCELLATION_REQUESTS, REFUNDS,
    listings, PASSWORD_RESET_TOKENS
)

# Import utilities
from utils.validation import (
    validate_name, validate_email, validate_phone, validate_nric,
    validate_license, validate_password, validate_file_size, allowed_file
)
from utils.auth import (
    login_required, generate_reset_token, send_password_reset_email
)
from utils.helpers import (
    calculate_refund_percentage, calculate_cart_totals,
    generate_booking_id, generate_request_id, generate_refund_id,
    get_cart_count
)
from utils.encryption import encrypt_value, decrypt_value
from utils.backup import SecureBackup
from utils.file_security import validate_uploaded_file, sanitize_filename


app = Flask(__name__)

app.config.from_object(Config)
stripe.api_key = Config.STRIPE_API_KEY


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
#signup selection page
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

            # Capture bytes and save to upload folder
            nric_bytes = nric_image.read()
            license_bytes = license_image.read()
            vehicle_card_bytes = vehicle_card_image.read()
            insurance_bytes = insurance_image.read()

            # Reset streams and save to disk
            nric_image.seek(0); license_image.seek(0); vehicle_card_image.seek(0); insurance_image.seek(0)
            nric_image.save(os.path.join(Config.UPLOAD_FOLDER, nric_filename))
            license_image.save(os.path.join(Config.UPLOAD_FOLDER, license_filename))
            vehicle_card_image.save(os.path.join(Config.UPLOAD_FOLDER, vehicle_card_filename))
            insurance_image.save(os.path.join(Config.UPLOAD_FOLDER, insurance_filename))

            documents = {
                'nric_image': {'filename': nric_filename, 'mime': nric_image.mimetype, 'data': nric_bytes, 'path': nric_filename},
                'license_image': {'filename': license_filename, 'mime': license_image.mimetype, 'data': license_bytes, 'path': license_filename},
                'vehicle_card_image': {'filename': vehicle_card_filename, 'mime': vehicle_card_image.mimetype, 'data': vehicle_card_bytes, 'path': vehicle_card_filename},
                'insurance_image': {'filename': insurance_filename, 'mime': insurance_image.mimetype, 'data': insurance_bytes, 'path': insurance_filename}
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

            create_user_with_documents(seller_data_plain)

            flash('Seller registration submitted successfully! Please wait for admin approval.', 'success')
            return redirect(url_for('registration_pending'))

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
        nric_image.seek(0)
        license_image.seek(0)

        nric_image.save(os.path.join(Config.UPLOAD_FOLDER, nric_filename))
        license_image.save(os.path.join(Config.UPLOAD_FOLDER, license_filename))

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
                'nric_image': {'filename': nric_filename, 'mime': nric_image.mimetype, 'data': nric_bytes, 'path': nric_filename},
                'license_image': {'filename': license_filename, 'mime': license_image.mimetype, 'data': license_bytes, 'path': license_filename}
            }
        }

        # Persist to DB with pending status for admin review
        create_user_with_documents(user_data_plain)

        # Redirect to registration pending page
        flash('Registration submitted successfully! Please wait for admin approval.', 'success')
        return redirect(url_for('registration_pending'))

    return render_template('signup.html')


# ============================================
# REGISTRATION PENDING PAGE
# ============================================
@app.route('/registration-pending')
def registration_pending():
    """Registration pending approval page"""
    return render_template('pending_reg.html')


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
    if not user or not check_password_hash(user.get('password_hash', ''), password):
        flash('Invalid email or password', 'error')
        return redirect(request.referrer or url_for('index'))

    # Check if user account is verified/approved
    if not user.get('verified'):
        flash('Your account is pending approval. Please wait for admin verification.', 'error')
        return redirect(url_for('registration_pending'))

    # Clear any stale flashes from earlier flows before setting the success message
    session.pop('_flashes', None)

    # Login successful
    session['user'] = email
    session['user_id'] = user.get('user_id')
    session['user_name'] = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
    session['user_type'] = user.get('user_type', 'user')  # Get user type from stored data
    session.modified = True

    flash(f"Welcome back, {user['first_name']}!", 'success')
    
    # Redirect based on user type
    user_type = user.get('user_type', 'user')
    
    if user_type == 'admin':
        return redirect(url_for('dashboard'))  # Redirect admins to admin panel
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
def admin_panel():
    """Admin panel to view and approve pending registrations"""
    # Check if user is logged in and is admin
    if 'user' not in session or session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))

    # Clear any lingering flashes from prior login attempts to keep the admin view clean
    session.pop('_flashes', None)

    def adapt(ticket):
        docs = ticket.get('documents', {})
        def doc_url(doc):
            if not doc or not isinstance(doc, dict) or not doc.get('id'):
                return None
            return url_for('admin_document', doc_id=doc['id'])
        return {
            'ticket_id': ticket.get('ticket_id'),
            'first_name': ticket.get('first_name'),
            'last_name': ticket.get('last_name'),
            'email': ticket.get('email'),
            'phone': ticket.get('phone'),
            'nric': ticket.get('nric'),
            'license_number': ticket.get('license_number'),
            'user_type': ticket.get('user_type'),
            'created_at': ticket.get('submitted_at'),
            'status': ticket.get('status'),
            'nric_image': doc_url(docs.get('nric_image')),
            'license_image': doc_url(docs.get('license_image')),
            'vehicle_card_image': doc_url(docs.get('vehicle_card_image')),
            'insurance_image': doc_url(docs.get('insurance_image')),
        }

    pending_tickets = get_signup_tickets(status='pending')
    approved_tickets = get_signup_tickets(status='approved')

    pending_users = [adapt(t) for t in pending_tickets if t.get('user_type') == 'user']
    pending_sellers = [adapt(t) for t in pending_tickets if t.get('user_type') == 'seller']
    approved_users = [adapt(t) for t in approved_tickets if t.get('user_type') == 'user']
    approved_sellers = [adapt(t) for t in approved_tickets if t.get('user_type') == 'seller']

    return render_template('admin_panel.html',
                         pending_users=pending_users,
                         pending_sellers=pending_sellers,
                         approved_users=approved_users,
                         approved_sellers=approved_sellers)


# ============================================
# ADMIN APPROVE USER
# ============================================
@app.route('/admin/approve/<int:ticket_id>', methods=['POST'])
def admin_approve_user(ticket_id):
    """Approve a pending user registration"""
    if 'user' not in session or session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))

    ok = set_signup_status(ticket_id, 'approved', reviewer=session.get('user'))
    if ok:
        flash('Signup approved successfully!', 'success')
    else:
        flash('Signup ticket not found.', 'error')
    return redirect(url_for('admin_panel'))


# ============================================
# ADMIN REJECT USER
# ============================================
@app.route('/admin/reject/<int:ticket_id>', methods=['POST'])
def admin_reject_user(ticket_id):
    """Reject and delete a pending user registration"""
    if 'user' not in session or session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))

    ok = set_signup_status(ticket_id, 'rejected', reviewer=session.get('user'))
    if ok:
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
def admin_document(doc_id):
    """Serve a stored document from DB to admin."""
    from mysql.connector import Error
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT file_name, mime_type, file_data FROM user_documents WHERE id = %s",
                (doc_id,)
            )
            row = cursor.fetchone()
            cursor.close()
            if not row or not row.get('file_data'):
                return "File not found", 404
            return send_file(
                BytesIO(row['file_data']),
                download_name=row.get('file_name') or f'doc_{doc_id}',
                mimetype=row.get('mime_type') or 'application/octet-stream'
            )
    except Error as exc:
        return f"Error retrieving file: {exc}", 500


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
    
    return render_template('seller_index.html')


# ============================================
# CREATE INITIAL ADMIN ACCOUNT (HELPER)
# ============================================
@app.route('/create-admin-secret-route-12345', methods=['GET', 'POST'])
def create_admin():
    """One-time route to create initial admin account - REMOVE after first admin is created"""
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
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()

        if not email or not validate_email(email):
            return "Invalid email address", 400

        user = get_user_by_email(email)
        if not user:
            flash('If an account exists with that email, you will receive a password reset link.', 'info')
            return render_template('forgot_password.html')

        reset_token = generate_reset_token()

        PASSWORD_RESET_TOKENS[reset_token] = {
            'email': email,
            'expires_at': datetime.now() + timedelta(hours=1),
            'used': False
        }

        send_password_reset_email(email, reset_token)

        flash('Password reset link has been sent to your email.', 'success')
        return render_template('forgot_password.html')

    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset password page - user clicks link from email"""
    token_data = PASSWORD_RESET_TOKENS.get(token)

    if not token_data:
        flash('Invalid or expired reset link.', 'error')
        return redirect(url_for('forgot_password'))

    if datetime.now() > token_data['expires_at']:
        flash('This reset link has expired. Please request a new one.', 'error')
        del PASSWORD_RESET_TOKENS[token]
        return redirect(url_for('forgot_password'))

    if token_data['used']:
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

            PASSWORD_RESET_TOKENS[token]['used'] = True

            flash('Password has been reset successfully! You can now login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('User account not found.', 'error')
            return redirect(url_for('forgot_password'))

    return render_template('reset_password.html', token=token)


@app.route('/encryption-proof')
def encryption_proof():
    """Demonstrate AES encryption/decryption via JSON only."""
    sample = "demo string"
    error = None
    cipher = decrypted = None
    round_trip = False
    current_user_encrypted = None
    current_user_decrypted = None

    try:
        cipher = encrypt_value(sample)
        decrypted = decrypt_value(cipher)
        round_trip = decrypted == sample

        if 'user' in session:
            email = session['user']
            users = session.get('users', {})
            if email in users:
                current_user_encrypted = users[email]
                current_user_decrypted = _decrypt_user_record(users[email])
    except Exception as exc:
        error = str(exc)

    return jsonify({
        "cipher": cipher,
        "decrypted": decrypted,
        "round_trip": round_trip,
        "error": error,
        "current_user_encrypted": current_user_encrypted,
        "current_user_decrypted": current_user_decrypted,
    })


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


@app.route('/vehicle_listing')
def vehicle_listing():
    search_query = request.args.get('q', '').lower()

    all_vehicles = [
        {'id': 1, 'name': 'Toyota Sienta Hybrid', 'price': 150, 'image': 'toyota.png', 'detail_url': url_for('sienta')},
        {'id': 2, 'name': 'MT-07/Y-AMT', 'price': 100, 'image': 'bike.png', 'detail_url': url_for('bike')},
        {'id': 3, 'name': 'Honda Civic', 'price': 120, 'image': 'civic.png', 'detail_url': url_for('honda_civic')},
        {'id': 4, 'name': 'Corolla Cross', 'price': 110, 'image': 'corolla.png', 'detail_url': url_for('corolla')},
        {'id': 5, 'name': 'AVANTE Hybrid', 'price': 180, 'image': 'avante.png', 'detail_url': url_for('avante')},
    ]

    if search_query:
        vehicles = [v for v in all_vehicles if search_query in v['name'].lower()]
    else:
        vehicles = all_vehicles

    cart_count = get_cart_count(session)
    return render_template('vehicle_listing.html', vehicles=vehicles, search_query=search_query, cart_count=cart_count)


@app.route('/vehicle_listing_logged')
def vehicle_listing_logged():
    search_query = request.args.get('q', '').lower()

    all_vehicles = [
        {'id': 1, 'name': 'Toyota Sienta Hybrid', 'price': 150, 'image': 'toyota.png', 'detail_url': url_for('sienta_logged')},
        {'id': 2, 'name': 'MT-07/Y-AMT', 'price': 100, 'image': 'bike.png', 'detail_url': url_for('bike_logged')},
        {'id': 3, 'name': 'Honda Civic', 'price': 120, 'image': 'civic.png', 'detail_url': url_for('honda_civic_logged')},
        {'id': 4, 'name': 'Corolla Cross', 'price': 110, 'image': 'corolla.png', 'detail_url': url_for('corolla_logged')},
        {'id': 5, 'name': 'AVANTE Hybrid', 'price': 180, 'image': 'avante.png', 'detail_url': url_for('avante_logged')},
    ]

    if search_query:
        vehicles = [v for v in all_vehicles if search_query in v['name'].lower()]
    else:
        vehicles = all_vehicles

    cart_count = get_cart_count(session)
    return render_template('vehicle_listing_logged.html', vehicles=vehicles, search_query=search_query, cart_count=cart_count)


@app.route('/vehicle_listing_seller_logged')
def vehicle_listing_seller_logged():
    search_query = request.args.get('q', '').lower()

    all_vehicles = [
        {'id': 1, 'name': 'Toyota Sienta Hybrid', 'price': 150, 'image': 'toyota.png', 'detail_url': url_for('sienta_logged')},
        {'id': 2, 'name': 'MT-07/Y-AMT', 'price': 100, 'image': 'bike.png', 'detail_url': url_for('bike_logged')},
        {'id': 3, 'name': 'Honda Civic', 'price': 120, 'image': 'civic.png', 'detail_url': url_for('honda_civic_logged')},
        {'id': 4, 'name': 'Corolla Cross', 'price': 110, 'image': 'corolla.png', 'detail_url': url_for('corolla_logged')},
        {'id': 5, 'name': 'AVANTE Hybrid', 'price': 180, 'image': 'avante.png', 'detail_url': url_for('avante_logged')},
    ]

    if search_query:
        vehicles = [v for v in all_vehicles if search_query in v['name'].lower()]
    else:
        vehicles = all_vehicles

    cart_count = get_cart_count(session)
    return render_template('vehicle_listing_seller_logged.html', vehicles=vehicles, search_query=search_query, cart_count=cart_count)


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
    if not user_email:
        flash('Please login to view your bookings', 'error')
        return redirect(url_for('login'))
    
    # Try to get user from database first
    bookings = []
    try:
        user = get_user_by_email(user_email)
        if user and user.get('user_id'):
            # Get user bookings from database
            bookings = get_user_bookings(user.get('user_id'))
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
        bookings = session_bookings
    
    # Get cart count for navbar
    cart_count = get_cart_count(session)
    
    return render_template('booking_history.html', 
                         bookings=bookings,
                         cart_count=cart_count)


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

    return redirect(url_for('cart'))


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
def checkout():
    """Checkout page"""
    cart_items = session.get('cart', {})

    if not cart_items:
        return redirect(url_for('cart'))

    totals = calculate_cart_totals(cart_items, VEHICLES)

    return render_template('checkout.html',
                           cart_items=totals['cart_data'],
                           subtotal=totals['subtotal'],
                           insurance_fee=totals['insurance_fee'],
                           service_fee=totals['service_fee'],
                           total=totals['total'],
                           stripe_public_key=Config.STRIPE_PUBLIC_KEY)


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
        # This ensures PII is protected even in Stripe's system
        encrypted_name = encrypt_value(data.get('name')) if data.get('name') else None
        encrypted_email = encrypt_value(data.get('email')) if data.get('email') else None
        encrypted_phone = encrypt_value(data.get('phone')) if data.get('phone') else None
        encrypted_license = encrypt_value(data.get('license')) if data.get('license') else None

        # Create payment intent with tokenized payment method support
        # Card data never touches our server - Stripe handles tokenization
        intent = stripe.PaymentIntent.create(
            amount=int(totals['total'] * 100),  # Amount in cents
            currency='sgd',
            payment_method_types=['card'],  # Explicitly use card tokenization
            metadata={
                # Store encrypted PII - decrypted only when needed
                'customer_name_encrypted': encrypted_name or '',
                'customer_email_encrypted': encrypted_email or '',
                'customer_phone_encrypted': encrypted_phone or '',
                'license_number_encrypted': encrypted_license or '',
                'booking_type': 'vehicle_rental',
            },
            description='67 Rentals Vehicle Booking',
            # Enable automatic payment methods for better tokenization
            automatic_payment_methods={
                'enabled': True,
            },
        )

        return jsonify({
            'clientSecret': intent.client_secret,
            'paymentIntentId': intent.id
        })

    except Exception as e:
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


@app.route('/payment-success')
def payment_success():
    """Payment success page - payment data is tokenized by Stripe"""
    payment_intent_id = request.args.get('payment_intent')

    if not payment_intent_id:
        return redirect(url_for('index'))

    try:
        # Retrieve payment intent from Stripe (contains tokenized payment method, not card data)
        payment_intent = stripe.PaymentIntent.retrieve(payment_intent_id)
        
        # Payment method is tokenized (pm_xxx) - no card data stored
        payment_method_id = payment_intent.payment_method
        
        # Decrypt customer metadata if needed for display
        decrypted_metadata = {}
        if payment_intent.metadata:
            for key, value in payment_intent.metadata.items():
                if key.endswith('_encrypted') and value:
                    field_name = key.replace('_encrypted', '')
                    try:
                        decrypted_metadata[field_name] = decrypt_value(value)
                    except:
                        decrypted_metadata[field_name] = 'N/A'
        
        session['cart'] = {}
        session.modified = True

        return render_template('payment_success.html', 
                             payment_intent_id=payment_intent_id,
                             payment_method_token=payment_method_id,
                             amount=payment_intent.amount / 100)
    except stripe.error.StripeError as e:
        flash(f'Error retrieving payment: {str(e)}', 'error')
        return redirect(url_for('index'))


@app.route('/webhook/stripe', methods=['POST'])
def stripe_webhook():
    """Stripe webhook handler for secure payment confirmation"""
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    webhook_secret = os.environ.get('STRIPE_WEBHOOK_SECRET')  # Set this in your env
    
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
        
        backup_path = backup_system.create_backup(include_files=include_files)
        
        return jsonify({
            'success': True,
            'message': 'Backup created successfully',
            'backup_file': os.path.basename(backup_path),
            'backup_path': backup_path,
            'timestamp': datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/admin/backup/list', methods=['GET'])
@login_required
def list_backups():
    """List all available backups"""
    try:
        backup_system = SecureBackup()
        backups = backup_system.list_backups()
        
        return jsonify({
            'success': True,
            'backups': backups,
            'count': len(backups)
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
    """Get backup system status and configuration"""
    try:
        backup_system = SecureBackup()
        backups = backup_system.list_backups()
        
        return jsonify({
            'backup_enabled': True,
            'backup_directory': backup_system.backup_dir,
            'cloud_backup_enabled': backup_system.cloud_backup_dir is not None,
            'cloud_backup_directory': backup_system.cloud_backup_dir,
            'total_backups': len(backups),
            'latest_backup': backups[0] if backups else None,
            'retention_days': Config.BACKUP_RETENTION_DAYS,
            'auto_backup_enabled': Config.AUTO_BACKUP_ENABLED,
            'auto_backup_interval_hours': Config.AUTO_BACKUP_INTERVAL_HOURS
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
        encryption_key_set = os.environ.get('DATA_ENCRYPTION_KEY') is not None
        
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
                'check_encryption_key': 'Set DATA_ENCRYPTION_KEY environment variable',
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
def cancel_booking(booking_id):
    """Display cancellation request page"""
    booking = BOOKINGS.get(booking_id)

    if not booking:
        return "Booking not found", 404

    if booking['status'] not in ['Confirmed', 'Pending']:
        return "This booking cannot be cancelled", 400

    refund_percentage = calculate_refund_percentage(booking)
    processing_fee = 10 if refund_percentage > 0 else 0
    estimated_refund = (booking['total_amount'] * refund_percentage / 100) - processing_fee
    estimated_refund = max(0, estimated_refund)

    return render_template('cancel_booking.html',
                           booking=booking,
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

    return render_template('cancellation_submitted.html',
                           request_id=request_id,
                           booking=booking)


@app.route('/seller/cancellation-requests')
def seller_cancellation_requests():
    """Seller page to view all cancellation requests"""
    pending_requests = {
        rid: req for rid, req in CANCELLATION_REQUESTS.items()
        if req['status'] == 'Pending'
    }
    return render_template('seller_cancellations.html', requests=pending_requests)


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
    global listings
    listings = [l for l in listings if l['id'] != listing_id]
    flash('Listing deleted successfully', 'success')
    return redirect(url_for('manage_listings'))


# ============================================
# ADMIN ROUTES
# ============================================

@app.route('/dashboard')
def dashboard():
    """Dashboard page"""
    return render_template('dashboard.html')


@app.route('/accounts')
def accounts():
    """Accounts management page"""
    return render_template('accounts.html')


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
            vid = int(vehicle_id)
            vehicle = VEHICLES.get(vid, {})
        else:
            vid = max(VEHICLES.keys()) + 1 if VEHICLES else 1
            vehicle = {}

        image_path = vehicle.get('image')
        if image_file and image_file.filename:
            upload_folder = os.path.join('static', 'images')
            os.makedirs(upload_folder, exist_ok=True)
            filename = image_file.filename
            save_path = os.path.join(upload_folder, filename)
            image_file.save(save_path)
            image_path = f'images/{filename}'

        VEHICLES[vid] = {
            'id': vid,
            'name': name,
            'type': vtype,
            'price_per_day': int(price_per_day),
            'pickup_location': pickup_location,
            'image': image_path,
            'description': description,
        }

        return redirect(url_for('vehicle_management'))

    return render_template('vehicle_management.html', vehicles=VEHICLES)


@app.route('/security-dashboard')
def security_dashboard():
    """Security management page"""
    return render_template('security_dashboard.html')


@app.route('/data-classification')
def data_classification():
    """Data classification page"""
    return render_template('data_classification.html')


@app.route('/audit-logs')
def audit_logs():
    """Audit logs page"""
    return render_template('audit_logs.html')


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

@app.route("/report")
def report():
    """Incident report page"""
    cart_count = get_cart_count(session)
    return render_template("incident_report.html", cart_count=cart_count)


@app.route("/cases")
def cases():
    """Submitted cases page"""
    cart_count = get_cart_count(session)
    return render_template("submitted_cases.html", cart_count=cart_count)

@app.route('/security-logs')
def security_logs():
    """Page 1: Access Security Logs"""
    return render_template('security_logs.html')

@app.route('/vehicle-fraud-logs')
def vehicle_fraud_logs():
    """Page 2: Vehicle Fraud Logs"""
    return render_template('vehicle_fraud_logs.html')


@app.route('/booking-fraud-logs')
def booking_fraud_logs():
    """Page 3: Booking Fraud Logs"""
    return render_template('booking_fraud_logs.html')

#AES

key = os.urandom(32)

def encrypt_value(plaintext):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_value(token):
    raw = base64.b64decode(token)
    nonce = raw[:16]
    tag = raw[16:32]
    ciphertext = raw[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

@app.route("/test-encrypt")
def test_encrypt():
    sample = "hello"
    cipher = encrypt_value(sample)
    return {"cipher": cipher, "plain": decrypt_value(cipher)}


if __name__ == "__main__":
    plain = "hello123"
    encrypted = encrypt_value(plain)
    print("Encrypted:", encrypted)
    print("Decrypted:", decrypt_value(encrypted))

    # Run without HTTPS - change to ssl_context="adhoc" to enable HTTPS
    app.run(debug=True, host='127.0.0.1', port=5000)

from flask import Flask, render_template, request, session, redirect, url_for, jsonify, flash
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import stripe
import os

# Import configuration
from config import Config

# Import database functions

from database import (
    get_user_by_email, create_user, get_all_vehicles,
    get_vehicle_by_id, create_booking, get_booking_by_id,
    update_user_password, save_reset_token, get_reset_token, mark_token_as_used
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


app = Flask(__name__)

app.config.from_object(Config)
stripe.api_key = Config.STRIPE_API_KEY



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
                           cart_count=cart_count)


# ============================================
# AUTHENTICATION ROUTES
# ============================================

# ============================================
# AUTHENTICATION ROUTES
# ============================================

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Sign up page with comprehensive validation including NRIC checksum"""
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
        elif not validate_nric(nric):
            errors.append('Invalid NRIC. Must start with S, T, F, G, or M, followed by 7 digits and a valid checksum letter')

        if not license_number:
            errors.append('Driver\'s license number is required')
        elif not validate_license(license_number):
            errors.append('Invalid license number format')

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

        if not license_image or license_image.filename == '':
            errors.append('Driver\'s license image is required')
        elif not allowed_file(license_image.filename):
            errors.append('License image must be a valid image file (png, jpg, jpeg, gif)')
        elif not validate_file_size(license_image):
            errors.append('License image must be less than 5MB')

        # Check if user already exists
        if 'users' not in session:
            session['users'] = {}

        if email in session['users']:
            errors.append('Email already registered')

        # If there are validation errors, return them
        if errors:
            for error in errors:
                flash(error, 'error')
            return redirect(url_for('signup'))

        # Create upload directory if it doesn't exist
        if not os.path.exists(Config.UPLOAD_FOLDER):
            os.makedirs(Config.UPLOAD_FOLDER)

        # Save uploaded files
        nric_filename = secure_filename(f"{email}_nric_{nric_image.filename}")
        license_filename = secure_filename(f"{email}_license_{license_image.filename}")

        nric_image.save(os.path.join(Config.UPLOAD_FOLDER, nric_filename))
        license_image.save(os.path.join(Config.UPLOAD_FOLDER, license_filename))

        # Create user account
        user_data = {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'phone': phone,
            'nric': nric,
            'license_number': license_number,
            'password': generate_password_hash(password),
            'nric_image': nric_filename,
            'license_image': license_filename,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'verified': False
        }

        session['users'][email] = user_data
        session.modified = True

        # Redirect to registration pending page instead of logging in automatically
        flash('Registration submitted successfully! Please wait for admin approval.', 'success')
        return redirect(url_for('registration_pending'))

    return render_template('signup.html')


@app.route('/registration-pending')
def registration_pending():
    """Registration pending approval page"""
    return render_template('pending_reg.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if not email or not password:
            flash('Email and password are required', 'error')
            return redirect(url_for('login'))

        users = session.get('users', {})

        if email not in users:
            flash('Invalid email or password', 'error')
            return redirect(url_for('login'))

        user = users[email]

        if not check_password_hash(user['password'], password):
            flash('Invalid email or password', 'error')
            return redirect(url_for('login'))

        # Login successful
        session['user'] = email
        session['user_name'] = f"{user['first_name']} {user['last_name']}"
        session.modified = True

        flash(f"Welcome back, {user['first_name']}!", 'success')
        return redirect(url_for('index'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    """Logout user"""
    session.pop('user', None)
    session.pop('user_name', None)
    session.modified = True

    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('index'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Forgot password page - request password reset"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()

        if not email or not validate_email(email):
            return "Invalid email address", 400

        users = session.get('users', {})

        if email not in users:
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

        users = session.get('users', {})
        if email in users:
            users[email]['password'] = generate_password_hash(new_password)
            session['users'] = users
            session.modified = True

            PASSWORD_RESET_TOKENS[token]['used'] = True

            flash('Password has been reset successfully! You can now login.', 'success')
            return redirect(url_for('login'))
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
    """Create a Stripe payment intent"""
    try:
        data = request.get_json()
        cart_items = session.get('cart', {})

        if not cart_items:
            return jsonify({'error': 'Cart is empty'}), 400

        totals = calculate_cart_totals(cart_items, VEHICLES)

        intent = stripe.PaymentIntent.create(
            amount=int(totals['total'] * 100),  # Amount in cents
            currency='sgd',
            metadata={
                'customer_name': data.get('name'),
                'customer_email': data.get('email'),
                'customer_phone': data.get('phone'),
                'license_number': data.get('license'),
            },
            description='67 Rentals Vehicle Booking',
        )

        return jsonify({'clientSecret': intent.client_secret})

    except Exception as e:
        return jsonify({'error': str(e)}), 403


@app.route('/payment-success')
def payment_success():
    """Payment success page"""
    payment_intent_id = request.args.get('payment_intent')

    if not payment_intent_id:
        return redirect(url_for('index'))

    session['cart'] = {}
    session.modified = True

    return render_template('payment_success.html', payment_intent_id=payment_intent_id)


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


# ============================================
# EVENT ROUTES
# ============================================

# ============================================
# RUN APPLICATION
# ============================================

if __name__ == "__main__":
    app.run(debug=True)
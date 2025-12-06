# This file makes utils a Python package
# You can leave it empty or import commonly used functions

from .validation import (
    validate_name,
    validate_email,
    validate_phone,
    validate_nric,
    validate_license,
    validate_password,
    validate_file_size,
    allowed_file
)

from .auth import (
    login_required,
    seller_required,
    generate_reset_token,
    send_password_reset_email
)

from .helpers import (
    calculate_refund_percentage,
    calculate_rental_days,
    calculate_cart_totals,
    generate_booking_id,
    generate_request_id,
    generate_refund_id,
    format_currency,
    get_cart_count
)
from datetime import datetime

def calculate_refund_percentage(booking):
    """
    Calculate refund percentage based on cancellation policy
    - More than 7 days before pickup: 100% refund
    - 3-7 days before pickup: 50% refund
    - Less than 3 days before pickup: No refund
    """
    pickup_date = datetime.strptime(booking['pickup_date'], '%Y-%m-%d')
    today = datetime.now()
    days_until_pickup = (pickup_date - today).days

    if days_until_pickup > 7:
        return 100  # Full refund
    elif days_until_pickup >= 3:
        return 50  # 50% refund
    else:
        return 0  # No refund


def calculate_rental_days(pickup_date_str, return_date_str):
    """Calculate number of days between pickup and return"""
    pickup_date = datetime.strptime(pickup_date_str, '%Y-%m-%d')
    return_date = datetime.strptime(return_date_str, '%Y-%m-%d')
    days = max(1, (return_date - pickup_date).days)
    return days


def calculate_cart_totals(cart_items, vehicles):
    """
    Calculate cart totals including subtotal, fees, and grand total
    Returns: dict with subtotal, insurance_fee, service_fee, total
    """
    subtotal = 0
    cart_data = []

    for item_id, item_info in cart_items.items():
        vehicle = vehicles.get(int(item_id))
        if vehicle:
            days = calculate_rental_days(item_info['pickup_date'], item_info['return_date'])
            item_subtotal = days * vehicle['price_per_day']

            cart_data.append({
                'id': vehicle['id'],
                'name': vehicle['name'],
                'type': vehicle['type'],
                'price_per_day': vehicle['price_per_day'],
                'pickup_location': vehicle['pickup_location'],
                'image': vehicle['image'],
                'pickup_date': item_info['pickup_date'],
                'return_date': item_info['return_date'],
                'days': days,
                'item_subtotal': item_subtotal
            })
            subtotal += item_subtotal

    # Calculate fees
    insurance_fee = round(subtotal * 0.08)
    service_fee = 25
    total = subtotal + insurance_fee + service_fee

    return {
        'cart_data': cart_data,
        'subtotal': subtotal,
        'insurance_fee': insurance_fee,
        'service_fee': service_fee,
        'total': total
    }


def generate_booking_id():
    """Generate a unique booking ID"""
    from models import BOOKINGS
    booking_count = len(BOOKINGS) + 1
    return f"BK{booking_count:03d}"


def generate_request_id(prefix='CR'):
    """Generate a unique request ID with given prefix"""
    from models import CANCELLATION_REQUESTS
    count = len(CANCELLATION_REQUESTS) + 1
    return f"{prefix}{count:04d}"


def generate_refund_id():
    """Generate a unique refund ID"""
    from models import REFUNDS
    refund_count = len(REFUNDS) + 1
    return f"RF{refund_count:04d}"


def format_currency(amount):
    """Format amount as Singapore Dollar"""
    return f"${amount:,.2f}"


def get_cart_count(session):
    """Get current cart item count from session"""
    return len(session.get('cart', {}))
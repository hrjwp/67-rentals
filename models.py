from datetime import datetime

# Vehicle data
VEHICLES = {
    1: {
        'id': 1,
        'name': 'Toyota Sienta Hybrid',
        'type': 'Hybrid',
        'price_per_day': 150,
        'pickup_location': 'Jurong Point, Singapore',
        'image': 'images/toyota.png',
        'description': 'Amazing Fuel Economy of 25.0km/L. Lower CO2 emissions with VES rating of A2. Quiet, 7 seater'
    },
    2: {
        'id': 2,
        'name': 'MT-07/Y-AMT',
        'type': 'Petrol',
        'price_per_day': 100,
        'pickup_location': 'NYP, Singapore',
        'image': 'images/bike.jpg',
        'description': 'Powered by Yamaha\'s renowned 689cc CP2 parallel-twin engine'
    },
    3: {
        'id': 3,
        'name': 'Honda Civic',
        'type': 'Hybrid',
        'price_per_day': 120,
        'pickup_location': 'Northpoint, Singapore',
        'image': 'images/civic.png',
        'description': '1.5L DOHC VTEC® Turbo Engine. 3 Drive Modes (Normal, Sport, Econ). Paddle Shifters'
    },
    4: {
        'id': 4,
        'name': 'TOYOTA Corolla Cross',
        'type': 'Petrol',
        'price_per_day': 110,
        'pickup_location': 'Bedok, Singapore',
        'image': 'images/corolla.png',
        'description': 'Powered by a standard 2.0-litre Hybrid Electric Engine (HEV) and motor, producing 195, boasts remarkable fuel efficiency of 4.8L/100km.'
    },
    5: {
        'id': 5,
        'name': 'AVANTE Hybrid',
        'type': 'Hybrid',
        'price_per_day': 180,
        'pickup_location': 'Bishan, Singapore',
        'image': 'images/avante.png',
        'description': 'Avante\'s newly developed 3rd Generation Platform delivers agile handling and stability powered by a fuel-efficient engine, giving you optimal driving performance wherever you go.'
    }
}

# Booking data
BOOKINGS = {
    'BK001': {
        'booking_id': 'BK001',
        'vehicle_id': 1,
        'vehicle_name': 'Toyota Sienta Hybrid',
        'vehicle_image': 'images/toyota.png',
        'customer_name': 'John Doe',
        'customer_email': 'john@example.com',
        'pickup_date': '2025-12-01',
        'return_date': '2025-12-05',
        'pickup_location': 'Jurong Point, Singapore',
        'booking_date': '2025-11-15',
        'days': 4,
        'total_amount': 725,
        'status': 'Confirmed',
        'payment_intent_id': 'pi_abc123'
    },
    'BK002': {
        'booking_id': 'BK002',
        'vehicle_id': 2,
        'vehicle_name': 'MT-07/Y-AMT',
        'vehicle_image': 'images/bike.jpg',
        'customer_name': 'Jane Smith',
        'customer_email': 'jane@example.com',
        'pickup_date': '2025-11-28',
        'return_date': '2025-11-30',
        'pickup_location': 'NYP, Singapore',
        'booking_date': '2025-11-20',
        'days': 2,
        'total_amount': 225,
        'status': 'Confirmed',
        'payment_intent_id': 'pi_xyz789'
    }
}

# Cancellation requests
CANCELLATION_REQUESTS = {}

# Refund records
REFUNDS = {
    "RF0001": {
        'refund_id': "RF0001",
        'booking_id': "BKG1234",
        'request_id': "REQ001",
        'original_amount': 120.00,
        'refund_percentage': 100,
        'processing_fee': 10,
        'refund_amount': 110.00,
        'request_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'approval_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'cancellation_date': datetime.now().strftime('%Y-%m-%d'),
        'status': 'Approved',
        'payment_intent_id': "pi_test_123456789"
    }
}

# Listings for sellers
listings = [
    {
        'id': 1,
        'name': 'Toyota Sienta Hybrid',
        'fuel_type': 'Hybrid',
        'location': 'Jurong Point, Singapore',
        'price': 150,
        'bookings': 23,
        'description': 'Amazing Fuel Economy of 25.0km/L. Lower CO2 emissions with VES rating of A2. Quiet, 7 seater',
        'status': 'active',
        'image': 'images/toyota.png'
    },
    {
        'id': 2,
        'name': 'MT-07/Y-AMT',
        'fuel_type': 'Petrol',
        'location': 'NYP, Singapore',
        'price': 100,
        'bookings': 15,
        'description': 'Powered by Yamaha\'s renowned 689cc CP2 parallel-twin engine',
        'status': 'active',
        'image': 'images/bike.jpg'
    }
]

# Password reset tokens
PASSWORD_RESET_TOKENS = {}
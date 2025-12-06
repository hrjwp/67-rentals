import mysql.connector
from mysql.connector import Error
from contextlib import contextmanager
from config import Config


def create_connection():
    """Create a database connection to MySQL database"""
    try:
        connection = mysql.connector.connect(
            host="mysql-67rentals-mymail-e67.e.aivencloud.com",
            user="avnadmin",
            password="AVNS_zofo1mZWBotNQUe8XAx",
            database="defaultdb",
            port="11215"
        )
        if connection.is_connected():
            return connection
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

@contextmanager
def get_db_connection():
    """Context manager for database connections"""
    connection = create_connection()
    try:
        yield connection
        connection.commit()
    except Error as e:
        connection.rollback()
        print(f"Database error: {e}")
        raise
    finally:
        if connection and connection.is_connected():
            connection.close()


# Database query functions

def get_user_by_email(email):
    """Get user by email"""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        return user


def create_user(user_data):
    """Create a new user"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = """
            INSERT INTO users (first_name, last_name, email, phone, nric, 
                             license_number, password, nric_image, license_image, verified)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        values = (
            user_data['first_name'],
            user_data['last_name'],
            user_data['email'],
            user_data['phone'],
            user_data['nric'],
            user_data['license_number'],
            user_data['password'],
            user_data['nric_image'],
            user_data['license_image'],
            user_data.get('verified', False)
        )
        cursor.execute(query, values)
        user_id = cursor.lastrowid
        cursor.close()
        return user_id


def get_all_vehicles():
    """Get all vehicles"""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM vehicles WHERE status = 'active'")
        vehicles = cursor.fetchall()
        cursor.close()
        return vehicles


def get_vehicle_by_id(vehicle_id):
    """Get vehicle by ID"""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM vehicles WHERE id = %s", (vehicle_id,))
        vehicle = cursor.fetchone()
        cursor.close()
        return vehicle


def create_booking(booking_data):
    """Create a new booking"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = """
            INSERT INTO bookings (booking_id, vehicle_id, user_id, pickup_date, 
                                return_date, pickup_location, days, total_amount, 
                                status, payment_intent_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        values = (
            booking_data['booking_id'],
            booking_data['vehicle_id'],
            booking_data['user_id'],
            booking_data['pickup_date'],
            booking_data['return_date'],
            booking_data['pickup_location'],
            booking_data['days'],
            booking_data['total_amount'],
            booking_data.get('status', 'Pending'),
            booking_data.get('payment_intent_id')
        )
        cursor.execute(query, values)
        booking_id = cursor.lastrowid
        cursor.close()
        return booking_id


def get_booking_by_id(booking_id):
    """Get booking by booking_id"""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM bookings WHERE booking_id = %s", (booking_id,))
        booking = cursor.fetchone()
        cursor.close()
        return booking


def update_user_password(email, new_password):
    """Update user password"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET password = %s WHERE email = %s",
            (new_password, email)
        )
        cursor.close()


def save_reset_token(token, email, expires_at):
    """Save password reset token"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = """
            INSERT INTO password_reset_tokens (token, email, expires_at, used)
            VALUES (%s, %s, %s, %s)
        """
        cursor.execute(query, (token, email, expires_at, False))
        cursor.close()


def get_reset_token(token):
    """Get password reset token"""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM password_reset_tokens WHERE token = %s",
            (token,)
        )
        token_data = cursor.fetchone()
        cursor.close()
        return token_data


def mark_token_as_used(token):
    """Mark reset token as used"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE password_reset_tokens SET used = TRUE WHERE token = %s",
            (token,)
        )
        cursor.close()

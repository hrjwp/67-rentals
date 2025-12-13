import mysql.connector
from mysql.connector import Error, errorcode
from contextlib import contextmanager
from config import Config
from db_config import DB_CONFIG
from utils.encryption import encrypt_value, decrypt_value


def create_connection():
    """Create a database connection to MySQL database"""
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
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


def _safe_alter(cursor, statement: str):
    """Run ALTER TABLE and swallow duplicate/unknown column errors."""
    try:
        cursor.execute(statement)
    except Error as exc:
        if exc.errno in {errorcode.ER_DUP_FIELDNAME, errorcode.ER_BAD_FIELD_ERROR}:
            return
        raise


def ensure_schema():
    """Ensure required tables/columns exist for signup tickets and documents."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Core support tables
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS user_documents (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                doc_type VARCHAR(50) NOT NULL,
                file_name VARCHAR(255) NULL,
                mime_type VARCHAR(100) NULL,
                file_path VARCHAR(255) NULL,
                file_data LONGBLOB NULL,
                uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
            """
        )
        # Add missing columns for binary storage if table already exists
        _safe_alter(cursor, "ALTER TABLE user_documents ADD COLUMN file_name VARCHAR(255) NULL")
        _safe_alter(cursor, "ALTER TABLE user_documents ADD COLUMN mime_type VARCHAR(100) NULL")
        _safe_alter(cursor, "ALTER TABLE user_documents ADD COLUMN file_path VARCHAR(255) NULL")
        _safe_alter(cursor, "ALTER TABLE user_documents ADD COLUMN file_data LONGBLOB NULL")
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS signup_tickets (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                user_type VARCHAR(20) NOT NULL,
                status ENUM('pending','approved','rejected') DEFAULT 'pending',
                submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                reviewed_at DATETIME NULL,
                reviewer VARCHAR(100) NULL,
                note TEXT NULL,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INT AUTO_INCREMENT PRIMARY KEY,
                token VARCHAR(255) NOT NULL UNIQUE,
                email VARCHAR(255) NOT NULL,
                expires_at DATETIME NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # Columns needed on users table
        _safe_alter(cursor, "ALTER TABLE users ADD COLUMN verified TINYINT(1) DEFAULT 0")
        _safe_alter(cursor, "ALTER TABLE users ADD COLUMN user_type VARCHAR(20) DEFAULT 'user'")
        _safe_alter(cursor, "ALTER TABLE users ADD COLUMN nric VARCHAR(20) NULL")
        _safe_alter(cursor, "ALTER TABLE users ADD COLUMN license_number VARCHAR(50) NULL")
        _safe_alter(cursor, "ALTER TABLE users MODIFY phone_number VARCHAR(30)")

        conn.commit()


def _fetch_documents_for_users(cursor, user_ids):
    """Return {user_id: {doc_type: {id, file_name, file_path}}} for given users."""
    if not user_ids:
        return {}
    placeholders = ", ".join(["%s"] * len(user_ids))
    cursor.execute(
        f"SELECT id, user_id, doc_type, file_name, file_path FROM user_documents WHERE user_id IN ({placeholders})",
        tuple(user_ids),
    )
    docs = {}
    for row in cursor.fetchall():
        # Handle both tuple and dict rows depending on cursor type
        if isinstance(row, dict):
            doc_id = row.get("id")
            uid = row.get("user_id")
            doc_type = row.get("doc_type")
            file_name = row.get("file_name")
            file_path = row.get("file_path")
        else:
            doc_id, uid, doc_type, file_name, file_path = row
        if uid is None:
            continue
        docs.setdefault(uid, {})[doc_type] = {
            "id": doc_id,
            "file_name": file_name,
            "file_path": file_path,
        }
    return docs


# Database query functions

def get_user_by_email(email):
    """Get user by email from DB."""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT user_id, first_name, last_name, email, phone_number AS phone,
                   nric, license_number, password_hash, user_type, verified, account_status, role
            FROM users WHERE email = %s
            """,
            (email,),
        )
        user = cursor.fetchone()
        cursor.close()
        return user


def get_user_documents(user_id):
    """Return document map for a user."""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT doc_type, file_path FROM user_documents WHERE user_id = %s",
            (user_id,),
        )
        docs = {row["doc_type"]: row["file_path"] for row in cursor.fetchall()}
        cursor.close()
        return docs


def create_user_with_documents(user_data):
    """
    Create a new user row, attach uploaded document paths, and open a signup ticket.
    user_data keys: first_name, last_name, email, phone, nric, license_number,
    password_hash, user_type, documents (dict of doc_type-> {filename, mime, data, path})
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        user_insert = """
            INSERT INTO users (
                first_name, last_name, email, phone_number, password_hash,
                nric, license_number, user_type, verified, account_status, role
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        user_values = (
            user_data["first_name"],
            user_data["last_name"],
            user_data["email"],
            user_data.get("phone"),
            user_data["password_hash"],
            user_data.get("nric"),
            user_data.get("license_number"),
            user_data.get("user_type", "user"),
            False,
            "active",
            "admin" if user_data.get("user_type") == "admin" else "customer",
        )
        cursor.execute(user_insert, user_values)
        user_id = cursor.lastrowid

        docs = user_data.get("documents", {}) or {}
        for doc_type, doc_val in docs.items():
            file_name = None
            mime_type = None
            file_data = None
            file_path = None

            if isinstance(doc_val, dict):
                file_name = doc_val.get("filename")
                mime_type = doc_val.get("mime")
                file_data = doc_val.get("data")
                file_path = doc_val.get("path")
            else:
                file_path = doc_val

            cursor.execute(
                """
                INSERT INTO user_documents (user_id, doc_type, file_name, mime_type, file_path, file_data)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (user_id, doc_type, file_name, mime_type, file_path, file_data),
            )

        cursor.execute(
            "INSERT INTO signup_tickets (user_id, user_type, status) VALUES (%s, %s, 'pending')",
            (user_id, user_data.get("user_type", "user")),
        )

        ticket_id = cursor.lastrowid
        cursor.close()
        return user_id, ticket_id


def get_signup_tickets(status=None):
    """Return signup tickets with joined user info and attached documents."""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        params = []
        where = ""
        if status:
            where = "WHERE t.status = %s"
            params.append(status)

        cursor.execute(
            f"""
            SELECT t.id as ticket_id, t.status, t.submitted_at, t.reviewed_at, t.reviewer, t.note,
                   u.user_id, u.first_name, u.last_name, u.email, u.phone_number AS phone,
                   u.nric, u.license_number, u.user_type, u.verified
            FROM signup_tickets t
            JOIN users u ON u.user_id = t.user_id
            {where}
            ORDER BY t.submitted_at DESC
            """,
            tuple(params),
        )
        rows = cursor.fetchall()
        docs = _fetch_documents_for_users(cursor, [row["user_id"] for row in rows])
        for row in rows:
            row["documents"] = docs.get(row["user_id"], {})
        cursor.close()
        return rows


def set_signup_status(ticket_id, status, reviewer=None, note=None):
    """Approve or reject a signup ticket and update user. Status: approved/rejected."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT user_id FROM signup_tickets WHERE id = %s",
            (ticket_id,),
        )
        res = cursor.fetchone()
        if not res:
            cursor.close()
            return False

        user_id = res[0]
        cursor.execute(
            """
            UPDATE signup_tickets
            SET status = %s, reviewed_at = NOW(), reviewer = %s, note = %s
            WHERE id = %s
            """,
            (status, reviewer, note, ticket_id),
        )
        if status == "approved":
            cursor.execute(
                "UPDATE users SET verified = 1 WHERE user_id = %s",
                (user_id,),
            )
        elif status == "rejected":
            cursor.execute(
                "UPDATE users SET verified = 0 WHERE user_id = %s",
                (user_id,),
            )

        cursor.close()
        return True


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
            "UPDATE users SET password_hash = %s WHERE email = %s",
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


def get_user_bookings(user_id):
    """Get all bookings for a specific user"""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        query = """
            SELECT b.*, v.name as vehicle_name, v.image as vehicle_image, v.type as vehicle_type
            FROM bookings b
            LEFT JOIN vehicles v ON b.vehicle_id = v.id
            WHERE b.user_id = %s
            ORDER BY b.pickup_date DESC
        """
        cursor.execute(query, (user_id,))
        bookings = cursor.fetchall()
        cursor.close()
        return bookings


# Ensure tables/columns exist when module is imported
ensure_schema()

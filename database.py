import mysql.connector
from mysql.connector import Error, errorcode
from contextlib import contextmanager
from config import Config
from db_config import DB_CONFIG
from utils.field_encryption_config import get_encrypted_columns, get_column_keys_for_decrypt
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any
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

def _encrypt_row(table_name: str, row: Dict[str, Any]) -> Dict[str, Any]:
    """Encrypt sensitive fields in a row before DB insert/update.
    Raises if encryption fails (e.g. DATA_ENCRYPTION_KEY not set)."""
    cols = get_encrypted_columns(table_name)
    out = dict(row)
    for col in cols:
        if col in out and out[col] is not None and out[col] != '':
            out[col] = encrypt_value(str(out[col]))
    return out


def _decrypt_row(table_name: str, row: Dict[str, Any], fallback: bool = True) -> Dict[str, Any]:
    """Decrypt sensitive fields in a row after DB fetch. Handles column aliases."""
    cols = get_encrypted_columns(table_name)
    out = dict(row)
    for col in cols:
        keys = get_column_keys_for_decrypt(table_name, col)
        for key in keys:
            if key in out and out[key] is not None:
                try:
                    out[key] = decrypt_value(out[key], fallback_on_error=fallback)
                except Exception:
                    if fallback:
                        out[key] = out[key]
                break  # Only decrypt one (column or its alias)
    return out

def _safe_alter(cursor, statement: str):
    """Run ALTER TABLE and swallow duplicate/unknown column errors."""
    try:
        cursor.execute(statement)
    except Error as exc:
        # Ignore duplicate field, unknown column, and duplicate key errors
        if exc.errno in {errorcode.ER_DUP_FIELDNAME, errorcode.ER_BAD_FIELD_ERROR, errorcode.ER_DUP_KEYNAME}:
            return
        # For MODIFY operations, also ignore warnings about data truncation if increasing size
        if 'MODIFY' in statement.upper() and exc.errno == 1265:  # Data truncated warning
            return
        raise


def ensure_schema():
    """Ensure required tables/columns exist for signup tickets and documents."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Core support tables
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS bookings (
                booking_id VARCHAR(20) PRIMARY KEY,
                vehicle_id INT NOT NULL,
                user_id INT NOT NULL,  -- Required for linking to customer data
                pickup_date DATE NOT NULL,
                return_date DATE NOT NULL,
                pickup_location VARCHAR(100),
                booking_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                days INT,
                total_amount DECIMAL(10,2),
                status ENUM('Confirmed', 'Pending', 'Cancelled') DEFAULT 'Pending',
                payment_intent_id VARCHAR(100),
                FOREIGN KEY (vehicle_id) REFERENCES vehicles(id),
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
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS password_reset_otps (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) NOT NULL,
                otp_hash VARCHAR(64) NOT NULL,
                salt VARCHAR(64) NOT NULL,
                expires_at DATETIME NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                attempts INT DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_email (email),
                INDEX idx_expires (expires_at)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS bookings (
                booking_id VARCHAR(20) PRIMARY KEY,
                vehicle_id INT,
                user_id INT,
                pickup_date DATE NOT NULL,
                return_date DATE NOT NULL,
                pickup_location VARCHAR(100),
                booking_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                days INT,
                total_amount DECIMAL(10,2),
                status ENUM('Confirmed', 'Pending', 'Cancelled') DEFAULT 'Pending',
                payment_intent_id VARCHAR(100),
                FOREIGN KEY (vehicle_id) REFERENCES vehicles(id),
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS incident_reports (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NULL,
                full_name VARCHAR(1000) NOT NULL,
                contact_number VARCHAR(1000) NOT NULL,
                email VARCHAR(1000) NOT NULL,
                booking_id VARCHAR(1000) NOT NULL,
                vehicle_name VARCHAR(255) NOT NULL,
                incident_date DATE NOT NULL,
                incident_time VARCHAR(20) NOT NULL,
                incident_location VARCHAR(1000) NOT NULL,
                incident_type VARCHAR(100) NOT NULL,
                severity_level VARCHAR(50) NOT NULL,
                incident_description TEXT NOT NULL,
                status ENUM('Pending Review','Under Review','Resolved') DEFAULT 'Pending Review',
                files_json JSON NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS incident_report_files (
                file_id INT AUTO_INCREMENT PRIMARY KEY,
                report_id INT NOT NULL,
                filename VARCHAR(255) NOT NULL,
                original_filename VARCHAR(500) NOT NULL,
                file_path VARCHAR(1000) NOT NULL,
                file_size_bytes BIGINT NOT NULL,
                file_type VARCHAR(50) NOT NULL,
                mime_type VARCHAR(100) NOT NULL,
                is_encrypted BOOLEAN DEFAULT TRUE,
                is_watermarked BOOLEAN DEFAULT FALSE,
                uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (report_id) REFERENCES incident_reports(id) ON DELETE CASCADE,
                INDEX idx_report_id (report_id),
                INDEX idx_filename (filename)
            )
            """
        )
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                audit_id INT AUTO_INCREMENT PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                user_id INT NOT NULL,
                ip_address VARCHAR(45),
                device_info VARCHAR(255),
                action VARCHAR(100) NOT NULL,
                entity_type VARCHAR(50) NOT NULL,
                entity_id VARCHAR(50) NOT NULL,
                previous_values JSON,
                new_values JSON,
                result ENUM('Success','Failure') DEFAULT 'Success',
                reason TEXT,
                risk_score DECIMAL(5,4) DEFAULT 0.0000,
                severity ENUM('Low','Medium','High','Critical') DEFAULT 'Low',
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
            """
        )
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS backup_logs (
                backup_id INT AUTO_INCREMENT PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                backup_type ENUM('Manual','Automated') DEFAULT 'Automated',
                backup_filename VARCHAR(255) NOT NULL,
                backup_path VARCHAR(500) NOT NULL,
                backup_size_bytes BIGINT NOT NULL,
                backup_size_mb DECIMAL(10,2) NOT NULL,
                checksum_sha256 VARCHAR(64) NOT NULL,
                tables_backed_up JSON NOT NULL,
                files_included INT DEFAULT 0,
                cloud_backup_enabled BOOLEAN DEFAULT FALSE,
                cloud_backup_path VARCHAR(500) NULL,
                status ENUM('Success','Failed','In Progress') DEFAULT 'Success',
                error_message TEXT NULL,
                verification_status ENUM('Verified','Failed','Pending') DEFAULT 'Pending',
                verification_timestamp DATETIME NULL,
                created_by_user_id INT NULL,
                FOREIGN KEY (created_by_user_id) REFERENCES users(user_id) ON DELETE SET NULL
            )
            """
        )
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS data_retention_settings (
                id INT PRIMARY KEY,
                auto_purge_enabled TINYINT(1) DEFAULT 1,
                retention_days INT DEFAULT 365,
                inactivity_purge_enabled TINYINT(1) DEFAULT 1,
                inactivity_days INT DEFAULT 90,
                apply_to_users TINYINT(1) DEFAULT 1,
                apply_to_sellers TINYINT(1) DEFAULT 1,
                exclude_admins TINYINT(1) DEFAULT 1,
                last_run_at DATETIME NULL,
                last_run_purged INT DEFAULT 0,
                last_run_reason VARCHAR(20) NULL,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                updated_by VARCHAR(255) NULL
            )
            """
        )
        cursor.execute("INSERT IGNORE INTO data_retention_settings (id) VALUES (1)")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS data_retention_overrides (
                user_id INT PRIMARY KEY,
                extension_days INT DEFAULT 0,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                updated_by VARCHAR(255) NULL,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
            )
            """
        )
        # Data retention policies for all data types
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS data_retention_policies (
                id INT AUTO_INCREMENT PRIMARY KEY,
                data_type VARCHAR(50) UNIQUE NOT NULL,
                display_name VARCHAR(100) NOT NULL,
                table_name VARCHAR(100) NOT NULL,
                date_column VARCHAR(50) NOT NULL,
                retention_days INT DEFAULT 365,
                auto_purge_enabled TINYINT(1) DEFAULT 1,
                purge_schedule ENUM('daily', 'weekly', 'monthly') DEFAULT 'daily',
                last_purge_at DATETIME NULL,
                last_purge_count INT DEFAULT 0,
                description TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
            """
        )
        # Seed default retention policies for all data types
        default_policies = [
            ('bookings', 'Bookings', 'bookings', 'booking_date', 730, 'Completed vehicle rental bookings'),
            ('audit_logs', 'Audit Logs', 'audit_logs', 'timestamp', 365, 'System audit trail entries'),
            ('security_logs', 'Security Logs', 'security_logs', 'timestamp', 730, 'Security event logs'),
            ('incident_reports', 'Incident Reports', 'incident_reports', 'created_at', 1825, 'Reported incidents and accidents'),
            ('password_reset_tokens', 'Password Reset Tokens', 'password_reset_tokens', 'created_at', 30, 'Password reset token records'),
            ('password_reset_otps', 'Password Reset OTPs', 'password_reset_otps', 'created_at', 7, 'One-time password records'),
            ('backup_logs', 'Backup Logs', 'backup_logs', 'timestamp', 365, 'Database backup history'),
            ('cancellation_requests', 'Cancellation Requests', 'cancellation_requests', 'created_at', 730, 'Booking cancellation records'),
        ]
        for policy in default_policies:
            cursor.execute("""
                INSERT IGNORE INTO data_retention_policies 
                (data_type, display_name, table_name, date_column, retention_days, description)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, policy)
        # Add foreign key separately if it doesn't exist (allows NULL user_id)
        try:
            cursor.execute("""
                ALTER TABLE incident_reports 
                ADD CONSTRAINT fk_incident_user 
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            """)
        except Error as e:
            # Foreign key might already exist, ignore
            if e.errno != errorcode.ER_DUP_KEY and 'Duplicate foreign key' not in str(e):
                print(f"Note: Could not add foreign key (may already exist): {e}")
        _safe_alter(cursor, "ALTER TABLE incident_reports ADD COLUMN status ENUM('Pending Review','Under Review','Resolved') DEFAULT 'Pending Review'")

        # Columns needed on users table
        _safe_alter(cursor, "ALTER TABLE users ADD COLUMN verified TINYINT(1) DEFAULT 0")
        _safe_alter(cursor, "ALTER TABLE users ADD COLUMN user_type VARCHAR(20) DEFAULT 'user'")
        _safe_alter(cursor, "ALTER TABLE users ADD COLUMN nric VARCHAR(20) NULL")
        _safe_alter(cursor, "ALTER TABLE users ADD COLUMN license_number VARCHAR(50) NULL")
        # Increase column sizes to accommodate encrypted values (encrypted data is base64, much longer)
        _safe_alter(cursor, "ALTER TABLE users MODIFY phone_number VARCHAR(255)")
        _safe_alter(cursor, "ALTER TABLE users MODIFY first_name VARCHAR(255)")
        _safe_alter(cursor, "ALTER TABLE users MODIFY last_name VARCHAR(255)")
        _safe_alter(cursor, "ALTER TABLE users MODIFY nric VARCHAR(255)")
        _safe_alter(cursor, "ALTER TABLE users MODIFY license_number VARCHAR(255)")
        _safe_alter(cursor, "ALTER TABLE users ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP")
        _safe_alter(cursor, "ALTER TABLE users ADD COLUMN last_login_at DATETIME NULL")
        
        # Update incident_reports table columns to accommodate encrypted data (increased to 1000 for safety)
        _safe_alter(cursor, "ALTER TABLE incident_reports MODIFY full_name VARCHAR(1000)")
        _safe_alter(cursor, "ALTER TABLE incident_reports MODIFY contact_number VARCHAR(1000)")
        _safe_alter(cursor, "ALTER TABLE incident_reports MODIFY email VARCHAR(1000)")
        _safe_alter(cursor, "ALTER TABLE incident_reports MODIFY booking_id VARCHAR(1000)")
        _safe_alter(cursor, "ALTER TABLE incident_reports MODIFY incident_location VARCHAR(1000)")

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
    """Get user by email from DB.Sensitive fields r decrtpyed"""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT user_id, first_name, last_name, email, phone_number AS phone,
                   nric, license_number, password_hash, user_type, verified, account_status, role,
                   created_at, last_login_at
            FROM users WHERE email = %s
            """,
            (email,),
        )
        user = cursor.fetchone()
        cursor.close()
        if user:
            user = _decrypt_row("users", user)
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
    Sensitive fields (first_name, last_name, phone_number, nric, license_number) are AES-encrypted.
    """

    # Encrypt sensitive PII before storing
    user_row = {
        "first_name": user_data.get("first_name"),
        "last_name": user_data.get("last_name"),
        "email": user_data.get("email"),  # ← ADD THIS LINE
        "phone_number": user_data.get("phone"),
        "nric": user_data.get("nric"),
        "license_number": user_data.get("license_number"),
    }
    user_row = _encrypt_row("users", user_row)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        user_insert = """
            INSERT INTO users (
                first_name, last_name, email, phone_number, password_hash,
                nric, license_number, user_type, verified, account_status, role
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        user_values = (
            user_row["first_name"],
            user_row["last_name"],
            user_row["email"],  # ✅ NOW ENCRYPTED
            user_row["phone_number"],
            user_data["password_hash"],
            user_row["nric"],
            user_row["license_number"],
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
            row.update(_decrypt_row("users", row))
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
                status, payment_intent_id, booking_date
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
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


def update_user_profile(user_id, first_name, last_name, email, phone):
    """Update editable profile fields for a user. Sensitive fields are AES-encrypted."""
    row = _encrypt_row("users", {
        "first_name": first_name,
        "last_name": last_name,
        "email": email,  # ← ADD THIS LINE
        "phone_number": phone,
    })
    first_name_enc = row["first_name"]
    last_name_enc = row["last_name"]
    email_enc = row["email"]  # ← ADD THIS LINE
    phone_enc = row["phone_number"]

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT user_id FROM users WHERE email = %s AND user_id != %s",
            (email, user_id)   # Note: This search won't work with encrypted email - see note below
        )
        if cursor.fetchone():
            cursor.close()
            return False, "Email already registered"

        cursor.execute(
            """
            UPDATE users
            SET first_name = %s,
                last_name = %s,
                email = %s,
                phone_number = %s
            WHERE user_id = %s
            """,
            (first_name_enc, last_name_enc, email_enc, phone_enc, user_id)  # ✅ NOW ENCRYPTED
        )
        cursor.close()
        return True, None


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


def invalidate_password_reset_otps(email: str):
    """Invalidate any existing OTPs for an email."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE password_reset_otps SET used = TRUE WHERE email = %s AND used = FALSE",
            (email,),
        )
        cursor.close()


def create_password_reset_otp(email: str, otp_hash: str, salt: str, expires_at):
    """Create a new password reset OTP entry."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO password_reset_otps (email, otp_hash, salt, expires_at, used, attempts)
            VALUES (%s, %s, %s, %s, FALSE, 0)
            """,
            (email, otp_hash, salt, expires_at),
        )
        otp_id = cursor.lastrowid
        cursor.close()
        return otp_id


def get_latest_password_reset_otp(email: str):
    """Get the latest unused OTP for an email."""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT * FROM password_reset_otps
            WHERE email = %s AND used = FALSE
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (email,),
        )
        row = cursor.fetchone()
        cursor.close()
        return row


def increment_password_reset_otp_attempts(otp_id: int):
    """Increment attempts for an OTP."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE password_reset_otps SET attempts = attempts + 1 WHERE id = %s",
            (otp_id,),
        )
        cursor.close()


def mark_password_reset_otp_used(otp_id: int):
    """Mark OTP as used."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE password_reset_otps SET used = TRUE WHERE id = %s",
            (otp_id,),
        )
        cursor.close()


def get_user_bookings(user_id):
    """Get all bookings for a specific user"""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        query = """
            SELECT 
                b.*, 
                v.name as vehicle_name,      -- Fetched via JOIN
                v.image as vehicle_image,    -- Fetched via JOIN
                v.type as vehicle_type       -- Fetched via JOIN
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



# ============= SECURITY LOGS =============

def add_security_log(user_id: str, event_type: str, severity: str,
                     description: str, ip_address: str = None,
                     device_info: str = None, action_taken: str = None) -> int:
    """Add a security log entry"""
    # CORRECTED: Use get_db_connection() instead of self.get_connection()
    with get_db_connection() as conn:
        cursor = conn.cursor()

        query = """
            INSERT INTO security_logs 
            (user_id, event_type, severity, description, ip_address, device_info, action_taken)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """

        cursor.execute(query, (user_id, event_type, severity, description,
                               ip_address, device_info, action_taken))
        conn.commit()
        log_id = cursor.lastrowid
        cursor.close()

        return log_id

def get_security_logs(severity: str = None, event_type: str = None,
                      user_id: str = None, limit: int = 100) -> List[Dict]:
    """Retrieve security logs with optional filters"""
    # CORRECTED: Use get_db_connection() instead of self.get_connection()
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)

        query = "SELECT * FROM security_logs WHERE 1=1"
        params = []

        if severity:
            query += " AND severity = %s"
            params.append(severity)
        if event_type:
            query += " AND event_type = %s"
            params.append(event_type)
        if user_id:
            query += " AND user_id = %s"
            params.append(user_id)

        query += " ORDER BY timestamp DESC LIMIT %s"
        params.append(limit)

        cursor.execute(query, params)
        logs = cursor.fetchall()
        cursor.close()

        return logs


# ============= INCIDENT REPORTS =============

def create_incident_report(report: Dict[str, Any]) -> int:
    """Insert a new incident report."""
    conn = create_connection()
    if not conn:
        raise Exception("Failed to connect to database")
    
    cursor = conn.cursor()
    try:
        # First, ensure the table exists
        cursor.execute("SHOW TABLES LIKE 'incident_reports'")
        table_exists = cursor.fetchone()
        if not table_exists:
            ensure_schema()
            cursor = conn.cursor()  # Get new cursor after schema creation
        
        query = """
            INSERT INTO incident_reports (
                user_id, full_name, contact_number, email,
                booking_id, vehicle_name, incident_date, incident_time,
                incident_location, incident_type, severity_level,
                incident_description, files_json, status
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        # Encrypt sensitive fields before storing
        values = (
            report.get('user_id'),
            encrypt_value(report['full_name']) if report.get('full_name') else None,
            encrypt_value(report['contact_number']) if report.get('contact_number') else None,
            encrypt_value(report['email']) if report.get('email') else None,
            encrypt_value(report['booking_id']) if report.get('booking_id') else None,
            report['vehicle_name'],  # Not sensitive
            report['incident_date'],  # Not sensitive
            report['incident_time'],  # Not sensitive
            encrypt_value(report['incident_location']) if report.get('incident_location') else None,
            report['incident_type'],  # Not sensitive
            report['severity_level'],  # Not sensitive
            encrypt_value(report['incident_description']) if report.get('incident_description') else None,
            json.dumps(report.get('files', [])) if report.get('files') else None,  # Store files in JSON field
            report.get('status', 'Pending Review'),
        )
        cursor.execute(query, values)
        new_id = cursor.lastrowid
        
        if not new_id:
            conn.rollback()
            cursor.close()
            conn.close()
            raise Exception("Insert failed: No ID returned")
        
        # Commit immediately
        conn.commit()
        
        # Files are stored in files_json field - no separate table needed
        # File details are included in the JSON for complete information
        
        # Verify the insert worked
        verify_cursor = conn.cursor()
        verify_cursor.execute("SELECT id FROM incident_reports WHERE id = %s", (new_id,))
        verify_result = verify_cursor.fetchone()
        verify_cursor.close()
        
        cursor.close()
        conn.close()
        
        if not verify_result:
            raise Exception("Insert appeared to succeed but record not found in database")
        
        return new_id
    except Exception as e:
        if conn:
            conn.rollback()
            if cursor:
                cursor.close()
            conn.close()
        raise Exception(f"Database insert failed: {str(e)}") from e


def ensure_incident_report_files_table():
    """Ensure the incident_report_files table exists. Can be called manually if needed."""
    conn = create_connection()
    if not conn:
        print("ERROR: Failed to connect to database")
        return False
    
    cursor = conn.cursor()
    try:
        # Check if table exists
        cursor.execute("SHOW TABLES LIKE 'incident_report_files'")
        table_exists = cursor.fetchone()
        
        if not table_exists:
            print("Creating incident_report_files table...")
            # Create table without foreign key first
            cursor.execute(
                """
            CREATE TABLE IF NOT EXISTS incident_report_files (
                file_id INT AUTO_INCREMENT PRIMARY KEY,
                report_id INT NOT NULL,
                filename VARCHAR(255) NOT NULL,
                original_filename VARCHAR(500) NOT NULL,
                file_path VARCHAR(1000) NOT NULL,
                file_size_bytes BIGINT NOT NULL,
                file_type VARCHAR(50) NOT NULL,
                mime_type VARCHAR(100) NOT NULL,
                is_encrypted BOOLEAN DEFAULT TRUE,
                is_watermarked BOOLEAN DEFAULT FALSE,
                uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_report_id (report_id),
                INDEX idx_filename (filename)
            )
                """
            )
            conn.commit()
            
            # Try to add foreign key constraint
            try:
                cursor.execute(
                    """
                    ALTER TABLE incident_report_files 
                    ADD CONSTRAINT fk_report_files 
                    FOREIGN KEY (report_id) REFERENCES incident_reports(id) ON DELETE CASCADE
                    """
                )
                conn.commit()
            except Error as fk_error:
                if fk_error.errno not in (errorcode.ER_DUP_KEYNAME, errorcode.ER_CANNOT_ADD_FOREIGN):
                    print(f"Warning: Could not add foreign key constraint: {fk_error}")
                else:
                    print("Foreign key constraint already exists or cannot be added (this is okay)")
            
            print("✓ incident_report_files table created successfully!")
            return True
        else:
            print("✓ incident_report_files table already exists")
            return True
    except Error as e:
        print(f"ERROR creating incident_report_files table: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()


def get_incident_reports(email: str = None, user_id: int = None) -> List[Dict[str, Any]]:
    """Fetch incident reports, optionally filtered by user email or user_id."""
    try:
        conn = create_connection()
        if not conn:
            print("ERROR: Failed to connect to database in get_incident_reports")
            return []
        
        cursor = conn.cursor(dictionary=True)
        clauses = []
        params = []
        
        # Match by user_id OR email (whichever is available)
        # Since email is encrypted, we need to encrypt the search email first
        # Use user_id for exact match, or search all and filter by decrypted email
        if user_id and email:
            # If we have user_id, use that (more efficient)
            clauses.append("user_id = %s")
            params.append(user_id)
        elif user_id:
            clauses.append("user_id = %s")
            params.append(user_id)
        elif email:
            # Email is encrypted, so we need to search all and filter after decryption
            # For now, we'll get all reports and filter by email after decryption
            # This is less efficient but necessary for encrypted data
            pass  # Will filter after decryption

        # Build query - if email search without user_id, get all and filter after decryption
        if email and not user_id:
            # Get all reports, will filter by email after decryption
            query = """
                SELECT
                    id, user_id, full_name, contact_number, email,
                    booking_id, vehicle_name, incident_date, incident_time,
                    incident_location, incident_type, severity_level,
                    incident_description, files_json, status, created_at
                FROM incident_reports
                ORDER BY created_at DESC
            """
            cursor.execute(query)
        else:
            # Use WHERE clause for user_id or no filter
            where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            query = f"""
                SELECT
                    id, user_id, full_name, contact_number, email,
                    booking_id, vehicle_name, incident_date, incident_time,
                    incident_location, incident_type, severity_level,
                    incident_description, files_json, status, created_at
                FROM incident_reports
                {where}
                ORDER BY created_at DESC
            """
            cursor.execute(query, tuple(params))
        
        rows = cursor.fetchall()
        
        # Decrypt sensitive fields and hydrate files list from files_json for each report
        filtered_rows = []
        for row in rows:
            # Decrypt sensitive fields
            try:
                if row.get('full_name'):
                    row['full_name'] = decrypt_value(row['full_name'])
                if row.get('contact_number'):
                    row['contact_number'] = decrypt_value(row['contact_number'])
                if row.get('email'):
                    row['email'] = decrypt_value(row['email'])
                if row.get('booking_id'):
                    row['booking_id'] = decrypt_value(row['booking_id'])
                if row.get('incident_location'):
                    row['incident_location'] = decrypt_value(row['incident_location'])
                if row.get('incident_description'):
                    row['incident_description'] = decrypt_value(row['incident_description'])
            except Exception as e:
                print(f"WARNING: Error decrypting fields for report {row.get('id')}: {e}")
                # Continue with encrypted values if decryption fails

            # Hydrate files from JSON so templates/routes can access report['files']
            files_json_val = row.get('files_json')
            if files_json_val:
                try:
                    # MySQL connector may already return JSON as Python object
                    if isinstance(files_json_val, str):
                        row['files'] = json.loads(files_json_val)
                    else:
                        row['files'] = list(files_json_val)
                except Exception as e:
                    print(f"WARNING: Error parsing files_json for report {row.get('id')}: {e}")
                    row['files'] = []
            else:
                row['files'] = []
            
            # Filter by email if email was provided but no user_id (since email is encrypted)
            if email and not user_id:
                if row.get('email') and row['email'].lower() == email.lower():
                    filtered_rows.append(row)
            else:
                filtered_rows.append(row)
        
        rows = filtered_rows
        
        cursor.close()
        conn.close()
        return rows
    except Exception as e:
        print(f"ERROR in get_incident_reports: {e}")
        import traceback
        print(traceback.format_exc())
        return []


def update_incident_status(report_id: int, status: str) -> bool:
    """Update status of an incident report."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE incident_reports SET status = %s WHERE id = %s",
            (status, report_id)
        )
        updated = cursor.rowcount
        cursor.close()
        return updated > 0


def delete_incident_report(report_id: int) -> bool:
    """Delete an incident report."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM incident_reports WHERE id = %s", (report_id,))
        deleted = cursor.rowcount
        cursor.close()
        return deleted > 0

# ============= VEHICLE FRAUD LOGS =============

def add_vehicle_fraud_log(user_id: str, vehicle_id: str, event_type: str,
                          severity: str, risk_score: float, description: str,
                          action_taken: str = None, gps_data: Dict = None,
                          mileage_data: Dict = None) -> int:
    """Add a vehicle fraud log entry"""
    # CORRECTED: Use get_db_connection() instead of self.get_connection()
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Extract GPS data if provided
        prev_location = gps_data.get('prev_location') if gps_data else None
        current_location = gps_data.get('current_location') if gps_data else None
        distance_km = gps_data.get('distance_km') if gps_data else None
        speed_kmh = gps_data.get('speed_kmh') if gps_data else None

        # Extract mileage data if provided
        reported_mileage = mileage_data.get('reported') if mileage_data else None
        gps_calculated_mileage = mileage_data.get('gps_calculated') if mileage_data else None
        discrepancy_percent = mileage_data.get('discrepancy_percent') if mileage_data else None

        query = """
            INSERT INTO vehicle_fraud_logs 
            (user_id, vehicle_id, event_type, severity, risk_score, description, action_taken,
             prev_location, current_location, distance_km, speed_kmh,
             reported_mileage, gps_calculated_mileage, discrepancy_percent)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """

        cursor.execute(query, (user_id, vehicle_id, event_type, severity, risk_score,
                               description, action_taken, prev_location, current_location,
                               distance_km, speed_kmh, reported_mileage,
                               gps_calculated_mileage, discrepancy_percent))
        conn.commit()
        log_id = cursor.lastrowid
        cursor.close()

        return log_id

def get_vehicle_fraud_logs(severity: str = None, event_type: str = None,
                           user_id: str = None, min_risk: float = None,
                           limit: int = 100) -> List[Dict]:
    """Retrieve vehicle fraud logs with optional filters"""
    # CORRECTED: Use get_db_connection() instead of self.get_connection()
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)

        query = "SELECT * FROM vehicle_fraud_logs WHERE 1=1"
        params = []

        if severity:
            query += " AND severity = %s"
            params.append(severity)
        if event_type:
            query += " AND event_type = %s"
            params.append(event_type)
        if user_id:
            query += " AND user_id = %s"
            params.append(user_id)
        if min_risk is not None:
            query += " AND risk_score >= %s"
            params.append(min_risk)

        query += " ORDER BY timestamp DESC LIMIT %s"
        params.append(limit)

        cursor.execute(query, params)
        logs = cursor.fetchall()
        cursor.close()

        # Convert to format matching your Flask app
        for log in logs:
            if log.get('prev_location'):
                log['gps_data'] = {
                    'prev_location': log['prev_location'],
                    'current_location': log['current_location'],
                    'distance_km': float(log['distance_km']) if log['distance_km'] else None,
                    'speed_kmh': float(log['speed_kmh']) if log['speed_kmh'] else None
                }

            if log.get('reported_mileage'):
                log['mileage_data'] = {
                    'reported': log['reported_mileage'],
                    'gps_calculated': log['gps_calculated_mileage'],
                    'discrepancy_percent': float(log['discrepancy_percent']) if log['discrepancy_percent'] else None
                }

        return logs

# ============= BOOKING FRAUD LOGS =============

def add_booking_fraud_log(user_id: str, booking_id: str, vehicle_id: str,
                          event_type: str, severity: str, risk_score: float,
                          description: str, action_taken: str = None,
                          booking_data: Dict = None, payment_data: Dict = None,
                          ml_indicators: List[str] = None, ip_address: str = None) -> int:
    """Add a booking fraud log entry"""
    # CORRECTED: Use get_db_connection() instead of self.get_connection()
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Extract booking data
        bookings_count_last_hour = booking_data.get('count_last_hour') if booking_data else None
        bookings_count_last_day = booking_data.get('count_last_day') if booking_data else None
        avg_interval_minutes = booking_data.get('avg_interval_minutes') if booking_data else None

        # Extract payment data
        decline_count = payment_data.get('decline_count') if payment_data else None
        cards_attempted = payment_data.get('cards_attempted') if payment_data else None
        last_decline_reason = payment_data.get('last_decline_reason') if payment_data else None

        # Convert ml_indicators to JSON
        ml_indicators_json = json.dumps(ml_indicators) if ml_indicators else None

        # Build query with optional fields (ip_address, fraud_score, fraud_type)
        # These are aliases for compatibility
        query = """
            INSERT INTO booking_fraud_logs 
            (user_id, booking_id, vehicle_id, event_type, severity, risk_score,
             description, action_taken, bookings_count_last_hour, bookings_count_last_day,
             avg_interval_minutes, decline_count, cards_attempted, last_decline_reason,
             ml_indicators, ip_address, fraud_score, fraud_type)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """

        cursor.execute(query, (user_id, booking_id, vehicle_id, event_type, severity,
                               risk_score, description, action_taken,
                               bookings_count_last_hour, bookings_count_last_day,
                               avg_interval_minutes, decline_count, cards_attempted,
                               last_decline_reason, ml_indicators_json, ip_address, risk_score, event_type))
        conn.commit()
        log_id = cursor.lastrowid
        cursor.close()

        return log_id

def get_booking_fraud_logs(severity: str = None, event_type: str = None,
                           user_id: str = None, min_risk: float = None,
                           limit: int = 100) -> List[Dict]:
    """Retrieve booking fraud logs with optional filters"""
    # CORRECTED: Use get_db_connection() instead of self.get_connection()
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)

        query = "SELECT * FROM booking_fraud_logs WHERE 1=1"
        params = []

        if severity:
            query += " AND severity = %s"
            params.append(severity)
        if event_type:
            query += " AND event_type = %s"
            params.append(event_type)
        if user_id:
            query += " AND user_id = %s"
            params.append(user_id)
        if min_risk is not None:
            query += " AND risk_score >= %s"
            params.append(min_risk)

        query += " ORDER BY timestamp DESC LIMIT %s"
        params.append(limit)

        cursor.execute(query, params)
        logs = cursor.fetchall()
        cursor.close()

        # Format to match Flask app structure
        for log in logs:
            if log.get('bookings_count_last_hour'):
                log['booking_data'] = {
                    'count_last_hour': log['bookings_count_last_hour'],
                    'count_last_day': log['bookings_count_last_day'],
                    'avg_interval_minutes': float(log['avg_interval_minutes']) if log[
                        'avg_interval_minutes'] else None
                }

            if log.get('decline_count'):
                log['payment_data'] = {
                    'decline_count': log['decline_count'],
                    'cards_attempted': log['cards_attempted'],
                    'last_decline_reason': log['last_decline_reason']
                }

            if log.get('ml_indicators'):
                log['ml_indicators'] = json.loads(log['ml_indicators'])

        return logs

# ============= STATISTICS =============

def get_security_stats() -> Dict[str, Any]:
    """Get security log statistics"""
    # CORRECTED: Use get_db_connection() instead of self.get_connection()
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)

        # Total count
        cursor.execute("SELECT COUNT(*) as total FROM security_logs")
        total = cursor.fetchone()['total']

        # Last 24 hours
        cursor.execute("""
            SELECT COUNT(*) as count FROM security_logs 
            WHERE timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)
        """)
        last_24h = cursor.fetchone()['count']

        # By severity
        cursor.execute("""
            SELECT severity, COUNT(*) as count 
            FROM security_logs 
            GROUP BY severity
        """)
        by_severity = {row['severity']: row['count'] for row in cursor.fetchall()}

        # By type
        cursor.execute("""
            SELECT event_type, COUNT(*) as count 
            FROM security_logs 
            GROUP BY event_type
        """)
        by_type = {row['event_type']: row['count'] for row in cursor.fetchall()}

        cursor.close()

        return {
            'total': total,
            'last_24h': last_24h,
            'by_severity': by_severity,
            'by_type': by_type
        }

def get_vehicle_fraud_stats() -> Dict[str, Any]:
    """Get vehicle fraud statistics"""
    # CORRECTED: Use get_db_connection() instead of self.get_connection()
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT COUNT(*) as total FROM vehicle_fraud_logs")
        total = cursor.fetchone()['total']

        cursor.execute("""
            SELECT COUNT(*) as count FROM vehicle_fraud_logs 
            WHERE timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)
        """)
        last_24h = cursor.fetchone()['count']

        cursor.execute("""
            SELECT COUNT(*) as count FROM vehicle_fraud_logs 
            WHERE risk_score >= 0.8
        """)
        high_risk = cursor.fetchone()['count']

        cursor.execute("""
            SELECT AVG(risk_score) as avg_score FROM vehicle_fraud_logs
        """)
        avg_risk = cursor.fetchone()['avg_score'] or 0

        cursor.execute("""
            SELECT severity, COUNT(*) as count 
            FROM vehicle_fraud_logs 
            GROUP BY severity
        """)
        by_severity = {row['severity']: row['count'] for row in cursor.fetchall()}

        cursor.execute("""
            SELECT event_type, COUNT(*) as count 
            FROM vehicle_fraud_logs 
            GROUP BY event_type
        """)
        by_type = {row['event_type']: row['count'] for row in cursor.fetchall()}

        cursor.close()

        return {
            'total': total,
            'last_24h': last_24h,
            'high_risk': high_risk,
            'avg_risk_score': float(avg_risk),
            'by_severity': by_severity,
            'by_type': by_type
        }

def get_booking_fraud_stats() -> Dict[str, Any]:
    """Get booking fraud statistics"""
    # CORRECTED: Use get_db_connection() instead of self.get_connection()
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT COUNT(*) as total FROM booking_fraud_logs")
        total = cursor.fetchone()['total']

        cursor.execute("""
            SELECT COUNT(*) as count FROM booking_fraud_logs 
            WHERE timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)
        """)
        last_24h = cursor.fetchone()['count']

        cursor.execute("""
            SELECT COUNT(*) as count FROM booking_fraud_logs 
            WHERE risk_score >= 0.8
        """)
        high_risk = cursor.fetchone()['count']

        cursor.execute("""
            SELECT AVG(risk_score) as avg_score FROM booking_fraud_logs
        """)
        avg_risk = cursor.fetchone()['avg_score'] or 0

        cursor.execute("""
            SELECT severity, COUNT(*) as count 
            FROM booking_fraud_logs 
            GROUP BY severity
        """)
        by_severity = {row['severity']: row['count'] for row in cursor.fetchall()}

        cursor.execute("""
            SELECT event_type, COUNT(*) as count 
            FROM booking_fraud_logs 
            GROUP BY event_type
        """)
        by_type = {row['event_type']: row['count'] for row in cursor.fetchall()}

        cursor.close()

        return {
            'total': total,
            'last_24h': last_24h,
            'high_risk': high_risk,
            'avg_risk_score': float(avg_risk),
            'by_severity': by_severity,
            'by_type': by_type
        }


from typing import List, Dict, Optional
import json
from database import get_db_connection

# ============= AUDIT LOGS =============

def add_audit_log(user_id: Optional[int], action: str, entity_type: str, entity_id: str,
                  previous_values: Optional[dict] = None, new_values: Optional[dict] = None,
                  result: str = 'Success', reason: Optional[str] = None,
                  risk_score: float = 0.0, severity: str = 'Low',
                  ip_address: Optional[str] = None, device_info: Optional[str] = None) -> int:
    """Add an audit log entry"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = """
            INSERT INTO audit_logs
            (user_id, action, entity_type, entity_id, previous_values, new_values,
             result, reason, risk_score, severity, ip_address, device_info)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (
            user_id,
            action,
            entity_type,
            str(entity_id),
            json.dumps(previous_values) if previous_values else None,
            json.dumps(new_values) if new_values else None,
            result,
            reason,
            risk_score,
            severity,
            ip_address,
            device_info
        ))
        conn.commit()
        audit_id = cursor.lastrowid
        cursor.close()
        return audit_id



def get_audit_logs(entity_type: Optional[str] = None, entity_id: Optional[str] = None,
                   user_id: Optional[int] = None, limit: int = 100) -> List[Dict]:
    """Retrieve audit logs with optional filters"""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        query = "SELECT * FROM audit_logs WHERE 1=1"
        params = []

        if entity_type:
            query += " AND entity_type = %s"
            params.append(entity_type)
        if entity_id:
            query += " AND entity_id = %s"
            params.append(str(entity_id))
        if user_id:
            query += " AND user_id = %s"
            params.append(user_id)

        query += " ORDER BY timestamp DESC LIMIT %s"
        params.append(limit)

        cursor.execute(query, params)
        logs = cursor.fetchall()
        cursor.close()
        return logs
    
# ============= BACKUP LOGS =============

def add_backup_log(backup_type: str, backup_filename: str, backup_path: str,
                   backup_size_bytes: int, backup_size_mb: float, checksum_sha256: str,
                   tables_backed_up: list, files_included: int = 0,
                   cloud_backup_enabled: bool = False, cloud_backup_path: str = None,
                   status: str = 'Success', error_message: str = None,
                   created_by_user_id: int = None) -> int:
    """Add a backup log entry for proof/verification"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = """
            INSERT INTO backup_logs
            (backup_type, backup_filename, backup_path, backup_size_bytes, backup_size_mb,
             checksum_sha256, tables_backed_up, files_included, cloud_backup_enabled,
             cloud_backup_path, status, error_message, created_by_user_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (
            backup_type,
            backup_filename,
            backup_path,
            backup_size_bytes,
            backup_size_mb,
            checksum_sha256,
            json.dumps(tables_backed_up),
            files_included,
            cloud_backup_enabled,
            cloud_backup_path,
            status,
            error_message,
            created_by_user_id
        ))
        conn.commit()
        backup_id = cursor.lastrowid
        cursor.close()
        return backup_id


def get_backup_logs(limit: int = 100, status: str = None) -> List[Dict]:
    """Get backup logs for verification/proof"""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        query = "SELECT * FROM backup_logs WHERE 1=1"
        params = []
        
        if status:
            query += " AND status = %s"
            params.append(status)
        
        query += " ORDER BY timestamp DESC LIMIT %s"
        params.append(limit)
        
        cursor.execute(query, params)
        logs = cursor.fetchall()
        cursor.close()
        return logs


def update_backup_verification(backup_id: int, verification_status: str):
    """Update backup verification status"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = """
            UPDATE backup_logs 
            SET verification_status = %s, verification_timestamp = NOW()
            WHERE backup_id = %s
        """
        cursor.execute(query, (verification_status, backup_id))
        conn.commit()
        cursor.close()


def get_backup_stats() -> Dict:
    """Get backup statistics for admin dashboard"""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        
        # Total backups
        cursor.execute("SELECT COUNT(*) as total FROM backup_logs")
        total = cursor.fetchone()['total']
        
        # Successful backups
        cursor.execute("SELECT COUNT(*) as success FROM backup_logs WHERE status = 'Success'")
        success = cursor.fetchone()['success']
        
        # Failed backups
        cursor.execute("SELECT COUNT(*) as failed FROM backup_logs WHERE status = 'Failed'")
        failed = cursor.fetchone()['failed']
        
        # Total size
        cursor.execute("SELECT SUM(backup_size_bytes) as total_size FROM backup_logs WHERE status = 'Success'")
        total_size = cursor.fetchone()['total_size'] or 0
        
        # Latest backup
        cursor.execute("SELECT * FROM backup_logs WHERE status = 'Success' ORDER BY timestamp DESC LIMIT 1")
        latest = cursor.fetchone()
        
        # Verified backups
        cursor.execute("SELECT COUNT(*) as verified FROM backup_logs WHERE verification_status = 'Verified'")
        verified = cursor.fetchone()['verified']
        
        cursor.close()
        
        return {
            'total_backups': total,
            'successful_backups': success,
            'failed_backups': failed,
            'total_size_bytes': total_size,
            'total_size_mb': round(total_size / (1024 * 1024), 2),
            'latest_backup': latest,
            'verified_backups': verified
        }


def get_user_by_id(user_id: int):
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT user_id, email, first_name, last_name, phone_number AS phone, nric, license_number FROM users WHERE user_id = %s",
            (user_id,),
        )
        user = cursor.fetchone()
        cursor.close()
        if user:
            user = _decrypt_row("users", user)
        return user


# ============= DATA RETENTION =============

def update_user_last_login(user_id: int):
    """Update last login timestamp for a user."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET last_login_at = NOW() WHERE user_id = %s",
            (user_id,),
        )
        cursor.close()


def get_retention_settings() -> Dict[str, Any]:
    """Fetch data retention settings (single-row table)."""
    defaults = {
        "auto_purge_enabled": 1,
        "retention_days": 365,
        "inactivity_purge_enabled": 1,
        "inactivity_days": 90,
        "apply_to_users": 1,
        "apply_to_sellers": 1,
        "exclude_admins": 1,
        "last_run_at": None,
        "last_run_purged": 0,
        "last_run_reason": None,
        "updated_at": None,
        "updated_by": None,
    }

    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM data_retention_settings WHERE id = 1")
        row = cursor.fetchone()
        cursor.close()

    if not row:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT IGNORE INTO data_retention_settings (id) VALUES (1)")
            cursor.close()
        return defaults

    settings = defaults.copy()
    for key in defaults.keys():
        if key in row and row[key] is not None:
            settings[key] = row[key]

    for flag in ("auto_purge_enabled", "inactivity_purge_enabled",
                 "apply_to_users", "apply_to_sellers", "exclude_admins"):
        value = settings.get(flag)
        try:
            settings[flag] = bool(int(value))
        except (TypeError, ValueError):
            settings[flag] = bool(value)

    return settings


def update_retention_settings(settings: Dict[str, Any], updated_by: str = None) -> None:
    """Update data retention settings."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT IGNORE INTO data_retention_settings (id) VALUES (1)")
        cursor.execute(
            """
            UPDATE data_retention_settings
            SET auto_purge_enabled = %s,
                retention_days = %s,
                inactivity_purge_enabled = %s,
                inactivity_days = %s,
                apply_to_users = %s,
                apply_to_sellers = %s,
                exclude_admins = %s,
                updated_by = %s
            WHERE id = 1
            """,
            (
                int(bool(settings.get("auto_purge_enabled"))),
                int(settings.get("retention_days", 365)),
                int(bool(settings.get("inactivity_purge_enabled"))),
                int(settings.get("inactivity_days", 90)),
                int(bool(settings.get("apply_to_users"))),
                int(bool(settings.get("apply_to_sellers"))),
                int(bool(settings.get("exclude_admins", True))),
                updated_by,
            ),
        )
        cursor.close()


def _table_exists(cursor, table_name: str) -> bool:
    cursor.execute(
        """
        SELECT COUNT(*) FROM information_schema.tables
        WHERE table_schema = DATABASE() AND table_name = %s
        """,
        (table_name,),
    )
    return cursor.fetchone()[0] > 0


def _column_exists(cursor, table_name: str, column_name: str) -> bool:
    cursor.execute(
        """
        SELECT COUNT(*) FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND table_name = %s
          AND column_name = %s
        """,
        (table_name, column_name),
    )
    return cursor.fetchone()[0] > 0


def get_retention_overrides() -> Dict[int, int]:
    """Return {user_id: extension_days}."""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT user_id, extension_days FROM data_retention_overrides")
        rows = cursor.fetchall()
        cursor.close()
    return {row["user_id"]: row.get("extension_days", 0) or 0 for row in rows}


def set_retention_extension(user_id: int, extension_days: int, updated_by: str = None) -> None:
    """Set per-user retention extension days (0 clears)."""
    extension_days = int(extension_days)
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if extension_days <= 0:
            cursor.execute(
                "DELETE FROM data_retention_overrides WHERE user_id = %s",
                (user_id,),
            )
        else:
            cursor.execute(
                """
                INSERT INTO data_retention_overrides (user_id, extension_days, updated_by)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE extension_days = VALUES(extension_days),
                                        updated_by = VALUES(updated_by)
                """,
                (user_id, extension_days, updated_by),
            )
        cursor.close()


def get_retention_users(apply_to_users: bool = True,
                        apply_to_sellers: bool = True,
                        include_admins: bool = False) -> List[Dict[str, Any]]:
    """Fetch user rows needed for retention overview."""
    if not apply_to_users and not apply_to_sellers:
        return []

    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        query = """
            SELECT user_id, first_name, last_name, email, user_type,
                   created_at, last_login_at
            FROM users
        """
        params: List[Any] = []
        where_clauses = []
        role_clauses = []
        if apply_to_users:
            role_clauses.append("(user_type = 'user' OR user_type IS NULL)")
        if apply_to_sellers:
            role_clauses.append("user_type = 'seller'")
        if role_clauses:
            where_clauses.append(f"({' OR '.join(role_clauses)})")
        if not include_admins:
            where_clauses.append("(user_type IS NULL OR user_type <> 'admin')")
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)
        cursor.execute(query, params)
        rows = cursor.fetchall()
        cursor.close()
    # Decrypt sensitive user fields
    return [_decrypt_row("users", row) for row in rows]


def _compute_retention_status(user: Dict[str, Any],
                              settings: Dict[str, Any],
                              extension_days: int,
                              now: datetime) -> Dict[str, Any]:
    created_at = user.get("created_at")
    last_login_at = user.get("last_login_at")

    retention_days = None
    if settings.get("auto_purge_enabled"):
        retention_days = int(settings.get("retention_days", 365)) + max(extension_days, 0)

    inactivity_days = None
    if settings.get("inactivity_purge_enabled"):
        inactivity_days = int(settings.get("inactivity_days", 90)) + max(extension_days, 0)

    retention_deadline = None
    if retention_days and created_at:
        retention_deadline = created_at + timedelta(days=retention_days)

    inactivity_deadline = None
    activity_anchor = last_login_at or created_at
    if inactivity_days and activity_anchor:
        inactivity_deadline = activity_anchor + timedelta(days=inactivity_days)

    deadlines = []
    if retention_deadline:
        deadlines.append(("retention", retention_deadline, retention_days))
    if inactivity_deadline:
        deadlines.append(("inactivity", inactivity_deadline, inactivity_days))

    purge_reason = None
    purge_deadline = None
    rule_days = None
    if deadlines:
        purge_reason, purge_deadline, rule_days = min(deadlines, key=lambda item: item[1])

    days_remaining = None
    if purge_deadline:
        delta = purge_deadline - now
        days_remaining = int(delta.total_seconds() // 86400)

    status = "unknown"
    should_purge = False
    if purge_deadline:
        if purge_deadline <= now:
            status = "overdue"
            should_purge = True
        elif days_remaining is not None and days_remaining <= 30:
            status = "due"
        else:
            status = "ok"

    progress = 0
    if rule_days:
        remaining = max(days_remaining or 0, 0)
        elapsed = rule_days - remaining
        if rule_days > 0:
            progress = int(max(0, min(100, (elapsed / rule_days) * 100)))

    return {
        "purge_deadline": purge_deadline,
        "days_remaining": days_remaining,
        "status": status,
        "should_purge": should_purge,
        "purge_reason": purge_reason,
        "retention_deadline": retention_deadline,
        "inactivity_deadline": inactivity_deadline,
        "retention_days_effective": retention_days,
        "inactivity_days_effective": inactivity_days,
        "progress": progress,
    }


def get_retention_overview(settings: Dict[str, Any] = None,
                           include_admins: bool = False) -> List[Dict[str, Any]]:
    """Return retention overview rows with computed deadlines."""
    if settings is None:
        settings = get_retention_settings()
    overrides = get_retention_overrides()
    users = get_retention_users(
        apply_to_users=settings.get("apply_to_users", True),
        apply_to_sellers=settings.get("apply_to_sellers", True),
        include_admins=include_admins,
    )
    now = datetime.now()

    rows = []
    for user in users:
        extension_days = overrides.get(user.get("user_id"), 0)
        computed = _compute_retention_status(user, settings, extension_days, now)
        rows.append({
            **user,
            **computed,
            "extension_days": extension_days,
        })
    return rows


def get_retention_candidates(settings: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return user rows eligible for retention purge based on settings."""
    overview = get_retention_overview(settings=settings, include_admins=False)
    return [row for row in overview if row.get("should_purge")]


def purge_user_data(user_id: int, email: str = None) -> Dict[str, int]:
    """Delete user data across related tables. Returns per-table delete counts."""
    deleted: Dict[str, int] = {}
    with get_db_connection() as conn:
        cursor = conn.cursor()

        if email is None and _table_exists(cursor, "users") and _column_exists(cursor, "users", "email"):
            cursor.execute("SELECT email FROM users WHERE user_id = %s", (user_id,))
            row = cursor.fetchone()
            if row:
                email = row[0] if not isinstance(row, dict) else row.get("email")

        if _table_exists(cursor, "incident_reports") and _column_exists(cursor, "incident_reports", "user_id"):
            if _table_exists(cursor, "incident_report_files") and _column_exists(cursor, "incident_report_files", "report_id"):
                cursor.execute("SELECT id FROM incident_reports WHERE user_id = %s", (user_id,))
                report_rows = cursor.fetchall()
                report_ids = [
                    (r[0] if not isinstance(r, dict) else r.get("id"))
                    for r in report_rows
                    if (r[0] if not isinstance(r, dict) else r.get("id")) is not None
                ]
                if report_ids:
                    placeholders = ", ".join(["%s"] * len(report_ids))
                    cursor.execute(
                        f"DELETE FROM incident_report_files WHERE report_id IN ({placeholders})",
                        tuple(report_ids),
                    )
                    deleted["incident_report_files"] = cursor.rowcount

        delete_targets = [
            ("booking_fraud_logs", "user_id"),
            ("vehicle_fraud_logs", "user_id"),
            ("security_logs", "user_id"),
            ("audit_logs", "user_id"),
            ("user_documents", "user_id"),
            ("signup_tickets", "user_id"),
            ("bookings", "user_id"),
            ("incident_reports", "user_id"),
            ("backup_logs", "created_by_user_id"),
        ]

        for table_name, column_name in delete_targets:
            if _table_exists(cursor, table_name) and _column_exists(cursor, table_name, column_name):
                cursor.execute(
                    f"DELETE FROM {table_name} WHERE {column_name} = %s",
                    (user_id,),
                )
                deleted[table_name] = cursor.rowcount

        if email and _table_exists(cursor, "password_reset_tokens") and _column_exists(cursor, "password_reset_tokens", "email"):
            cursor.execute(
                "DELETE FROM password_reset_tokens WHERE email = %s",
                (email,),
            )
            deleted["password_reset_tokens"] = cursor.rowcount

        if _table_exists(cursor, "users") and _column_exists(cursor, "users", "user_id"):
            cursor.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
            deleted["users"] = cursor.rowcount

        cursor.close()
    return deleted


def _record_retention_run(purged_count: int, reason: str) -> None:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE data_retention_settings
            SET last_run_at = NOW(),
                last_run_purged = %s,
                last_run_reason = %s
            WHERE id = 1
            """,
            (purged_count, reason),
        )
        cursor.close()


def run_retention_purge(reason: str = "auto") -> Dict[str, Any]:
    """Run retention purge and return summary."""
    settings = get_retention_settings()
    result = {
        "purged_count": 0,
        "candidate_count": 0,
        "errors": [],
        "skipped_reason": None,
    }

    if not settings.get("apply_to_users") and not settings.get("apply_to_sellers"):
        result["skipped_reason"] = "No roles enabled"
        _record_retention_run(0, reason)
        return result

    if not settings.get("auto_purge_enabled") and not settings.get("inactivity_purge_enabled"):
        result["skipped_reason"] = "No purge rules enabled"
        _record_retention_run(0, reason)
        return result

    overview = get_retention_overview(settings=settings, include_admins=False)
    candidates = [row for row in overview if row.get("should_purge")]
    result["candidate_count"] = len(candidates)

    for user in candidates:
        user_id = user.get("user_id")
        try:
            purge_user_data(user_id, user.get("email"))
            result["purged_count"] += 1
        except Exception as exc:
            result["errors"].append({
                "user_id": user_id,
                "error": str(exc),
            })

    _record_retention_run(result["purged_count"], reason)
    return result


# ============= DATA RETENTION POLICIES (Multi-Type) =============

def get_all_retention_policies() -> List[Dict[str, Any]]:
    """Fetch all data retention policies with record counts."""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT * FROM data_retention_policies ORDER BY display_name
        """)
        policies = cursor.fetchall()
        
        # Get record counts for each table
        for policy in policies:
            table_name = policy.get("table_name")
            try:
                cursor.execute(f"SELECT COUNT(*) as cnt FROM {table_name}")
                result = cursor.fetchone()
                policy["record_count"] = result["cnt"] if result else 0
            except:
                policy["record_count"] = 0
            
            # Get count of records due for purge
            date_col = policy.get("date_column")
            retention_days = policy.get("retention_days", 365)
            try:
                cursor.execute(f"""
                    SELECT COUNT(*) as cnt FROM {table_name}
                    WHERE {date_col} < DATE_SUB(NOW(), INTERVAL %s DAY)
                """, (retention_days,))
                result = cursor.fetchone()
                policy["due_for_purge"] = result["cnt"] if result else 0
            except:
                policy["due_for_purge"] = 0
        
        cursor.close()
        return policies


def get_retention_policy(data_type: str) -> Dict[str, Any]:
    """Fetch a single retention policy by data_type."""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT * FROM data_retention_policies WHERE data_type = %s
        """, (data_type,))
        policy = cursor.fetchone()
        cursor.close()
        return policy


def update_retention_policy(data_type: str, settings: Dict[str, Any]) -> bool:
    """Update a retention policy."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE data_retention_policies
            SET retention_days = %s,
                auto_purge_enabled = %s,
                purge_schedule = %s
            WHERE data_type = %s
        """, (
            int(settings.get("retention_days", 365)),
            1 if settings.get("auto_purge_enabled") else 0,
            settings.get("purge_schedule", "daily"),
            data_type,
        ))
        cursor.close()
        return cursor.rowcount > 0


def get_retention_statistics() -> Dict[str, Any]:
    """Get overall retention statistics across all data types."""
    policies = get_all_retention_policies()
    
    total_records = sum(p.get("record_count", 0) for p in policies)
    total_due = sum(p.get("due_for_purge", 0) for p in policies)
    
    # Get last global purge time
    last_purge = None
    for p in policies:
        if p.get("last_purge_at"):
            if not last_purge or p["last_purge_at"] > last_purge:
                last_purge = p["last_purge_at"]
    
    return {
        "total_records": total_records,
        "total_due_for_purge": total_due,
        "last_purge_at": last_purge,
        "policy_count": len(policies),
        "auto_purge_enabled_count": sum(1 for p in policies if p.get("auto_purge_enabled")),
    }


def purge_data_for_type(data_type: str, reason: str = "manual") -> Dict[str, Any]:
    """Purge data for a specific data type based on its retention policy."""
    policy = get_retention_policy(data_type)
    if not policy:
        return {"success": False, "error": "Policy not found", "purged_count": 0}
    
    table_name = policy.get("table_name")
    date_col = policy.get("date_column")
    retention_days = policy.get("retention_days", 365)
    
    result = {
        "success": True,
        "data_type": data_type,
        "purged_count": 0,
        "error": None,
    }
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            # Get count before delete
            cursor.execute(f"""
                SELECT COUNT(*) as cnt FROM {table_name}
                WHERE {date_col} < DATE_SUB(NOW(), INTERVAL %s DAY)
            """, (retention_days,))
            count_row = cursor.fetchone()
            count_to_delete = count_row[0] if count_row else 0
            
            # Perform deletion
            cursor.execute(f"""
                DELETE FROM {table_name}
                WHERE {date_col} < DATE_SUB(NOW(), INTERVAL %s DAY)
            """, (retention_days,))
            
            result["purged_count"] = cursor.rowcount
            
            # Update policy last purge info
            cursor.execute("""
                UPDATE data_retention_policies
                SET last_purge_at = NOW(), last_purge_count = %s
                WHERE data_type = %s
            """, (result["purged_count"], data_type))
            
        except Exception as e:
            result["success"] = False
            result["error"] = str(e)
        
        cursor.close()
    
    return result


def run_all_retention_purges(reason: str = "scheduled") -> Dict[str, Any]:
    """Run retention purge for all enabled data types."""
    policies = get_all_retention_policies()
    
    summary = {
        "total_purged": 0,
        "types_processed": 0,
        "errors": [],
        "details": [],
    }
    
    for policy in policies:
        if not policy.get("auto_purge_enabled"):
            continue
        
        data_type = policy.get("data_type")
        result = purge_data_for_type(data_type, reason)
        
        summary["types_processed"] += 1
        summary["total_purged"] += result.get("purged_count", 0)
        
        if result.get("error"):
            summary["errors"].append({
                "data_type": data_type,
                "error": result["error"],
            })
        
        summary["details"].append({
            "data_type": data_type,
            "display_name": policy.get("display_name"),
            "purged_count": result.get("purged_count", 0),
            "success": result.get("success", False),
        })
    
    return summary

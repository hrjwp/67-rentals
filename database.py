import mysql.connector
from mysql.connector import Error, errorcode
from contextlib import contextmanager
from config import Config
from db_config import DB_CONFIG
from utils.encryption import encrypt_value, decrypt_value
import json
from typing import List, Dict, Any


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
                full_name VARCHAR(255) NOT NULL,
                contact_number VARCHAR(50) NOT NULL,
                email VARCHAR(255) NOT NULL,
                booking_id VARCHAR(50) NOT NULL,
                vehicle_name VARCHAR(255) NOT NULL,
                incident_date DATE NOT NULL,
                incident_time VARCHAR(20) NOT NULL,
                incident_location VARCHAR(255) NOT NULL,
                incident_type VARCHAR(100) NOT NULL,
                severity_level VARCHAR(50) NOT NULL,
                incident_description TEXT NOT NULL,
                status ENUM('Pending Review','Under Review','Resolved') DEFAULT 'Pending Review',
                files_json JSON NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
        values = (
            report.get('user_id'),
            report['full_name'],
            report['contact_number'],
            report['email'],
            report['booking_id'],
            report['vehicle_name'],
            report['incident_date'],
            report['incident_time'],
            report['incident_location'],
            report['incident_type'],
            report['severity_level'],
            report['incident_description'],
            json.dumps(report.get('files', [])) if report.get('files') else None,
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
        # This allows finding reports whether user was logged in or not
        # Use LOWER() for case-insensitive email matching
        if user_id and email:
            clauses.append("(user_id = %s OR LOWER(email) = LOWER(%s))")
            params.extend([user_id, email])
        elif user_id:
            clauses.append("user_id = %s")
            params.append(user_id)
        elif email:
            clauses.append("LOWER(email) = LOWER(%s)")
            params.append(email)

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
        cursor.close()
        conn.close()

        # Decode files JSON
        for row in rows:
            try:
                row['files'] = json.loads(row['files_json']) if row.get('files_json') else []
            except Exception:
                row['files'] = []
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
                          ml_indicators: List[str] = None) -> int:
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

        query = """
            INSERT INTO booking_fraud_logs 
            (user_id, booking_id, vehicle_id, event_type, severity, risk_score,
             description, action_taken, bookings_count_last_hour, bookings_count_last_day,
             avg_interval_minutes, decline_count, cards_attempted, last_decline_reason,
             ml_indicators)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """

        cursor.execute(query, (user_id, booking_id, vehicle_id, event_type, severity,
                               risk_score, description, action_taken,
                               bookings_count_last_hour, bookings_count_last_day,
                               avg_interval_minutes, decline_count, cards_attempted,
                               last_decline_reason, ml_indicators_json))
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

def add_audit_log(user_id: int, action: str, entity_type: str, entity_id: str,
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
    
def get_user_by_id(user_id: int):
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT user_id, email, first_name, last_name FROM users WHERE user_id = %s",
            (user_id,),
        )
        user = cursor.fetchone()
        cursor.close()
        return user


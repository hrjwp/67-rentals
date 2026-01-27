"""
Database Migration Script for ML Fraud Detection
Adds required fields to booking_fraud_logs and vehicle_fraud_logs tables
Run this once to ensure all ML fields are available
"""
from database import get_db_connection, _safe_alter
from mysql.connector import Error, errorcode


def ensure_fraud_logs_tables():
    """Ensure booking_fraud_logs and vehicle_fraud_logs tables exist with all ML fields"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        try:
            # ============= VEHICLE FRAUD LOGS TABLE =============
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vehicle_fraud_logs (
                    vehicle_fraud_log_id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id VARCHAR(50) NOT NULL,
                    vehicle_id VARCHAR(50) NOT NULL,
                    event_type VARCHAR(100) NOT NULL,
                    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') DEFAULT 'MEDIUM',
                    risk_score DECIMAL(5,3) DEFAULT 0.0,
                    description TEXT,
                    action_taken TEXT,
                    prev_location VARCHAR(255),
                    current_location VARCHAR(255),
                    distance_km DECIMAL(10,2),
                    speed_kmh DECIMAL(10,2),
                    reported_mileage DECIMAL(10,2),
                    gps_calculated_mileage DECIMAL(10,2),
                    discrepancy_percent DECIMAL(5,2),
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    ip_address VARCHAR(45),
                    INDEX idx_user_id (user_id),
                    INDEX idx_vehicle_id (vehicle_id),
                    INDEX idx_timestamp (timestamp),
                    INDEX idx_severity (severity),
                    INDEX idx_risk_score (risk_score)
                )
            """)
            print("✓ vehicle_fraud_logs table created/verified")
            
            # Add ML-specific fields if they don't exist
            _safe_alter(cursor, "ALTER TABLE vehicle_fraud_logs ADD COLUMN ip_address VARCHAR(45) NULL")
            _safe_alter(cursor, "ALTER TABLE vehicle_fraud_logs ADD COLUMN ml_indicators JSON NULL")
            _safe_alter(cursor, "ALTER TABLE vehicle_fraud_logs ADD COLUMN fraud_score DECIMAL(5,3) NULL")
            
            # ============= BOOKING FRAUD LOGS TABLE =============
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS booking_fraud_logs (
                    booking_fraud_log_id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id VARCHAR(50) NOT NULL,
                    booking_id VARCHAR(50) NOT NULL,
                    vehicle_id VARCHAR(50),
                    event_type VARCHAR(100) NOT NULL,
                    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') DEFAULT 'MEDIUM',
                    risk_score DECIMAL(5,3) DEFAULT 0.0,
                    description TEXT,
                    action_taken TEXT,
                    bookings_count_last_hour INT DEFAULT 0,
                    bookings_count_last_day INT DEFAULT 0,
                    avg_interval_minutes DECIMAL(10,2),
                    decline_count INT DEFAULT 0,
                    cards_attempted INT DEFAULT 0,
                    last_decline_reason VARCHAR(255),
                    ml_indicators JSON,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    ip_address VARCHAR(45),
                    INDEX idx_user_id (user_id),
                    INDEX idx_booking_id (booking_id),
                    INDEX idx_vehicle_id (vehicle_id),
                    INDEX idx_timestamp (timestamp),
                    INDEX idx_severity (severity),
                    INDEX idx_risk_score (risk_score),
                    INDEX idx_event_type (event_type)
                )
            """)
            print("✓ booking_fraud_logs table created/verified")
            
            # Add ML-specific fields if they don't exist
            _safe_alter(cursor, "ALTER TABLE booking_fraud_logs ADD COLUMN ip_address VARCHAR(45) NULL")
            _safe_alter(cursor, "ALTER TABLE booking_fraud_logs ADD COLUMN fraud_score DECIMAL(5,3) NULL")
            _safe_alter(cursor, "ALTER TABLE booking_fraud_logs ADD COLUMN fraud_type VARCHAR(100) NULL")
            
            # Add alias for fraud_score (some code uses fraud_score, some use risk_score)
            # We'll keep both for compatibility
            
            conn.commit()
            print("\n✅ All ML fraud detection tables and fields are ready!")
            print("\nFields added:")
            print("  booking_fraud_logs:")
            print("    - ip_address (for tracking source IP)")
            print("    - fraud_score (alias for risk_score, for ML compatibility)")
            print("    - fraud_type (alias for event_type, for ML compatibility)")
            print("    - ml_indicators (JSON array of ML detection reasons)")
            print("\n  vehicle_fraud_logs:")
            print("    - ip_address (for tracking source IP)")
            print("    - ml_indicators (JSON array of ML detection reasons)")
            print("    - fraud_score (alias for risk_score, for ML compatibility)")
            
        except Error as e:
            print(f"❌ Error creating tables: {e}")
            conn.rollback()
            raise
        finally:
            cursor.close()


if __name__ == '__main__':
    print("=" * 60)
    print("ML Fraud Detection Database Migration")
    print("=" * 60)
    ensure_fraud_logs_tables()
    print("\n" + "=" * 60)
    print("Migration Complete!")
    print("=" * 60)

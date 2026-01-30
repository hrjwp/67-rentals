"""
ML Behavior Data Collector
Collects user behavior patterns for ML anomaly detection:
- Booking frequency patterns
- Mileage usage patterns
- Travel speed patterns
- Login patterns
"""
from datetime import datetime, timedelta
from database import get_db_connection
from geopy.distance import geodesic
import json


def get_user_booking_patterns(user_id):
    """
    Collect booking frequency patterns for a user
    Returns: dict with booking statistics
    """
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)

        # Get bookings in last hour
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM bookings
            WHERE user_id = %s 
            AND booking_date >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
        """, (user_id,))
        bookings_last_hour = cursor.fetchone()['count'] or 0

        # Get bookings in last day
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM bookings
            WHERE user_id = %s 
            AND booking_date >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        """, (user_id,))
        bookings_last_day = cursor.fetchone()['count'] or 0

        # Calculate average booking interval
        cursor.execute("""
            SELECT booking_date
            FROM bookings
            WHERE user_id = %s
            ORDER BY booking_date DESC
            LIMIT 10
        """, (user_id,))
        recent_bookings = cursor.fetchall()

        avg_interval_minutes = 0
        if len(recent_bookings) > 1:
            intervals = []
            for i in range(len(recent_bookings) - 1):
                dt1 = recent_bookings[i]['booking_date']
                dt2 = recent_bookings[i + 1]['booking_date']
                if isinstance(dt1, str):
                    dt1 = datetime.strptime(dt1, '%Y-%m-%d %H:%M:%S')
                if isinstance(dt2, str):
                    dt2 = datetime.strptime(dt2, '%Y-%m-%d %H:%M:%S')
                if isinstance(dt1, datetime) and isinstance(dt2, datetime):
                    diff = (dt1 - dt2).total_seconds() / 60
                    intervals.append(diff)
            if intervals:
                avg_interval_minutes = sum(intervals) / len(intervals)

        cursor.close()

        return {
            'bookings_last_hour': bookings_last_hour,
            'bookings_last_day': bookings_last_day,
            'avg_booking_interval_minutes': avg_interval_minutes
        }


def get_user_login_patterns(user_id):
    """
    Collect login patterns from security logs
    Returns: dict with login statistics
    """
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)

        # Failed logins
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM security_logs
            WHERE user_id = %s
            AND event_type LIKE 'LOGIN_FAIL%'
            AND timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        """, (str(user_id),))
        failed_logins = cursor.fetchone()['count'] or 0

        # Logins in last hour
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM security_logs
            WHERE user_id = %s
            AND event_type = 'LOGIN_SUCCESS'
            AND timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
        """, (str(user_id),))
        logins_last_hour = cursor.fetchone()['count'] or 0

        cursor.close()

        return {
            'failed_logins': failed_logins,
            'logins_last_hour': logins_last_hour
        }


def get_user_mileage_patterns(user_id, vehicle_id=None):
    """
    Collect mileage patterns from vehicle fraud logs or bookings
    Returns: dict with mileage statistics
    """
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)

        # Try to get recent mileage data from vehicle fraud logs
        # Note: vehicle_fraud_logs uses separate columns, not a JSON mileage_data column
        if vehicle_id:
            cursor.execute("""
                SELECT reported_mileage, gps_calculated_mileage, discrepancy_percent
                FROM vehicle_fraud_logs
                WHERE user_id = %s
                AND vehicle_id = %s
                AND reported_mileage IS NOT NULL
                ORDER BY timestamp DESC
                LIMIT 1
            """, (str(user_id), str(vehicle_id)))
            recent_log = cursor.fetchone()

            if recent_log and recent_log.get('reported_mileage') is not None:
                try:
                    reported = float(recent_log.get('reported_mileage', 0) or 0)
                    gps = float(recent_log.get('gps_calculated_mileage', 0) or 0)

                    cursor.close()
                    return {
                        'reported_mileage': reported,
                        'gps_mileage': gps,
                        'mileage_discrepancy': abs(reported - gps)
                    }
                except Exception as e:
                    print(f"Warning: Error parsing mileage data: {e}")

        cursor.close()

        # Default values if no data found
        return {
            'reported_mileage': 0,
            'gps_mileage': 0,
            'mileage_discrepancy': 0
        }


def get_user_travel_patterns(user_id, current_location=None, prev_location=None, time_diff_minutes=1):
    """
    Calculate travel speed and GPS jump patterns
    Returns: dict with travel statistics
    """
    travel_speed_kmh = 0
    gps_jump_km = 0

    if current_location and prev_location:
        try:
            # Calculate distance
            if isinstance(current_location, (list, tuple)) and isinstance(prev_location, (list, tuple)):
                distance_km = geodesic(prev_location, current_location).kilometers
                gps_jump_km = distance_km

                # Calculate speed
                if time_diff_minutes > 0:
                    travel_speed_kmh = (distance_km / time_diff_minutes) * 60
        except Exception as e:
            print(f"Error calculating travel patterns: {e}")

    return {
        'travel_speed_kmh': travel_speed_kmh,
        'gps_jump_km': gps_jump_km
    }


def get_user_payment_patterns(user_id):
    """
    Collect payment/card patterns
    Returns: dict with payment statistics
    """
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)

        # Card declines from booking fraud logs
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM booking_fraud_logs
            WHERE user_id = %s
            AND fraud_type LIKE '%Card Decline%'
            AND timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        """, (str(user_id),))
        card_declines = cursor.fetchone()['count'] or 0

        # Unique cards used (simplified - would need payment_method tracking)
        unique_cards_count = 1  # Default, would need actual payment method tracking

        cursor.close()

        return {
            'card_declines': card_declines,
            'unique_cards_count': unique_cards_count
        }


def get_user_location_patterns(user_id, current_ip=None, current_country=None):
    """
    Collect location/IP patterns
    Returns: dict with location statistics
    """
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)

        # IP changes in last day
        cursor.execute("""
            SELECT COUNT(DISTINCT ip_address) as count
            FROM security_logs
            WHERE user_id = %s
            AND timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        """, (str(user_id),))
        ip_changes = cursor.fetchone()['count'] or 0

        # Location changes in last hour (from security logs)
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM security_logs
            WHERE user_id = %s
            AND event_type LIKE '%LOCATION%'
            AND timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
        """, (str(user_id),))
        location_changes = cursor.fetchone()['count'] or 0

        cursor.close()

        # VPN detection (simplified - would need actual VPN detection service)
        vpn_detected = 0

        # Country match (simplified)
        ip_country_match = 1 if current_country else 0

        return {
            'ip_changes_last_day': ip_changes,
            'location_changes_last_hour': location_changes,
            'ip_country': current_country or 'Unknown',
            'user_country': current_country or 'Unknown',  # Would get from user profile
            'ip_country_match': ip_country_match,
            'vpn_detected': vpn_detected
        }


def collect_user_behavior_data(user_id, vehicle_id=None, current_location=None,
                               prev_location=None, time_diff_minutes=1,
                               current_ip=None, current_country=None):
    """
    Main function to collect all user behavior data for ML fraud detection
    Returns: dict with all features needed for fraud detection
    """
    # Collect all patterns
    booking_patterns = get_user_booking_patterns(user_id)
    login_patterns = get_user_login_patterns(user_id)
    mileage_patterns = get_user_mileage_patterns(user_id, vehicle_id)
    travel_patterns = get_user_travel_patterns(user_id, current_location, prev_location, time_diff_minutes)
    payment_patterns = get_user_payment_patterns(user_id)
    location_patterns = get_user_location_patterns(user_id, current_ip, current_country)

    # Combine all patterns
    user_data = {
        **booking_patterns,
        **login_patterns,
        **mileage_patterns,
        **travel_patterns,
        **payment_patterns,
        **location_patterns,
        'prev_location': prev_location,
        'current_location': current_location,
        'time_diff_minutes': time_diff_minutes,
        'hour_of_day': datetime.now().hour,
        'is_weekend': 1 if datetime.now().weekday() >= 5 else 0
    }

    return user_data
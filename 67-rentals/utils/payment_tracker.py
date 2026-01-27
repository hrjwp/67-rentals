"""
Payment Decline Tracker
Tracks card declines and payment failures for ML fraud detection
"""
from database import get_db_connection
from datetime import datetime, timedelta


def track_payment_decline(user_id, booking_id, vehicle_id, decline_reason, ip_address=None):
    """
    Track a payment decline and log to booking_fraud_logs if threshold exceeded
    Returns: (should_log_fraud, decline_count)
    """
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        
        # Count declines in last 24 hours for this user
        cursor.execute("""
            SELECT COUNT(*) as decline_count
            FROM booking_fraud_logs
            WHERE user_id = %s
            AND (
                event_type LIKE '%Card Decline%'
                OR fraud_type LIKE '%Card Decline%'
            )
            AND timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        """, (str(user_id),))
        
        result = cursor.fetchone()
        decline_count = (result['decline_count'] or 0) + 1  # +1 for current decline
        
        # We don't store card fingerprints (by design), so treat "cards_attempted" as attempts count.
        cards_attempted = decline_count

        cursor.close()
        
        # Always write a log row for each decline so it appears in MySQL/booking_fraud_logs.
        # (Severity stays LOW unless threshold is exceeded.)
        from database import add_booking_fraud_log

        add_booking_fraud_log(
            user_id=str(user_id),
            booking_id=booking_id or 'N/A',
            vehicle_id=str(vehicle_id) if vehicle_id else None,
            event_type='Card Decline',
            severity='LOW',
            risk_score=0.2,
            description=f"Card decline recorded. Reason: {decline_reason}",
            booking_data={
                'count_last_hour': 0,
                'count_last_day': 0,
                'avg_interval_minutes': 0
            },
            payment_data={
                'decline_count': decline_count,
                'cards_attempted': cards_attempted,
                'last_decline_reason': decline_reason
            },
            ml_indicators=[
                "Card Decline",
                f"Declines (24h): {decline_count}"
            ],
            ip_address=ip_address
        )

        # Log an additional "alert" event if threshold exceeded (>3 declines)
        should_log = decline_count > 3
        
        if should_log:
            # Get booking frequency data
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT 
                    COUNT(*) as bookings_last_hour,
                    (SELECT COUNT(*) FROM bookings 
                     WHERE user_id = %s AND booking_date >= DATE_SUB(NOW(), INTERVAL 24 HOUR)) as bookings_last_day
                FROM bookings
                WHERE user_id = %s
                AND booking_date >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
            """, (user_id, user_id))
            
            booking_stats = cursor.fetchone()
            cursor.close()
            
            # Log to booking fraud logs
            add_booking_fraud_log(
                user_id=str(user_id),
                booking_id=booking_id or 'N/A',
                vehicle_id=str(vehicle_id) if vehicle_id else None,
                event_type='Repeated Card Declines',
                severity='HIGH' if decline_count > 5 else 'MEDIUM',
                risk_score=0.8 if decline_count > 5 else 0.6,
                description=f"Multiple card declines detected: {decline_count} declines in last 24 hours. Last reason: {decline_reason}",
                booking_data={
                    'count_last_hour': booking_stats.get('bookings_last_hour', 0) if booking_stats else 0,
                    'count_last_day': booking_stats.get('bookings_last_day', 0) if booking_stats else 0,
                    'avg_interval_minutes': 0
                },
                payment_data={
                    'decline_count': decline_count,
                    'cards_attempted': cards_attempted,
                    'last_decline_reason': decline_reason
                },
                ml_indicators=[
                    f"Multiple Card Declines: {decline_count} declines",
                    f"Cards Attempted: {cards_attempted}",
                    f"Last Decline: {decline_reason}"
                ],
                ip_address=ip_address
            )
        
        return should_log, decline_count


def get_user_payment_decline_count(user_id, hours=24):
    """Get count of payment declines for a user in the last N hours"""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT COUNT(*) as decline_count
            FROM booking_fraud_logs
            WHERE user_id = %s
            AND (
                event_type LIKE '%Card Decline%'
                OR fraud_type LIKE '%Card Decline%'
            )
            AND timestamp >= DATE_SUB(NOW(), INTERVAL %s HOUR)
        """, (str(user_id), hours))
        
        result = cursor.fetchone()
        cursor.close()
        return result['decline_count'] or 0

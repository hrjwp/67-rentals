"""
Payment Decline Tracker
Tracks card declines and payment failures for ML fraud detection
"""
from database import get_db_connection
from datetime import datetime, timedelta
from fraud_detection import FraudDetector
import os


# Lazy-load a shared FraudDetector instance for this module
_fraud_detector = None
_MODEL_PATH = 'models/fraud_detector.pkl'


def _get_fraud_detector():
    """
    Get (and lazily initialize) the FraudDetector used for risk scoring.
    Falls back to rule-based behavior inside FraudDetector if models are not loaded.
    """
    global _fraud_detector
    if _fraud_detector is None:
        detector = FraudDetector()
        if os.path.exists(_MODEL_PATH):
            try:
                detector.load_models('models/')
            except Exception:
                # If loading fails, keep detector with rule-based checks only
                pass
        _fraud_detector = detector
    return _fraud_detector


def _score_to_severity(score: float) -> str:
    """Map ML fraud score to severity label."""
    if score is None:
        return 'LOW'
    if score >= 0.8:
        return 'HIGH'
    if score >= 0.5:
        return 'MEDIUM'
    return 'LOW'


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

        # Build a minimal user_data dict for the ML model
        fraud_detector = _get_fraud_detector()
        user_data = {
            'user_id': user_id,
            'bookings_last_hour': 0,
            'bookings_last_day': 0,
            'avg_booking_interval_minutes': 0,
            'card_declines': decline_count,
            'unique_cards_count': cards_attempted,
        }

        # Get ML fraud score (0-1), and reasons (may be empty if only rules/partial model)
        ml_score, ml_is_fraud, ml_reasons = fraud_detector.predict_fraud(user_data)
        severity_single = _score_to_severity(ml_score)
        high_risk_single = ml_score is not None and ml_score >= 0.8

        # Always write a log row for each decline so it appears in MySQL/booking_fraud_logs.
        # (Severity stays LOW unless threshold is exceeded.)
        from database import add_booking_fraud_log

        # IMPORTANT:
        # Do NOT force a fake booking_id like 'N/A' here.
        # When there is no real booking row yet, we must pass NULL (None)
        # so the foreign key on booking_fraud_logs(booking_id) is not violated.
        add_booking_fraud_log(
            user_id=str(user_id),
            booking_id=booking_id if booking_id else None,
            vehicle_id=str(vehicle_id) if vehicle_id else None,
            event_type='Card Decline',
            severity=severity_single,
            risk_score=float(ml_score),
            description=(
                f"Card decline recorded. Reason: {decline_reason}. "
                f"ML score={ml_score:.3f}, reasons={', '.join(ml_reasons) if ml_reasons else 'N/A'}"
            ),
            action_taken='FRAUD_BLOCKED' if high_risk_single else None,
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

            # Enrich user_data with booking frequency for repeated-decline ML scoring
            user_data_repeated = {
                'user_id': user_id,
                'bookings_last_hour': booking_stats.get('bookings_last_hour', 0) if booking_stats else 0,
                'bookings_last_day': booking_stats.get('bookings_last_day', 0) if booking_stats else 0,
                'avg_booking_interval_minutes': 0,
                'card_declines': decline_count,
                'unique_cards_count': cards_attempted,
            }

            ml_score_rep, ml_is_fraud_rep, ml_reasons_rep = fraud_detector.predict_fraud(user_data_repeated)
            severity_repeated = _score_to_severity(ml_score_rep)
            high_risk_repeated = ml_score_rep is not None and ml_score_rep >= 0.8

            # Log to booking fraud logs
            # Same rule: only link to a booking when a real booking_id exists.
            add_booking_fraud_log(
                user_id=str(user_id),
                booking_id=booking_id if booking_id else None,
                vehicle_id=str(vehicle_id) if vehicle_id else None,
                event_type='Repeated Card Declines',
                severity=severity_repeated,
                risk_score=float(ml_score_rep),
                description=(
                    f"Multiple card declines detected: {decline_count} declines in last 24 hours. "
                    f"Last reason: {decline_reason}. "
                    f"ML score={ml_score_rep:.3f}, reasons={', '.join(ml_reasons_rep) if ml_reasons_rep else 'N/A'}"
                ),
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
                ip_address=ip_address,
                action_taken='FRAUD_BLOCKED' if high_risk_repeated else None,
            )

        # Determine if this user should be actively blocked for fraud
        high_risk = high_risk_single or (should_log and high_risk_repeated)

        return should_log, decline_count, high_risk


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

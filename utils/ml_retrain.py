"""
ML Model Retraining Module
Automatically retrains the fraud detection model with new user behavior data
to learn normal patterns over time.
"""
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from database import get_db_connection
from fraud_detection import FraudDetector
import os
import json


def collect_historical_behavior_data(days_back=30):
    """
    Collect historical user behavior data from the database
    This learns from actual user patterns over time
    """
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)

        # Get all bookings from the last N days
        cursor.execute("""
            SELECT 
                b.user_id,
                b.vehicle_id,
                b.booking_date,
                b.pickup_date,
                b.return_date,
                b.total_amount,
                vfl.reported_mileage,
                vfl.gps_calculated_mileage,
                vfl.discrepancy_percent,
                vfl.speed_kmh as travel_speed_kmh,
                vfl.distance_km as gps_jump_km,
                bfl.event_type as fraud_type,
                bfl.risk_score as fraud_score,
                sl.event_type,
                sl.timestamp as log_timestamp
            FROM bookings b
            LEFT JOIN vehicle_fraud_logs vfl ON b.user_id = vfl.user_id AND b.vehicle_id = vfl.vehicle_id
            LEFT JOIN booking_fraud_logs bfl ON b.user_id = bfl.user_id AND b.booking_id = bfl.booking_id
            LEFT JOIN security_logs sl ON b.user_id = sl.user_id
            WHERE b.booking_date >= DATE_SUB(NOW(), INTERVAL %s DAY)
            ORDER BY b.booking_date DESC
        """, (days_back,))

        bookings = cursor.fetchall()
        cursor.close()

        return bookings


def aggregate_user_features(user_id, bookings_data):
    """
    Aggregate features for a user from their booking history
    This builds the normal behavior profile
    """
    user_bookings = [b for b in bookings_data if b['user_id'] == user_id]

    if not user_bookings:
        return None

    # Calculate booking frequency patterns
    booking_dates = [b['booking_date'] for b in user_bookings if b['booking_date']]
    bookings_last_hour = 0
    bookings_last_day = 0
    avg_interval_minutes = 0

    if booking_dates:
        now = datetime.now()
        for bd in booking_dates:
            if isinstance(bd, str):
                bd = datetime.strptime(bd, '%Y-%m-%d %H:%M:%S')
            if isinstance(bd, datetime):
                hours_ago = (now - bd).total_seconds() / 3600
                if hours_ago <= 1:
                    bookings_last_hour += 1
                if hours_ago <= 24:
                    bookings_last_day += 1

        # Calculate average interval
        if len(booking_dates) > 1:
            intervals = []
            sorted_dates = sorted([bd if isinstance(bd, datetime) else datetime.strptime(bd, '%Y-%m-%d %H:%M:%S')
                                   for bd in booking_dates], reverse=True)
            for i in range(len(sorted_dates) - 1):
                diff = (sorted_dates[i] - sorted_dates[i + 1]).total_seconds() / 60
                intervals.append(diff)
            if intervals:
                avg_interval_minutes = sum(intervals) / len(intervals)

    # Aggregate mileage patterns from vehicle_fraud_logs (uses separate columns, not JSON)
    reported_mileage = 0
    gps_mileage = 0
    mileage_count = 0

    # Get mileage data from the joined vehicle_fraud_logs data
    for booking in user_bookings:
        if booking.get('reported_mileage') is not None:
            try:
                reported = float(booking.get('reported_mileage', 0) or 0)
                gps = float(booking.get('gps_calculated_mileage', 0) or 0)
                if reported > 0 or gps > 0:
                    reported_mileage += reported
                    gps_mileage += gps
                    mileage_count += 1
            except:
                pass

    if mileage_count > 0:
        reported_mileage = reported_mileage / mileage_count
        gps_mileage = gps_mileage / mileage_count

    # Aggregate travel speeds
    travel_speeds = [b.get('travel_speed_kmh', 0) for b in user_bookings if b.get('travel_speed_kmh', 0) > 0]
    avg_travel_speed = sum(travel_speeds) / len(travel_speeds) if travel_speeds else 0

    # Check for fraud labels
    is_fraud = any(b.get('fraud_type') for b in user_bookings if b.get('fraud_type'))
    fraud_score_avg = np.mean([b.get('fraud_score', 0) or 0 for b in user_bookings if b.get('fraud_score')])

    # Build feature vector
    features = {
        'failed_logins': 0,  # Would aggregate from security logs
        'logins_last_hour': 0,
        'bookings_last_hour': bookings_last_hour,
        'bookings_last_day': bookings_last_day,
        'avg_booking_interval_minutes': avg_interval_minutes,
        'card_declines': 0,  # Would aggregate from payment logs
        'unique_cards_count': 1,
        'reported_mileage': reported_mileage,
        'gps_mileage': gps_mileage,
        'mileage_discrepancy': abs(reported_mileage - gps_mileage),
        'travel_speed_kmh': avg_travel_speed,
        'gps_jump_km': 0,  # Would aggregate
        'location_changes_last_hour': 0,
        'ip_changes_last_day': 0,
        'ip_country_match': 1,
        'vpn_detected': 0,
        'hour_of_day': datetime.now().hour,
        'is_weekend': 1 if datetime.now().weekday() >= 5 else 0
    }

    return features, 1 if is_fraud or fraud_score_avg > 0.7 else 0


def retrain_model_with_new_data(days_back=30, min_samples=50):
    """
    Retrain the ML model with new historical data
    This allows the model to learn normal behavior patterns automatically
    """
    print(f"\n🔄 Starting ML Model Retraining with data from last {days_back} days...")

    # Collect historical data
    bookings_data = collect_historical_behavior_data(days_back)

    if len(bookings_data) < min_samples:
        print(f"⚠️ Not enough data for retraining ({len(bookings_data)} < {min_samples} samples)")
        print("   Model will continue using existing patterns.")
        return False

    # Aggregate features by user
    user_features = {}
    user_labels = {}

    unique_users = set(b['user_id'] for b in bookings_data if b.get('user_id'))

    for user_id in unique_users:
        features, label = aggregate_user_features(user_id, bookings_data)
        if features:
            user_features[user_id] = features
            user_labels[user_id] = label

    if len(user_features) < min_samples:
        print(f"⚠️ Not enough unique users for retraining ({len(user_features)} < {min_samples})")
        return False

    # Convert to DataFrame
    feature_columns = [
        'failed_logins', 'logins_last_hour', 'bookings_last_hour',
        'bookings_last_day', 'avg_booking_interval_minutes',
        'card_declines', 'unique_cards_count', 'reported_mileage',
        'gps_mileage', 'mileage_discrepancy', 'travel_speed_kmh',
        'gps_jump_km', 'location_changes_last_hour', 'ip_changes_last_day',
        'ip_country_match', 'vpn_detected', 'hour_of_day', 'is_weekend'
    ]

    X_data = []
    y_data = []

    for user_id, features in user_features.items():
        row = [features.get(col, 0) for col in feature_columns]
        X_data.append(row)
        y_data.append(user_labels[user_id])

    X = pd.DataFrame(X_data, columns=feature_columns)
    y = pd.Series(y_data)

    print(f"✅ Collected {len(X)} samples for retraining")
    print(f"   Normal users: {sum(y == 0)}, Fraud users: {sum(y == 1)}")

    # Train new model
    try:
        detector = FraudDetector()

        # Train anomaly detection on normal users
        X_normal = X[y == 0]
        if len(X_normal) > 10:
            print("   Training anomaly detection model...")
            detector.train_anomaly_model(X_normal)
            print("   ✅ Anomaly detection trained")

        # Train supervised classifier if we have fraud samples
        if sum(y == 1) > 5:
            print("   Training supervised classifier...")
            detector.train_classifier(X, y)
            print("   ✅ Classifier trained")
        else:
            print("   ⚠️ Not enough fraud samples for supervised training, using anomaly detection only")

        # Save the retrained model
        os.makedirs('models', exist_ok=True)
        detector.save_models('models/')
        print(f"   ✅ Model saved to models/fraud_detector.pkl")
        print(f"\n✅ ML Model Retraining Complete!")
        print(f"   Model now knows normal patterns from {len(X)} users")

        return True

    except Exception as e:
        print(f"❌ Error during retraining: {e}")
        return False


def schedule_periodic_retraining(interval_days=7):
    """
    Schedule periodic retraining (call this from a background thread or cron job)
    This ensures the model learns new normal patterns as user behavior evolves
    """
    import threading
    import time

    def retrain_worker():
        while True:
            try:
                retrain_model_with_new_data(days_back=30)
                # Wait for interval_days before next retraining
                time.sleep(interval_days * 24 * 3600)
            except Exception as e:
                print(f"Error in periodic retraining: {e}")
                time.sleep(3600)  # Retry in 1 hour on error

    thread = threading.Thread(target=retrain_worker, daemon=True)
    thread.start()
    print(f"✅ Periodic ML retraining scheduled (every {interval_days} days)")


if __name__ == '__main__':
# Manual retraining
    retrain_model_with_new_data(days_back=30)
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import pickle
from datetime import datetime
from geopy.distance import geodesic

class FraudDetector:
    def __init__(self):
        # canonical feature order used for training and inference
        self.feature_columns = [
            'failed_logins', 'logins_last_hour', 'bookings_last_hour',
            'bookings_last_day', 'avg_booking_interval_minutes',
            'card_declines', 'unique_cards_count', 'reported_mileage',
            'gps_mileage', 'mileage_discrepancy', 'travel_speed_kmh',
            'gps_jump_km', 'location_changes_last_hour', 'ip_changes_last_day',
            'ip_country_match', 'vpn_detected', 'hour_of_day', 'is_weekend'
        ]

        self.anomaly_model = None
        self.classifier_model = None
        self.scaler = StandardScaler()

    def extract_features(self, user_data):
        # ensure keys exactly match self.feature_columns
        features = {
            'failed_logins': user_data.get('failed_logins', 0),
            'logins_last_hour': user_data.get('logins_last_hour', 0),
            'bookings_last_hour': user_data.get('bookings_last_hour', 0),
            'bookings_last_day': user_data.get('bookings_last_day', 0),
            'avg_booking_interval_minutes': user_data.get('avg_booking_interval_minutes', 0),
            'card_declines': user_data.get('card_declines', 0),
            'unique_cards_count': user_data.get('unique_cards_count', 0),  # matches training
            'reported_mileage': user_data.get('reported_mileage', 0),
            'gps_mileage': user_data.get('gps_mileage', 0),
            'mileage_discrepancy': abs(user_data.get('reported_mileage', 0) - user_data.get('gps_mileage', 0)),
            'travel_speed_kmh': self.calculate_travel_speed(user_data),
            'gps_jump_km': user_data.get('gps_jump_km', user_data.get('gps_jump_distance', 0)),
            'location_changes_last_hour': user_data.get('location_changes_last_hour', user_data.get('location_changes', 0)),
            'ip_changes_last_day': user_data.get('ip_changes_last_day', user_data.get('ip_changes', 0)),
            'ip_country_match': 1 if user_data.get('ip_country') == user_data.get('user_country') else 0,
            'vpn_detected': 1 if user_data.get('vpn_detected', False) else 0,
            'hour_of_day': user_data.get('hour_of_day', datetime.now().hour),
            'is_weekend': user_data.get('is_weekend', 1 if datetime.now().weekday() >= 5 else 0)
        }

        return features

    def calculate_travel_speed(self, user_data):
        if 'prev_location' not in user_data or 'current_location' not in user_data:
            return user_data.get('travel_speed_kmh', 0)
        prev_loc = user_data['prev_location']
        curr_loc = user_data['current_location']
        time_diff = user_data.get('time_diff_minutes', 1)
        if time_diff == 0:
            return 0
        try:
            distance_km = geodesic(prev_loc, curr_loc).kilometers
            return (distance_km / time_diff) * 60
        except Exception:
            return 0

    def rule_based_checks(self, user_data):
        """
        Simple rule-based heuristics returning (is_fraud: bool, reasons: list).
        Expects numeric fields in user_data (falls back to 0 if missing).
        """
        reasons = []

        def num(k):
            try:
                return float(user_data.get(k, 0) or 0)
            except Exception:
                return 0.0

        def intnum(k):
            try:
                return int(user_data.get(k, 0) or 0)
            except Exception:
                return 0

        failed_logins = intnum('failed_logins')
        logins_last_hour = intnum('logins_last_hour')
        bookings_last_hour = intnum('bookings_last_hour')
        bookings_last_day = intnum('bookings_last_day')
        avg_interval = num('avg_booking_interval_minutes')
        card_declines = intnum('card_declines')
        unique_cards = intnum('unique_cards_count')
        reported_mileage = num('reported_mileage')
        gps_mileage = num('gps_mileage')
        mileage_discrepancy = num('mileage_discrepancy') or abs(reported_mileage - gps_mileage)
        travel_speed_kmh = num('travel_speed_kmh')
        gps_jump_km = num('gps_jump_km')
        location_changes = intnum('location_changes_last_hour')
        ip_changes = intnum('ip_changes_last_day')
        ip_country_match = intnum('ip_country_match')
        vpn_detected = intnum('vpn_detected')

        # Login takeover indicators
        if failed_logins >= 5 and logins_last_hour >= 2:
            reasons.append(
                f"High failed logins ({failed_logins}) with recent successes ({logins_last_hour}). Possible account takeover.")

        if ip_changes >= 5 and ip_country_match == 0:
            reasons.append(f"Frequent IP changes ({ip_changes}) and country mismatch. Suspicious access pattern.")

        # Rapid booking / automated booking indicators
        if bookings_last_hour >= 10:
            reasons.append(
                f"Very high bookings in the last hour ({bookings_last_hour}). Rapid booking fraud suspected.")
        if bookings_last_day >= 20 and avg_interval < 30:
            reasons.append(
                f"Many bookings today ({bookings_last_day}) with short avg interval ({avg_interval:.1f} min).")

        # Payment fraud indicators
        if card_declines >= 4 or unique_cards >= 4:
            reasons.append(
                f"Multiple card declines ({card_declines}) or many cards used ({unique_cards}). Payment fraud likely.")

        # Mileage / GPS anomalies
        if mileage_discrepancy > max(30, 0.3 * max(1, reported_mileage)):
            reasons.append(f"Large mileage discrepancy ({mileage_discrepancy}). Mileage tampering suspected.")

        if travel_speed_kmh > 200:
            reasons.append(f"Impossible travel speed ({travel_speed_kmh} km/h). GPS spoofing likely.")

        if gps_jump_km > 100:
            reasons.append(f"Huge GPS jump ({gps_jump_km} km). Teleportation/GPS spoofing suspected.")

        # VPN / location anomalies
        if vpn_detected and ip_country_match == 0:
            reasons.append("VPN detected with IP-country mismatch.")

        is_fraud = len(reasons) > 0
        return is_fraud, reasons

    def predict_fraud(self, user_data):
        # Rule-based checks (unchanged)
        rule_fraud, rule_reasons = self.rule_based_checks(user_data)
        if rule_fraud:
            return 1.0, True, rule_reasons

        # Extract features and build DataFrame with the same columns/order used for training
        features = self.extract_features(user_data)
        feature_df = pd.DataFrame([features], columns=self.feature_columns).fillna(0)

        # Use scaler.transform on a DataFrame to avoid the "valid feature names" warning.
        try:
            # if scaler has been fitted, it has attribute 'mean_' (or feature_names_in_)
            if hasattr(self.scaler, "mean_"):
                feature_scaled = self.scaler.transform(feature_df)
            else:
                feature_scaled = feature_df.values
        except Exception:
            # Fallback to values if any unexpected error occurs
            feature_scaled = feature_df.values

        reasons = []
        fraud_score = 0.0

        # Anomaly detection
        if self.anomaly_model:
            anomaly_score = self.anomaly_model.score_samples(feature_scaled)[0]
            anomaly_prob = 1 / (1 + np.exp(anomaly_score))
            fraud_score = max(fraud_score, anomaly_prob)
            if anomaly_prob > 0.7:
                reasons.append('Unusual behavior pattern detected')

        # Supervised classification
        if self.classifier_model:
            fraud_prob = self.classifier_model.predict_proba(feature_scaled)[0][1]
            fraud_score = max(fraud_score, fraud_prob)
            if fraud_prob > 0.7:
                reasons.append('High fraud probability from historical patterns')

        is_fraud = fraud_score > 0.7
        return fraud_score, is_fraud, reasons

    def save_models(self, path='models/'):
        """Save trained models"""
        with open(f'{path}fraud_detector.pkl', 'wb') as f:
            pickle.dump({
                'anomaly_model': self.anomaly_model,
                'classifier_model': self.classifier_model,
                'scaler': self.scaler
            }, f)

    def load_models(self, path='models/'):
        """Load trained models"""
        with open(f'{path}fraud_detector.pkl', 'rb') as f:
            models = pickle.load(f)
            self.anomaly_model = models['anomaly_model']
            self.classifier_model = models['classifier_model']
            self.scaler = models['scaler']


# Example usage
if __name__ == '__main__':
    detector = FraudDetector()

    # Example user data
    user_data = {
        'failed_logins': 2,
        'logins_last_hour': 3,
        'bookings_last_hour': 2,
        'bookings_last_day': 5,
        'card_declines': 1,
        'reported_mileage': 100,
        'gps_mileage': 98,
        'travel_speed_kmh': 60,
        'gps_jump_km': 10,
        'ip_changes_last_day': 1,
        'ip_country': 'US',
        'user_country': 'US',
        'prev_location': (40.7128, -74.0060),  # NYC
        'current_location': (40.7589, -73.9851),  # Times Square
        'time_diff_minutes': 15
    }

    fraud_score, is_fraud, reasons = detector.predict_fraud(user_data)

    print(f"Fraud Score: {fraud_score:.2f}")
    print(f"Is Fraud: {is_fraud}")
    print(f"Reasons: {reasons}")
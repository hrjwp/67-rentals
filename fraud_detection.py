import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import pickle
from datetime import datetime, timedelta
from geopy.distance import geodesic


class FraudDetector:
    def __init__(self):
        self.anomaly_model = None
        self.classifier_model = None
        self.scaler = StandardScaler()

    def extract_features(self, user_data):
        """
        Extract features from user activity data
        user_data should contain: user_id, timestamp, location, booking_info, payment_info
        """
        features = {}

        # Login pattern features
        features['failed_login_count'] = user_data.get('failed_logins', 0)
        features['login_frequency'] = user_data.get('logins_last_hour', 0)

        # Booking pattern features
        features['bookings_last_hour'] = user_data.get('bookings_last_hour', 0)
        features['bookings_last_day'] = user_data.get('bookings_last_day', 0)
        features['avg_booking_interval'] = user_data.get('avg_booking_interval_minutes', 0)

        # Payment features
        features['card_declines'] = user_data.get('card_declines', 0)
        features['different_cards_used'] = user_data.get('unique_cards_count', 0)

        # Mileage features
        features['reported_mileage'] = user_data.get('reported_mileage', 0)
        features['gps_mileage'] = user_data.get('gps_mileage', 0)
        features['mileage_discrepancy'] = abs(
            user_data.get('reported_mileage', 0) - user_data.get('gps_mileage', 0)
        )

        # Location/Travel features
        features['travel_speed_kmh'] = self.calculate_travel_speed(user_data)
        features['gps_jump_distance'] = user_data.get('gps_jump_km', 0)
        features['location_changes'] = user_data.get('location_changes_last_hour', 0)

        # IP features
        features['ip_changes'] = user_data.get('ip_changes_last_day', 0)
        features['ip_country_match'] = 1 if user_data.get('ip_country') == user_data.get('user_country') else 0
        features['vpn_detected'] = 1 if user_data.get('vpn_detected', False) else 0

        # Time-based features
        features['hour_of_day'] = datetime.now().hour
        features['is_weekend'] = 1 if datetime.now().weekday() >= 5 else 0

        return features

    def calculate_travel_speed(self, user_data):
        """Calculate speed between two GPS points"""
        if 'prev_location' not in user_data or 'current_location' not in user_data:
            return 0

        prev_loc = user_data['prev_location']  # (lat, lon)
        curr_loc = user_data['current_location']  # (lat, lon)
        time_diff = user_data.get('time_diff_minutes', 1)

        if time_diff == 0:
            return 0

        distance_km = geodesic(prev_loc, curr_loc).kilometers
        speed_kmh = (distance_km / time_diff) * 60

        return speed_kmh

    def rule_based_checks(self, user_data):
        """
        Hard rules that immediately flag fraud
        Returns: (is_fraud, fraud_reasons)
        """
        fraud_reasons = []

        # Impossible travel speed (>200 km/h between bookings)
        if user_data.get('travel_speed_kmh', 0) > 200:
            fraud_reasons.append('Impossible travel speed detected')

        # GPS jump (sudden location change >500km)
        if user_data.get('gps_jump_km', 0) > 500:
            fraud_reasons.append('GPS jump detected')

        # Multiple failed logins (>5 in short period)
        if user_data.get('failed_logins', 0) > 5:
            fraud_reasons.append('Multiple failed login attempts')

        # Rapid bookings (>5 in 1 hour)
        if user_data.get('bookings_last_hour', 0) > 5:
            fraud_reasons.append('Abnormal booking frequency')

        # Repeated card declines (>3)
        if user_data.get('card_declines', 0) > 3:
            fraud_reasons.append('Multiple card declines')

        # Mileage fraud (>20% discrepancy)
        reported = user_data.get('reported_mileage', 0)
        gps = user_data.get('gps_mileage', 0)
        if gps > 0 and abs(reported - gps) / gps > 0.20:
            fraud_reasons.append('Mileage discrepancy detected')

        is_fraud = len(fraud_reasons) > 0
        return is_fraud, fraud_reasons

    def train_anomaly_model(self, historical_data):
        """
        Train Isolation Forest for anomaly detection
        historical_data: DataFrame with feature columns
        """
        X = self.scaler.fit_transform(historical_data)

        self.anomaly_model = IsolationForest(
            contamination=0.1,  # Expected % of outliers
            random_state=42,
            n_estimators=100
        )
        self.anomaly_model.fit(X)

    def train_classifier(self, X_train, y_train):
        """
        Train supervised classifier if you have labeled fraud data
        X_train: feature matrix
        y_train: labels (0=normal, 1=fraud)
        """
        X_scaled = self.scaler.fit_transform(X_train)

        self.classifier_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'  # Handle imbalanced data
        )
        self.classifier_model.fit(X_scaled, y_train)

    def predict_fraud(self, user_data):
        """
        Main prediction method
        Returns: fraud_score (0-1), is_fraud (bool), reasons (list)
        """
        # First check hard rules
        rule_fraud, rule_reasons = self.rule_based_checks(user_data)

        if rule_fraud:
            return 1.0, True, rule_reasons

        # Extract features for ML
        features = self.extract_features(user_data)
        feature_array = np.array(list(features.values())).reshape(1, -1)
        feature_scaled = self.scaler.transform(feature_array)

        reasons = []
        fraud_score = 0.0

        # Anomaly detection
        if self.anomaly_model:
            anomaly_score = self.anomaly_model.score_samples(feature_scaled)[0]
            # Convert to 0-1 scale (lower score = more anomalous)
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
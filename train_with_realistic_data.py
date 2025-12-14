from fraud_detection import FraudDetector
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt

# ============= STEP 1: Generate Realistic Data =============
print("=" * 60)
print("STEP 1: Generating Realistic Training Data")
print("=" * 60)

# Import the generator (make sure you saved the previous artifact as generate_realistic_data.py)
from generate_realistic_data import RealisticDataGenerator

generator = RealisticDataGenerator()
dataset = generator.generate_complete_dataset(
    num_legitimate=1000,
    num_fraud=200
)

# Save for later use
dataset.to_csv('realistic_fraud_data.csv', index=False)
print("\n Data generated and saved!")

# ============= STEP 2: Prepare Training Data =============
print("\n" + "=" * 60)
print("STEP 2: Preparing Training Data")
print("=" * 60)

# Select features (remove non-feature columns)
feature_columns = [
    'failed_logins', 'logins_last_hour', 'bookings_last_hour',
    'bookings_last_day', 'avg_booking_interval_minutes',
    'card_declines', 'unique_cards_count', 'reported_mileage',
    'gps_mileage', 'mileage_discrepancy', 'travel_speed_kmh',
    'gps_jump_km', 'location_changes_last_hour', 'ip_changes_last_day',
    'ip_country_match', 'vpn_detected', 'hour_of_day', 'is_weekend'
]

X = dataset[feature_columns]
y = dataset['is_fraud']

# Split into train and test sets (80% train, 20% test)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"Training set: {len(X_train)} samples")
print(f"Test set: {len(X_test)} samples")
print(f"Fraud ratio in training: {y_train.sum() / len(y_train) * 100:.1f}%")

# ============= STEP 3: Train Models =============
print("\n" + "=" * 60)
print("STEP 3: Training ML Models")
print("=" * 60)

detector = FraudDetector()

# Train anomaly detection (unsupervised)
print("\n Training Anomaly Detection Model (Isolation Forest)...")
X_train_normal = X_train[y_train == 0]  # Only normal users for anomaly detection
detector.train_anomaly_model(X_train_normal)
print("✅ Anomaly detection trained!")

# Train supervised classifier
print("\n Training Supervised Classifier (Random Forest)...")
detector.train_classifier(X_train, y_train)
print(" Classifier trained!")

# ============= STEP 4: Evaluate Models =============
print("\n" + "=" * 60)
print("STEP 4: Evaluating Model Performance")
print("=" * 60)

# Test on test set
correct_predictions = 0
fraud_detected = 0
false_positives = 0
false_negatives = 0

predictions = []
for idx in range(len(X_test)):
    # Create user_data dict from test row
    user_data = X_test.iloc[idx].to_dict()
    actual_fraud = y_test.iloc[idx]

    # Predict
    fraud_score, is_fraud, reasons = detector.predict_fraud(user_data)
    predictions.append(is_fraud)

    # Check accuracy
    if is_fraud == actual_fraud:
        correct_predictions += 1

    if is_fraud and actual_fraud:
        fraud_detected += 1
    elif is_fraud and not actual_fraud:
        false_positives += 1
    elif not is_fraud and actual_fraud:
        false_negatives += 1

# Calculate metrics
accuracy = correct_predictions / len(X_test) * 100
precision = fraud_detected / (fraud_detected + false_positives) if (fraud_detected + false_positives) > 0 else 0
recall = fraud_detected / (fraud_detected + false_negatives) if (fraud_detected + false_negatives) > 0 else 0
f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

print("\n MODEL PERFORMANCE:")
print(f"Accuracy: {accuracy:.2f}%")
print(f"Precision: {precision:.2f}")
print(f"Recall: {recall:.2f}")
print(f"F1 Score: {f1_score:.2f}")

print("\n CONFUSION MATRIX:")
print(f"True Positives (Fraud Detected): {fraud_detected}")
print(f"False Positives (False Alarms): {false_positives}")
print(f"False Negatives (Missed Fraud): {false_negatives}")
print(f"True Negatives (Correctly Cleared): {len(X_test) - fraud_detected - false_positives - false_negatives}")

# ============= STEP 5: Save Models =============
print("\n" + "=" * 60)
print("STEP 5: Saving Trained Models")
print("=" * 60)

detector.save_models('models/')
print(" Models saved to models/fraud_detector.pkl")

# ============= STEP 6: Test Examples =============
print("\n" + "=" * 60)
print("STEP 6: Testing with Example Cases")
print("=" * 60)

# Example 1: Legitimate user
print("\n Example 1: Legitimate User")
legitimate_user = {
    'failed_logins': 1,
    'logins_last_hour': 2,
    'bookings_last_hour': 1,
    'bookings_last_day': 3,
    'avg_booking_interval_minutes': 240,
    'card_declines': 0,
    'unique_cards_count': 1,
    'reported_mileage': 85,
    'gps_mileage': 82,
    'mileage_discrepancy': 3,
    'travel_speed_kmh': 65,
    'gps_jump_km': 15,
    'location_changes_last_hour': 1,
    'ip_changes_last_day': 0,
    'ip_country_match': 1,
    'vpn_detected': 0,
    'hour_of_day': 14,
    'is_weekend': 0
}

score, is_fraud, reasons = detector.predict_fraud(legitimate_user)
print(f"Risk Score: {score:.3f}")
print(f"Is Fraud: {is_fraud}")
print(f"Reasons: {reasons if reasons else 'Clean - No fraud detected'}")

# Example 2: Rapid booking fraud
print("\n Example 2: Rapid Booking Fraud")
rapid_booking_fraud = {
    'failed_logins': 2,
    'logins_last_hour': 3,
    'bookings_last_hour': 12,  # RED FLAG
    'bookings_last_day': 25,  # RED FLAG
    'avg_booking_interval_minutes': 5,  # RED FLAG
    'card_declines': 3,
    'unique_cards_count': 5,
    'reported_mileage': 50,
    'gps_mileage': 48,
    'mileage_discrepancy': 2,
    'travel_speed_kmh': 75,
    'gps_jump_km': 40,
    'location_changes_last_hour': 6,
    'ip_changes_last_day': 2,
    'ip_country_match': 0,
    'vpn_detected': 1,
    'hour_of_day': 3,
    'is_weekend': 0
}

score, is_fraud, reasons = detector.predict_fraud(rapid_booking_fraud)
print(f"Risk Score: {score:.3f}")
print(f"Is Fraud: {is_fraud}")
print(f"Reasons: {reasons}")

# Example 3: GPS spoofing
print("\n Example 3: GPS Spoofing / Impossible Travel")
gps_spoof = {
    'failed_logins': 1,
    'logins_last_hour': 2,
    'bookings_last_hour': 2,
    'bookings_last_day': 5,
    'avg_booking_interval_minutes': 90,
    'card_declines': 1,
    'unique_cards_count': 2,
    'reported_mileage': 120,
    'gps_mileage': 115,
    'mileage_discrepancy': 5,
    'travel_speed_kmh': 280,  # RED FLAG - Impossible
    'gps_jump_km': 450,  # RED FLAG - Teleportation
    'location_changes_last_hour': 8,
    'ip_changes_last_day': 3,
    'ip_country_match': 0,
    'vpn_detected': 1,
    'hour_of_day': 2,
    'is_weekend': 1
}

score, is_fraud, reasons = detector.predict_fraud(gps_spoof)
print(f"Risk Score: {score:.3f}")
print(f"Is Fraud: {is_fraud}")
print(f"Reasons: {reasons}")

print("\n" + "=" * 60)
print(" TRAINING COMPLETE!")
print("=" * 60)
print("\nYou can now use the trained model in your Flask app!")
print("The model is saved at: models/fraud_detector.pkl")
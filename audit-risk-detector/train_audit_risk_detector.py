from audit_risk_detector import AuditRiskDetector
from generate_realistic_audit_data import RealisticAuditDataGenerator
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import matplotlib.pyplot as plt
import os

# ============= STEP 1: Generate Realistic Data =============
print("=" * 70)
print("STEP 1: GENERATING REALISTIC AUDIT LOG DATA")
print("=" * 70)

generator = RealisticAuditDataGenerator()
dataset = generator.generate_complete_dataset(
    num_normal=800,
    num_exfiltration=50,
    num_privilege_esc=40,
    num_bulk_delete=35,
    num_automated=35,
    num_recon=40
)

# Save for later use
dataset.to_csv('realistic_audit_data.csv', index=False)
print("\n✓ Data generated and saved to 'realistic_audit_data.csv'!")

# ============= STEP 2: Prepare Training Data =============
print("\n" + "=" * 70)
print("STEP 2: PREPARING TRAINING DATA")
print("=" * 70)

# Feature columns for ML models
feature_columns = [
    'actions_last_hour', 'actions_last_day', 'failed_actions_count',
    'avg_action_interval_minutes', 'sensitive_actions_count',
    'delete_operations_count', 'update_operations_count',
    'create_operations_count', 'view_operations_count',
    'unique_entity_types', 'entity_diversity_score',
    'consecutive_failures', 'privilege_level_changes',
    'data_access_volume', 'unusual_time_score',
    'ip_diversity_score', 'device_changes', 'hour_of_day',
    'is_weekend', 'is_night_hours', 'action_velocity',
    'risk_score_trend', 'anomaly_score'
]

# Add is_night_hours feature
dataset['is_night_hours'] = ((dataset['hour_of_day'] < 6) | (dataset['hour_of_day'] > 22)).astype(int)

X = dataset[feature_columns]
y = dataset['is_suspicious']

# Split into train and test sets (80% train, 20% test)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"Training set: {len(X_train)} samples")
print(f"Test set: {len(X_test)} samples")
print(f"Suspicious ratio in training: {y_train.sum() / len(y_train) * 100:.1f}%")
print(f"Suspicious ratio in testing: {y_test.sum() / len(y_test) * 100:.1f}%")

# ============= STEP 3: Train Models =============
print("\n" + "=" * 70)
print("STEP 3: TRAINING ML MODELS")
print("=" * 70)

detector = AuditRiskDetector()

# Train anomaly detection (unsupervised)
print("\n📊 Training Anomaly Detection Model (Isolation Forest — 150 estimators, contamination=0.04)...")
X_train_normal = X_train[y_train == 0]    # normal samples for fitting
X_train_suspicious = X_train[y_train == 1] # suspicious samples for calibrating danger threshold
detector.train_anomaly_model(X_train_normal, X_train_suspicious)
print("✅ Anomaly detection model trained!")

# Train supervised classifier
print("\n📊 Training Supervised Classifier (Gradient Boosting — sequential error correction)...")
detector.train_classifier(X_train, y_train)
print("✅ Classifier trained!")

# ============= STEP 4: Evaluate Models =============
print("\n" + "=" * 70)
print("STEP 4: EVALUATING MODEL PERFORMANCE")
print("=" * 70)

# Test on test set
correct_predictions = 0
suspicious_detected = 0
false_positives = 0
false_negatives = 0
all_risk_scores = []
all_predictions = []

print("\nProcessing test samples...")
for idx in range(len(X_test)):
    # Create audit_data dict from test row
    audit_data = X_test.iloc[idx].to_dict()
    actual_suspicious = y_test.iloc[idx]
    
    # Add action list (use sample data since we don't have actual actions in features)
    audit_data['recent_actions'] = []
    audit_data['entity_types_accessed'] = []
    
    # Predict
    risk_score, is_suspicious, reasons, risk_level = detector.predict_risk(audit_data)
    all_risk_scores.append(risk_score)
    all_predictions.append(is_suspicious)
    
    # Check accuracy
    if is_suspicious == actual_suspicious:
        correct_predictions += 1
    
    if is_suspicious and actual_suspicious:
        suspicious_detected += 1
    elif is_suspicious and not actual_suspicious:
        false_positives += 1
    elif not is_suspicious and actual_suspicious:
        false_negatives += 1

# Calculate metrics
accuracy = correct_predictions / len(X_test) * 100
true_negatives = len(X_test) - suspicious_detected - false_positives - false_negatives

precision = suspicious_detected / (suspicious_detected + false_positives) if (suspicious_detected + false_positives) > 0 else 0
recall = suspicious_detected / (suspicious_detected + false_negatives) if (suspicious_detected + false_negatives) > 0 else 0
f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
specificity = true_negatives / (true_negatives + false_positives) if (true_negatives + false_positives) > 0 else 0

# Calculate AUC-ROC
try:
    auc_roc = roc_auc_score(y_test, all_risk_scores)
except:
    auc_roc = 0.0

print("\n" + "=" * 70)
print("📈 MODEL PERFORMANCE METRICS")
print("=" * 70)
print(f"Accuracy:    {accuracy:.2f}%")
print(f"Precision:   {precision:.3f} (How many flagged cases were actually suspicious)")
print(f"Recall:      {recall:.3f} (How many suspicious cases were caught)")
print(f"F1 Score:    {f1_score:.3f} (Balance between precision and recall)")
print(f"Specificity: {specificity:.3f} (How many normal cases were correctly identified)")
print(f"AUC-ROC:     {auc_roc:.3f} (Overall model performance)")

print("\n" + "=" * 70)
print("📊 CONFUSION MATRIX")
print("=" * 70)
print(f"✅ True Positives (Suspicious Detected):   {suspicious_detected}")
print(f"❌ False Positives (False Alarms):         {false_positives}")
print(f"❌ False Negatives (Missed Attacks):       {false_negatives}")
print(f"✅ True Negatives (Correctly Cleared):     {true_negatives}")

print("\n" + "=" * 70)
print("🎯 DETECTION EFFECTIVENESS")
print("=" * 70)
print(f"• Out of {y_test.sum()} actual suspicious activities:")
print(f"  → Detected: {suspicious_detected} ({recall*100:.1f}%)")
print(f"  → Missed: {false_negatives} ({(1-recall)*100:.1f}%)")
print(f"\n• Out of {(~y_test.astype(bool)).sum()} normal activities:")
print(f"  → Correctly identified: {true_negatives} ({specificity*100:.1f}%)")
print(f"  → False alarms: {false_positives} ({(1-specificity)*100:.1f}%)")

# ============= STEP 5: Save Models =============
print("\n" + "=" * 70)
print("STEP 5: SAVING TRAINED MODELS")
print("=" * 70)

os.makedirs('models', exist_ok=True)
detector.save_models('models/')
print("✅ Models saved to models/audit_risk_detector.pkl")

# ============= STEP 6: Test Examples =============
print("\n" + "=" * 70)
print("STEP 6: TESTING WITH EXAMPLE SCENARIOS")
print("=" * 70)

# Example 1: Normal admin activity
print("\n" + "=" * 50)
print("EXAMPLE 1: NORMAL ADMIN ACTIVITY")
print("=" * 50)
normal_activity = {
    'actions_last_hour': 5,
    'actions_last_day': 25,
    'failed_actions_count': 1,
    'avg_action_interval_minutes': 12,
    'sensitive_actions_count': 2,
    'delete_operations_count': 1,
    'update_operations_count': 3,
    'create_operations_count': 1,
    'view_operations_count': 0,
    'unique_entity_types': 2,
    'consecutive_failures': 0,
    'privilege_level_changes': 0,
    'data_access_volume': 15,
    'ip_diversity_score': 0,
    'device_changes': 0,
    'hour_of_day': 14,
    'is_weekend': 0,
    'recent_actions': ['UPDATE_VEHICLE', 'UPDATE_BOOKING', 'VIEW_DASHBOARD'],
    'entity_types_accessed': ['VEHICLE', 'BOOKING', 'USER']
}

score, is_suspicious, reasons, risk_level = detector.predict_risk(normal_activity)
print(f"Risk Score:  {score:.3f}")
print(f"Risk Level:  {risk_level}")
print(f"Suspicious:  {'🚨 YES' if is_suspicious else '✅ NO'}")
print(f"Details:     {reasons if reasons else 'Clean - Normal activity pattern'}")

# Example 2: Data exfiltration
print("\n" + "=" * 50)
print("EXAMPLE 2: DATA EXFILTRATION ATTEMPT")
print("=" * 50)
data_exfil = {
    'actions_last_hour': 45,
    'actions_last_day': 180,
    'failed_actions_count': 5,
    'avg_action_interval_minutes': 1.3,
    'sensitive_actions_count': 8,
    'delete_operations_count': 0,
    'update_operations_count': 2,
    'create_operations_count': 0,
    'view_operations_count': 43,
    'unique_entity_types': 6,
    'consecutive_failures': 2,
    'privilege_level_changes': 0,
    'data_access_volume': 250,
    'ip_diversity_score': 3.2,
    'device_changes': 2,
    'hour_of_day': 2,
    'is_weekend': 1,
    'recent_actions': ['EXPORT_USERS', 'BULK_READ', 'DOWNLOAD_LOGS', 'EXPORT_VEHICLES'],
    'entity_types_accessed': ['USER', 'BOOKING', 'VEHICLE', 'PAYMENT', 'DOCUMENT', 'LOG']
}

score, is_suspicious, reasons, risk_level = detector.predict_risk(data_exfil)
print(f"Risk Score:  {score:.3f}")
print(f"Risk Level:  {risk_level}")
print(f"Suspicious:  {'🚨 YES' if is_suspicious else '✅ NO'}")
print(f"Threats:")
for i, reason in enumerate(reasons, 1):
    print(f"  {i}. {reason}")

# Example 3: Privilege escalation
print("\n" + "=" * 50)
print("EXAMPLE 3: PRIVILEGE ESCALATION ATTEMPT")
print("=" * 50)
priv_escalation = {
    'actions_last_hour': 12,
    'actions_last_day': 35,
    'failed_actions_count': 8,
    'avg_action_interval_minutes': 5,
    'sensitive_actions_count': 10,
    'delete_operations_count': 2,
    'update_operations_count': 5,
    'create_operations_count': 3,
    'view_operations_count': 2,
    'unique_entity_types': 3,
    'consecutive_failures': 6,
    'privilege_level_changes': 4,
    'data_access_volume': 45,
    'ip_diversity_score': 4.5,
    'device_changes': 3,
    'hour_of_day': 23,
    'is_weekend': 0,
    'recent_actions': ['UPDATE_ROLE', 'GRANT_ACCESS', 'UPDATE_PERMISSIONS', 'MODIFY_SECURITY'],
    'entity_types_accessed': ['USER', 'PERMISSION', 'ROLE']
}

score, is_suspicious, reasons, risk_level = detector.predict_risk(priv_escalation)
print(f"Risk Score:  {score:.3f}")
print(f"Risk Level:  {risk_level}")
print(f"Suspicious:  {'🚨 YES' if is_suspicious else '✅ NO'}")
print(f"Threats:")
for i, reason in enumerate(reasons, 1):
    print(f"  {i}. {reason}")

# Example 4: Bulk deletion attack
print("\n" + "=" * 50)
print("EXAMPLE 4: BULK DELETION / SABOTAGE")
print("=" * 50)
bulk_delete = {
    'actions_last_hour': 18,
    'actions_last_day': 40,
    'failed_actions_count': 3,
    'avg_action_interval_minutes': 3.3,
    'sensitive_actions_count': 12,
    'delete_operations_count': 8,
    'update_operations_count': 2,
    'create_operations_count': 0,
    'view_operations_count': 8,
    'unique_entity_types': 4,
    'consecutive_failures': 3,
    'privilege_level_changes': 1,
    'data_access_volume': 60,
    'ip_diversity_score': 2.1,
    'device_changes': 1,
    'hour_of_day': 3,
    'is_weekend': 1,
    'recent_actions': ['DELETE_BOOKING', 'DELETE_USER', 'BULK_DELETE', 'DELETE_VEHICLE'],
    'entity_types_accessed': ['BOOKING', 'USER', 'VEHICLE', 'LOG']
}

score, is_suspicious, reasons, risk_level = detector.predict_risk(bulk_delete)
print(f"Risk Score:  {score:.3f}")
print(f"Risk Level:  {risk_level}")
print(f"Suspicious:  {'🚨 YES' if is_suspicious else '✅ NO'}")
print(f"Threats:")
for i, reason in enumerate(reasons, 1):
    print(f"  {i}. {reason}")

# Example 5: Automated bot attack
print("\n" + "=" * 50)
print("EXAMPLE 5: AUTOMATED BOT ATTACK")
print("=" * 50)
bot_attack = {
    'actions_last_hour': 75,
    'actions_last_day': 400,
    'failed_actions_count': 25,
    'avg_action_interval_minutes': 0.8,
    'sensitive_actions_count': 15,
    'delete_operations_count': 3,
    'update_operations_count': 20,
    'create_operations_count': 10,
    'view_operations_count': 42,
    'unique_entity_types': 7,
    'consecutive_failures': 12,
    'privilege_level_changes': 2,
    'data_access_volume': 180,
    'ip_diversity_score': 6.8,
    'device_changes': 5,
    'hour_of_day': 15,
    'is_weekend': 0,
    'recent_actions': ['UPDATE_VEHICLE', 'DELETE_BOOKING', 'CREATE_USER', 'EXPORT_DATA'],
    'entity_types_accessed': ['USER', 'BOOKING', 'VEHICLE', 'PAYMENT', 'PERMISSION', 'LOG', 'DOCUMENT']
}

score, is_suspicious, reasons, risk_level = detector.predict_risk(bot_attack)
print(f"Risk Score:  {score:.3f}")
print(f"Risk Level:  {risk_level}")
print(f"Suspicious:  {'🚨 YES' if is_suspicious else '✅ NO'}")
print(f"Threats:")
for i, reason in enumerate(reasons, 1):
    print(f"  {i}. {reason}")

print("\n" + "=" * 70)
print("✅ TRAINING COMPLETE!")
print("=" * 70)
print("\n🎉 Your AI-powered audit risk detector is ready to use!")
print("📁 Model saved at: models/audit_risk_detector.pkl")
print("📊 Training data saved at: realistic_audit_data.csv")
print("\n💡 Next steps:")
print("  1. Integrate the detector into your Flask app")
print("  2. Use detector.predict_risk(audit_data) to analyze audit logs in real-time")
print("  3. Set up alerts for high-risk activities")
print("  4. Review and retrain periodically with new data")

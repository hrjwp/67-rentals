import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import pickle
from datetime import datetime, timedelta
from collections import Counter
from typing import Dict, List, Tuple, Optional

class AuditRiskDetector:
    """
    AI-powered risk detection system for audit logs
    Detects suspicious activities like privilege escalation, data exfiltration,
    unauthorized access, and unusual administrative actions.
    """
    
    def __init__(self):
        # Canonical feature order for ML models
        self.feature_columns = [
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
        
        self.anomaly_model = None
        self.classifier_model = None
        self.scaler = StandardScaler()
        
        # High-risk action patterns
        self.sensitive_actions = {
            'DELETE_USER', 'DELETE_BOOKING', 'UPDATE_PERMISSIONS', 'GRANT_ACCESS',
            'REVOKE_ACCESS', 'CHANGE_PASSWORD', 'UPDATE_ROLE', 'EXPORT_DATA',
            'BULK_DELETE', 'MODIFY_SECURITY', 'DISABLE_LOGGING', 'ALTER_AUDIT',
            'SYSTEM_CONFIG', 'DATABASE_ACCESS', 'CREDENTIAL_CHANGE'
        }
        
        self.data_exfiltration_patterns = {
            'EXPORT', 'DOWNLOAD', 'VIEW_ALL', 'BULK_READ', 'QUERY_ALL',
            'EXTRACT', 'COPY', 'BACKUP'
        }
        
    def extract_features(self, audit_data: Dict) -> Dict:
        """
        Extract behavioral features from audit log data
        """
        features = {
            # Activity volume metrics
            'actions_last_hour': audit_data.get('actions_last_hour', 0),
            'actions_last_day': audit_data.get('actions_last_day', 0),
            'failed_actions_count': audit_data.get('failed_actions_count', 0),
            'avg_action_interval_minutes': audit_data.get('avg_action_interval_minutes', 0),
            
            # Action type analysis
            'sensitive_actions_count': audit_data.get('sensitive_actions_count', 0),
            'delete_operations_count': audit_data.get('delete_operations_count', 0),
            'update_operations_count': audit_data.get('update_operations_count', 0),
            'create_operations_count': audit_data.get('create_operations_count', 0),
            'view_operations_count': audit_data.get('view_operations_count', 0),
            
            # Diversity metrics
            'unique_entity_types': audit_data.get('unique_entity_types', 0),
            'entity_diversity_score': self.calculate_diversity_score(audit_data),
            
            # Behavioral anomalies
            'consecutive_failures': audit_data.get('consecutive_failures', 0),
            'privilege_level_changes': audit_data.get('privilege_level_changes', 0),
            'data_access_volume': audit_data.get('data_access_volume', 0),
            
            # Temporal patterns
            'unusual_time_score': self.calculate_unusual_time_score(audit_data),
            'hour_of_day': audit_data.get('hour_of_day', datetime.now().hour),
            'is_weekend': audit_data.get('is_weekend', 1 if datetime.now().weekday() >= 5 else 0),
            'is_night_hours': 1 if audit_data.get('hour_of_day', 12) < 6 or audit_data.get('hour_of_day', 12) > 22 else 0,
            
            # Access pattern metrics
            'ip_diversity_score': audit_data.get('ip_diversity_score', 0),
            'device_changes': audit_data.get('device_changes', 0),
            
            # Velocity and trend metrics
            'action_velocity': self.calculate_action_velocity(audit_data),
            'risk_score_trend': audit_data.get('risk_score_trend', 0),
            'anomaly_score': audit_data.get('anomaly_score', 0)
        }
        
        return features
    
    def calculate_diversity_score(self, audit_data: Dict) -> float:
        """
        Calculate how diverse the entity types accessed are
        High diversity might indicate reconnaissance or data exfiltration
        """
        entity_types = audit_data.get('entity_types_accessed', [])
        if not entity_types:
            return 0.0
        
        # Shannon entropy for diversity
        counts = Counter(entity_types)
        total = len(entity_types)
        entropy = -sum((count/total) * np.log2(count/total) for count in counts.values() if count > 0)
        
        # Normalize to 0-10 scale
        max_entropy = np.log2(len(counts)) if len(counts) > 1 else 1
        return (entropy / max_entropy) * 10 if max_entropy > 0 else 0
    
    def calculate_unusual_time_score(self, audit_data: Dict) -> float:
        """
        Score how unusual the timing of actions is
        Higher score = more unusual (night/weekend/rapid succession)
        """
        score = 0.0
        hour = audit_data.get('hour_of_day', 12)
        is_weekend = audit_data.get('is_weekend', 0)
        avg_interval = audit_data.get('avg_action_interval_minutes', 60)
        
        # Night hours (11 PM - 6 AM)
        if hour < 6 or hour > 22:
            score += 3.0
        # Early morning (6-8 AM) or late evening (8-11 PM)
        elif hour < 8 or hour > 20:
            score += 1.5
        
        # Weekend activity
        if is_weekend:
            score += 2.0
        
        # Rapid-fire actions (less than 5 seconds between actions)
        if avg_interval < 0.083:  # 5 seconds in minutes
            score += 4.0
        elif avg_interval < 1:  # Less than 1 minute
            score += 2.0
        
        return min(score, 10.0)  # Cap at 10
    
    def calculate_action_velocity(self, audit_data: Dict) -> float:
        """
        Calculate the speed of actions (actions per minute)
        """
        actions_last_hour = audit_data.get('actions_last_hour', 0)
        if actions_last_hour == 0:
            return 0.0
        return actions_last_hour / 60.0  # Actions per minute
    
    def rule_based_checks(self, audit_data: Dict) -> Tuple[bool, List[str]]:
        """
        Rule-based detection for obvious suspicious patterns
        Returns: (is_suspicious, list of reasons)
        """
        reasons = []
        
        def num(k):
            try:
                return float(audit_data.get(k, 0) or 0)
            except:
                return 0.0
        
        def intnum(k):
            try:
                return int(audit_data.get(k, 0) or 0)
            except:
                return 0
        
        # Extract metrics
        actions_last_hour = intnum('actions_last_hour')
        actions_last_day = intnum('actions_last_day')
        failed_actions = intnum('failed_actions_count')
        consecutive_failures = intnum('consecutive_failures')
        sensitive_actions = intnum('sensitive_actions_count')
        delete_ops = intnum('delete_operations_count')
        privilege_changes = intnum('privilege_level_changes')
        data_access = intnum('data_access_volume')
        ip_diversity = num('ip_diversity_score')
        device_changes = intnum('device_changes')
        hour_of_day = intnum('hour_of_day')
        is_weekend = intnum('is_weekend')
        unique_entities = intnum('unique_entity_types')
        
        # Get action list for pattern matching
        recent_actions = audit_data.get('recent_actions', [])
        
        # === PRIVILEGE ESCALATION DETECTION ===
        if privilege_changes >= 3:
            reasons.append(
                f"Multiple privilege level changes detected ({privilege_changes}). "
                f"Possible privilege escalation attempt."
            )
        
        if sensitive_actions >= 5 and failed_actions >= 2:
            reasons.append(
                f"High number of sensitive actions ({sensitive_actions}) with failures ({failed_actions}). "
                f"Suspicious administrative activity."
            )
        
        # === BRUTE FORCE / UNAUTHORIZED ACCESS ===
        if consecutive_failures >= 5:
            reasons.append(
                f"Consecutive failed actions ({consecutive_failures}). "
                f"Possible unauthorized access attempt or brute force."
            )
        
        if failed_actions >= 10 and actions_last_hour >= 15:
            reasons.append(
                f"Unusual failure rate: {failed_actions} failures with {actions_last_hour} actions in last hour. "
                f"Account may be compromised."
            )
        
        # === DATA EXFILTRATION DETECTION ===
        if data_access >= 100 or (actions_last_hour >= 20 and unique_entities >= 5):
            reasons.append(
                f"High data access volume ({data_access} records, {unique_entities} entity types). "
                f"Possible data exfiltration or reconnaissance."
            )
        
        # Check for exfiltration patterns in actions
        exfil_count = sum(1 for action in recent_actions 
                         if any(pattern in action.upper() for pattern in self.data_exfiltration_patterns))
        if exfil_count >= 3:
            reasons.append(
                f"Multiple data export/download operations detected ({exfil_count}). "
                f"Possible data exfiltration attempt."
            )
        
        # === BULK DELETION ATTACK ===
        if delete_ops >= 5:
            reasons.append(
                f"Excessive deletion operations ({delete_ops}). "
                f"Possible sabotage or data destruction attempt."
            )
        
        if delete_ops >= 3 and consecutive_failures >= 2:
            reasons.append(
                f"Multiple delete attempts with failures. "
                f"Unauthorized deletion attempt likely."
            )
        
        # === RAPID AUTOMATED ACTIVITY ===
        avg_interval = num('avg_action_interval_minutes')
        if actions_last_hour >= 30 and avg_interval < 1:
            reasons.append(
                f"Extremely rapid actions ({actions_last_hour} in 1 hour, avg {avg_interval:.2f} min apart). "
                f"Automated attack or bot activity suspected."
            )
        
        # === SUSPICIOUS TIMING ===
        if (hour_of_day < 5 or hour_of_day > 23) and actions_last_hour >= 10:
            reasons.append(
                f"High activity during unusual hours ({hour_of_day}:00 with {actions_last_hour} actions). "
                f"Possible unauthorized access during off-hours."
            )
        
        if is_weekend and sensitive_actions >= 3:
            reasons.append(
                f"Sensitive administrative actions during weekend. "
                f"Unusual behavior pattern detected."
            )
        
        # === IP/DEVICE ANOMALIES ===
        if ip_diversity >= 5 and actions_last_day >= 20:
            reasons.append(
                f"High IP diversity ({ip_diversity:.1f} score) with frequent actions. "
                f"Possible account sharing or compromise."
            )
        
        if device_changes >= 3 and actions_last_day >= 15:
            reasons.append(
                f"Multiple device changes ({device_changes}) with high activity. "
                f"Unusual access pattern detected."
            )
        
        # === PATTERN-BASED DETECTION ===
        # Check for reconnaissance pattern (view multiple entities quickly)
        view_ops = intnum('view_operations_count')
        if view_ops >= 15 and unique_entities >= 4 and avg_interval < 5:
            reasons.append(
                f"Rapid viewing of multiple entity types ({unique_entities} types, {view_ops} views). "
                f"Reconnaissance activity suspected."
            )
        
        # Check for credential harvesting
        password_changes = sum(1 for action in recent_actions if 'PASSWORD' in action.upper() or 'CREDENTIAL' in action.upper())
        if password_changes >= 3:
            reasons.append(
                f"Multiple password/credential related actions ({password_changes}). "
                f"Possible credential harvesting or account takeover."
            )
        
        is_suspicious = len(reasons) > 0
        return is_suspicious, reasons
    
    def predict_risk(self, audit_data: Dict) -> Tuple[float, bool, List[str], str]:
        """
        Main prediction function
        Returns: (risk_score, is_suspicious, reasons, risk_level)

        Score composition:
          - Rule-based hits contribute up to 0.30 per fired rule (capped at 0.90)
          - ML signals (anomaly + classifier) contribute the remaining weight
          - Final = 0.70 * ml_score + 0.30 * rule_score
          This prevents a single mild rule from hard-coding 1.0 and ensures
          normal admin activity is not persistently flagged as High/Critical.
        """
        # Run rule-based checks — collect reasons but don't short-circuit
        rule_suspicious, rule_reasons = self.rule_based_checks(audit_data)
        # Scale: each rule adds ~0.30; cap total rule contribution at 0.90
        rule_score = float(np.clip(0.30 * len(rule_reasons), 0.0, 0.90))

        # Extract features for ML models
        features = self.extract_features(audit_data)
        feature_df = pd.DataFrame([features], columns=self.feature_columns).fillna(0)

        # Always pass a plain numpy array (no column names) to avoid sklearn's
        # feature-name validation.  Column ORDER is fixed by self.feature_columns.
        feature_arr = feature_df.values  # shape (1, 23)

        # Scale features — guard against a mismatched scaler
        try:
            if hasattr(self.scaler, "mean_"):
                scaler_n = getattr(self.scaler, 'n_features_in_', feature_arr.shape[1])
                arr_for_scaler = feature_arr
                if arr_for_scaler.shape[1] != scaler_n:
                    if arr_for_scaler.shape[1] < scaler_n:
                        pad = np.zeros((1, scaler_n - arr_for_scaler.shape[1]))
                        arr_for_scaler = np.hstack([arr_for_scaler, pad])
                    else:
                        arr_for_scaler = arr_for_scaler[:, :scaler_n]
                feature_scaled = self.scaler.transform(arr_for_scaler)
                # After scaling, ensure the output has the right number of columns
                # for the downstream models (handles the scaler-retrained-on-17 case)
                for model_name, model_obj in [('anomaly', self.anomaly_model),
                                               ('classifier', self.classifier_model)]:
                    if model_obj is None:
                        continue
                    model_n = getattr(model_obj, 'n_features_in_', feature_scaled.shape[1])
                    if feature_scaled.shape[1] != model_n:
                        if feature_scaled.shape[1] < model_n:
                            pad = np.zeros((1, model_n - feature_scaled.shape[1]))
                            feature_scaled = np.hstack([feature_scaled, pad])
                        else:
                            feature_scaled = feature_scaled[:, :model_n]
                        break  # same fix applies to both models
            else:
                feature_scaled = feature_arr
        except Exception:
            feature_scaled = feature_arr

        reasons = list(rule_reasons)
        ml_score = 0.0

        # Anomaly detection
        if self.anomaly_model:
            raw_score = self.anomaly_model.score_samples(feature_scaled)[0]

            # Normalise relative to training score distribution:
            # score_max (≈0 for normal) → 0.0 anomaly  |  score_min (very negative) → 1.0 anomaly
            score_min = getattr(self, '_anomaly_score_min', -0.5)
            score_max = getattr(self, '_anomaly_score_max', 0.0)
            score_range = score_max - score_min
            if score_range > 0:
                anomaly_prob = float(np.clip((score_max - raw_score) / score_range, 0.0, 1.0))
            else:
                anomaly_prob = float(np.clip(-raw_score / 0.5, 0.0, 1.0))

            ml_score = max(ml_score, anomaly_prob)
            if anomaly_prob > 0.65:
                reasons.append('Unusual audit log pattern detected by anomaly detection')

        # Supervised classification
        if self.classifier_model:
            risk_prob = self.classifier_model.predict_proba(feature_scaled)[0][1]
            ml_score = max(ml_score, risk_prob)
            if risk_prob > 0.6:
                reasons.append('High risk probability based on historical patterns')

        # Combine: ML is the primary driver; rules add weight on top
        if self.anomaly_model or self.classifier_model:
            risk_score = float(np.clip(0.70 * ml_score + 0.30 * rule_score, 0.0, 1.0))
        else:
            # No ML models loaded — rely solely on rule score
            risk_score = rule_score

        is_suspicious = risk_score > 0.6
        risk_level = self.calculate_risk_level(risk_score)

        return risk_score, is_suspicious, reasons, risk_level
    
    def calculate_risk_level(self, risk_score: float) -> str:
        """Convert risk score to risk level"""
        if risk_score >= 0.8:
            return 'Critical'
        elif risk_score >= 0.6:
            return 'High'
        elif risk_score >= 0.4:
            return 'Medium'
        else:
            return 'Low'
    
    def train_anomaly_model(self, X_train: pd.DataFrame):
        """Train anomaly detection model on normal audit logs"""
        X_arr = X_train.values if hasattr(X_train, 'values') else np.array(X_train)
        self.scaler.fit(X_arr)
        X_scaled = self.scaler.transform(X_arr)
        
        self.anomaly_model = IsolationForest(
            contamination=0.05,   # lower = fewer false positives on clean data
            random_state=42,
            n_estimators=100
        )
        self.anomaly_model.fit(X_scaled)

        # Store the score distribution on training (normal) data so we can
        # normalise future scores relative to what "normal" looks like.
        train_scores = self.anomaly_model.score_samples(X_scaled)
        self._anomaly_score_min = float(train_scores.min())
        self._anomaly_score_max = float(train_scores.max())
    
    def train_classifier(self, X_train: pd.DataFrame, y_train: pd.Series):
        """Train supervised classifier on labeled audit logs"""
        X_arr = X_train.values if hasattr(X_train, 'values') else np.array(X_train)
        if not hasattr(self.scaler, "mean_"):
            self.scaler.fit(X_arr)
        
        X_scaled = self.scaler.transform(X_arr)
        
        self.classifier_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        self.classifier_model.fit(X_scaled, y_train)
    
    def save_models(self, path='models/'):
        """Save trained models"""
        import os
        os.makedirs(path, exist_ok=True)
        
        with open(f'{path}audit_risk_detector.pkl', 'wb') as f:
            pickle.dump({
                'anomaly_model': self.anomaly_model,
                'classifier_model': self.classifier_model,
                'scaler': self.scaler,
                'anomaly_score_min': getattr(self, '_anomaly_score_min', -0.5),
                'anomaly_score_max': getattr(self, '_anomaly_score_max', 0.0),
            }, f)
    
    def load_models(self, path='models/'):
        """
        Load trained models.
        Validates every component was trained on len(self.feature_columns) features.
        If a corrupted / mismatched pkl is found (e.g. one written by an old retrainer
        that only used 17 features), the bad file is deleted and a FileNotFoundError is
        raised so the caller falls back to rule-based detection until retrained.
        """
        import os
        pkl_path = f'{path}audit_risk_detector.pkl'
        with open(pkl_path, 'rb') as fh:
            models = pickle.load(fh)

        anomaly_model    = models['anomaly_model']
        classifier_model = models['classifier_model']
        scaler           = models['scaler']

        expected = len(self.feature_columns)  # always 23

        # Validate feature counts on every component
        bad = []
        for name, obj in [('scaler', scaler),
                          ('anomaly_model', anomaly_model),
                          ('classifier_model', classifier_model)]:
            n = getattr(obj, 'n_features_in_', None)
            if n is not None and n != expected:
                bad.append(f'{name} has {n} features (expected {expected})')

        if bad:
            print(f'WARNING: Corrupt pkl at {pkl_path}:')
            for msg in bad:
                print(f'  - {msg}')
            print('  Deleting corrupt pkl — will retrain on next scheduled run.')
            try:
                os.remove(pkl_path)
            except OSError:
                pass
            raise FileNotFoundError(
                f'Corrupt pkl deleted ({", ".join(bad)}). '
                'Re-run train_audit_risk_detector.py to rebuild.'
            )

        self.anomaly_model    = anomaly_model
        self.classifier_model = classifier_model
        self.scaler           = scaler

        if 'anomaly_score_min' in models and 'anomaly_score_max' in models:
            self._anomaly_score_min = models['anomaly_score_min']
            self._anomaly_score_max = models['anomaly_score_max']
        else:
            self._calibrate_anomaly_bounds()

    def _calibrate_anomaly_bounds(self):
        """
        Derive _anomaly_score_min / _anomaly_score_max from the loaded model
        by scoring a representative batch of synthetic normal-looking data.
        Called automatically for legacy pkls that don't store these bounds.
        """
        if self.anomaly_model is None or self.scaler is None:
            self._anomaly_score_min = -0.5
            self._anomaly_score_max = -0.3
            return
        try:
            n = 300
            rng = np.random.RandomState(42)
            n_features = getattr(self.scaler, 'n_features_in_', 23)
            # Generate plausible normal activity: low counts, low diversity
            # Use zeros as a safe baseline that is definitely "normal"
            synthetic = np.zeros((n, n_features))
            # actions_last_hour ≈ 3-6, actions_last_day ≈ 15-35
            synthetic[:, 0] = rng.poisson(4, n)
            synthetic[:, 1] = rng.poisson(25, n)
            # failed actions ≈ 0-1
            synthetic[:, 2] = rng.binomial(4, 0.05, n)
            # avg_interval ≈ 10-20 min
            synthetic[:, 3] = rng.uniform(8, 25, n)
            # hour_of_day ≈ business hours (col 17)
            if n_features > 17:
                synthetic[:, 17] = rng.randint(8, 18, n)

            scaled = self.scaler.transform(synthetic)
            scores = self.anomaly_model.score_samples(scaled)
            # Use a slightly wider range than [min, max] so a score
            # exactly at the training min doesn't map to 1.0 immediately
            self._anomaly_score_min = float(scores.min()) - 0.05
            self._anomaly_score_max = float(scores.max())
        except Exception:
            self._anomaly_score_min = -0.65
            self._anomaly_score_max = -0.40


# Example usage
if __name__ == '__main__':
    detector = AuditRiskDetector()
    
    # Example 1: Normal admin activity
    print("=" * 70)
    print("EXAMPLE 1: NORMAL ADMIN ACTIVITY")
    print("=" * 70)
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
    
    risk_score, is_suspicious, reasons, risk_level = detector.predict_risk(normal_activity)
    print(f"Risk Score: {risk_score:.3f}")
    print(f"Risk Level: {risk_level}")
    print(f"Is Suspicious: {is_suspicious}")
    print(f"Reasons: {reasons if reasons else 'Clean - Normal activity pattern'}")
    
    # Example 2: Data exfiltration attempt
    print("\n" + "=" * 70)
    print("EXAMPLE 2: DATA EXFILTRATION ATTEMPT")
    print("=" * 70)
    data_exfil = {
        'actions_last_hour': 45,
        'actions_last_day': 180,
        'failed_actions_count': 5,
        'avg_action_interval_minutes': 1.3,
        'sensitive_actions_count': 8,
        'delete_operations_count': 0,
        'update_operations_count': 2,
        'create_operations_count': 0,
        'view_operations_count': 35,
        'unique_entity_types': 6,
        'consecutive_failures': 2,
        'privilege_level_changes': 0,
        'data_access_volume': 250,
        'ip_diversity_score': 3.2,
        'device_changes': 2,
        'hour_of_day': 2,
        'is_weekend': 1,
        'recent_actions': ['EXPORT_USERS', 'BULK_READ_BOOKINGS', 'DOWNLOAD_LOGS', 'EXPORT_VEHICLES', 'VIEW_ALL_USERS'],
        'entity_types_accessed': ['USER', 'BOOKING', 'VEHICLE', 'PAYMENT', 'DOCUMENT', 'LOG']
    }
    
    risk_score, is_suspicious, reasons, risk_level = detector.predict_risk(data_exfil)
    print(f"Risk Score: {risk_score:.3f}")
    print(f"Risk Level: {risk_level}")
    print(f"Is Suspicious: {is_suspicious}")
    print(f"Reasons:")
    for reason in reasons:
        print(f"  - {reason}")
    
    # Example 3: Privilege escalation attempt
    print("\n" + "=" * 70)
    print("EXAMPLE 3: PRIVILEGE ESCALATION ATTEMPT")
    print("=" * 70)
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
        'recent_actions': ['UPDATE_ROLE', 'GRANT_ACCESS', 'UPDATE_PERMISSIONS', 'CHANGE_PASSWORD', 'MODIFY_SECURITY'],
        'entity_types_accessed': ['USER', 'PERMISSION', 'ROLE']
    }
    
    risk_score, is_suspicious, reasons, risk_level = detector.predict_risk(priv_escalation)
    print(f"Risk Score: {risk_score:.3f}")
    print(f"Risk Level: {risk_level}")
    print(f"Is Suspicious: {is_suspicious}")
    print(f"Reasons:")
    for reason in reasons:
        print(f"  - {reason}")
    
    # Example 4: Bulk deletion attack
    print("\n" + "=" * 70)
    print("EXAMPLE 4: BULK DELETION ATTACK")
    print("=" * 70)
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
        'recent_actions': ['DELETE_BOOKING', 'DELETE_USER', 'BULK_DELETE', 'DELETE_VEHICLE', 'DELETE_LOG'],
        'entity_types_accessed': ['BOOKING', 'USER', 'VEHICLE', 'LOG']
    }
    
    risk_score, is_suspicious, reasons, risk_level = detector.predict_risk(bulk_delete)
    print(f"Risk Score: {risk_score:.3f}")
    print(f"Risk Level: {risk_level}")
    print(f"Is Suspicious: {is_suspicious}")
    print(f"Reasons:")
    for reason in reasons:
        print(f"  - {reason}")

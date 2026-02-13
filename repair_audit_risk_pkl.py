"""
repair_audit_risk_pkl.py
------------------------
One-time fix: replaces the corrupted/mismatched audit_risk_detector.pkl on disk
with a known-good version that has the correct 23-feature models AND has the
anomaly score bounds calibrated and stored.

Run this ONCE from the project root:
    python repair_audit_risk_pkl.py

It will:
  1. Check whether models/audit_risk_detector.pkl exists and has the right shape
  2. If it's corrupted (17-feature models from the old retrainer bug), delete it
     and rebuild using the original training data in realistic_audit_data.csv
  3. If it's already good, just add the score-bounds metadata and re-save
"""

import os, sys, pickle, numpy as np, pandas as pd
from pathlib import Path

MODEL_DIR   = Path('audit-risk-detector/models')
PKL_PATH    = MODEL_DIR / 'audit_risk_detector.pkl'
DATA_PATH   = Path('audit-risk-detector/realistic_audit_data.csv')
EXPECTED_N  = 23   # the number of features the current code always uses

FEATURE_COLUMNS = [
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

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent / 'audit-risk-detector'))


def check_pkl(path):
    """Returns (is_good, n_scaler, n_anomaly, n_classifier, has_bounds)"""
    if not path.exists():
        return False, None, None, None, False
    with open(path, 'rb') as f:
        m = pickle.load(f)
    sc = m.get('scaler')
    am = m.get('anomaly_model')
    cm = m.get('classifier_model')
    ns = getattr(sc, 'n_features_in_', None)
    na = getattr(am, 'n_features_in_', None)
    nc = getattr(cm, 'n_features_in_', None)
    has_bounds = 'anomaly_score_min' in m and 'anomaly_score_max' in m
    is_good = all(n == EXPECTED_N for n in [ns, na, nc] if n is not None)
    return is_good, ns, na, nc, has_bounds


def calibrate_bounds(anomaly_model, scaler):
    """Score synthetic normal data to find the real score distribution."""
    rng = np.random.RandomState(42)
    n = 400
    synthetic = np.zeros((n, EXPECTED_N))
    synthetic[:, 0] = rng.poisson(4, n)       # actions_last_hour
    synthetic[:, 1] = rng.poisson(25, n)      # actions_last_day
    synthetic[:, 2] = rng.binomial(4, 0.05, n)  # failed_actions_count
    synthetic[:, 3] = rng.uniform(8, 25, n)   # avg_action_interval_minutes
    synthetic[:, 17] = rng.randint(8, 18, n)  # hour_of_day (business hours)
    scaled = scaler.transform(synthetic)
    scores = anomaly_model.score_samples(scaled)
    return float(scores.min()) - 0.05, float(scores.max())


def retrain_from_csv(data_path, model_dir):
    """Full retrain from the training CSV."""
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split

    print(f'  Loading training data from {data_path}…')
    df = pd.read_csv(data_path)

    # Compute derived features that may be missing from CSV
    if 'is_night_hours' not in df.columns:
        df['is_night_hours'] = ((df['hour_of_day'] < 6) | (df['hour_of_day'] > 22)).astype(int)
    if 'action_velocity' not in df.columns:
        df['action_velocity'] = df['actions_last_hour'] / 60.0
    if 'entity_diversity_score' not in df.columns:
        df['entity_diversity_score'] = 0.0
    if 'unusual_time_score' not in df.columns:
        df['unusual_time_score'] = 0.0
    if 'risk_score_trend' not in df.columns:
        df['risk_score_trend'] = 0.0
    if 'anomaly_score' not in df.columns:
        df['anomaly_score'] = 0.0

    available = [c for c in FEATURE_COLUMNS if c in df.columns]
    missing   = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        print(f'  Missing columns (will be zero-filled): {missing}')
        for c in missing:
            df[c] = 0.0

    X = df[FEATURE_COLUMNS].fillna(0)
    y = df['is_suspicious'].astype(int)

    X_train, _, y_train, _ = train_test_split(X, y, test_size=0.2,
                                               random_state=42, stratify=y)
    X_normal = X_train[y_train == 0]

    scaler = StandardScaler()
    X_arr = X_normal.values
    scaler.fit(X_arr)

    X_scaled = scaler.transform(X_arr)
    anomaly_model = IsolationForest(contamination=0.05, random_state=42, n_estimators=100)
    anomaly_model.fit(X_scaled)
    train_scores = anomaly_model.score_samples(X_scaled)
    score_min = float(train_scores.min()) - 0.05
    score_max = float(train_scores.max())

    X_all_scaled = scaler.transform(X_train.values)
    classifier = RandomForestClassifier(n_estimators=100, max_depth=10,
                                        random_state=42, class_weight='balanced')
    classifier.fit(X_all_scaled, y_train)

    model_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        'anomaly_model': anomaly_model,
        'classifier_model': classifier,
        'scaler': scaler,
        'anomaly_score_min': score_min,
        'anomaly_score_max': score_max,
    }
    with open(model_dir / 'audit_risk_detector.pkl', 'wb') as f:
        pickle.dump(payload, f)

    print(f'  Retrained on {len(X_train)} samples ({int(y_train.sum())} suspicious).')
    print(f'  Score bounds: min={score_min:.4f}, max={score_max:.4f}')
    return score_min, score_max


# ─── Main ────────────────────────────────────────────────────────────────────

print('=' * 60)
print('Audit Risk PKL Repair Utility')
print('=' * 60)

is_good, ns, na, nc, has_bounds = check_pkl(PKL_PATH)

print(f'\nPKL path : {PKL_PATH}')
print(f'Exists   : {PKL_PATH.exists()}')
if PKL_PATH.exists():
    print(f'Features : scaler={ns}, anomaly={na}, classifier={nc} (need {EXPECTED_N})')
    print(f'Has bounds stored: {has_bounds}')
    print(f'Is valid : {is_good}')

if not PKL_PATH.exists():
    print('\nNo pkl found.')
    if DATA_PATH.exists():
        print('Training CSV found — retraining…')
        retrain_from_csv(DATA_PATH, MODEL_DIR)
        print('✅ Retrained successfully.')
    else:
        print(f'ERROR: No training data at {DATA_PATH} either.')
        print('Run train_audit_risk_detector.py manually to create the model.')
        sys.exit(1)

elif not is_good:
    print('\n⚠️  Corrupted pkl detected (wrong feature count). Deleting and retraining…')
    PKL_PATH.unlink(missing_ok=True)
    if DATA_PATH.exists():
        retrain_from_csv(DATA_PATH, MODEL_DIR)
        print('✅ Retrained from CSV successfully.')
    else:
        print(f'ERROR: No training data at {DATA_PATH}.')
        print('Run train_audit_risk_detector.py manually.')
        sys.exit(1)

elif not has_bounds:
    print('\nPKL is valid but missing anomaly score bounds — patching…')
    with open(PKL_PATH, 'rb') as f:
        m = pickle.load(f)
    score_min, score_max = calibrate_bounds(m['anomaly_model'], m['scaler'])
    m['anomaly_score_min'] = score_min
    m['anomaly_score_max'] = score_max
    with open(PKL_PATH, 'wb') as f:
        pickle.dump(m, f)
    print(f'  Score bounds calibrated: min={score_min:.4f}, max={score_max:.4f}')
    print('✅ PKL patched successfully.')

else:
    print('\n✅ PKL is already valid and has score bounds — nothing to do.')

# Final verification
is_good2, ns2, na2, nc2, has_bounds2 = check_pkl(PKL_PATH)
print(f'\nFinal check: features={ns2}/{na2}/{nc2}, bounds={has_bounds2}, valid={is_good2}')

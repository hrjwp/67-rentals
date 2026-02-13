"""
audit_risk_retrainer.py
-----------------------
Periodic retraining scheduler for the AuditRiskDetector.

Usage in app.py (add near the top, after audit_risk_analyzer is initialised):

    from audit_risk_retrainer import schedule_audit_risk_retraining
    schedule_audit_risk_retraining(
        analyzer=audit_risk_analyzer,
        interval_days=7,          # retrain every 7 days
        min_new_samples=200,      # only retrain if there are enough new logs
        model_path='audit-risk-detector/models/'
    )
"""

import threading
import time
import logging
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)


def retrain_audit_risk_model(
    analyzer,
    model_path: str = 'audit-risk-detector/models/',
    days_back: int = 30,
    min_samples: int = 200,
) -> bool:
    """
    Pull recent audit logs from the DB, rebuild features, and retrain both
    the anomaly model and the supervised classifier.

    Returns True if retraining succeeded, False otherwise.
    """
    try:
        import pandas as pd
        import numpy as np
        from database import get_db_connection

        logger.info("[AuditRiskRetrainer] Fetching recent audit logs for retraining…")

        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                """
                SELECT user_id, action, entity_type, result, timestamp,
                       ip_address, device_info, risk_score
                FROM audit_logs
                WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY)
                ORDER BY timestamp DESC
                """,
                (days_back,),
            )
            raw_logs = cursor.fetchall()
            cursor.close()

        if len(raw_logs) < min_samples:
            logger.info(
                f"[AuditRiskRetrainer] Only {len(raw_logs)} logs found "
                f"(need {min_samples}). Skipping retraining."
            )
            return False

        # ── Group logs by user ───────────────────────────────────────────────
        from collections import defaultdict

        user_logs: dict = defaultdict(list)
        for log in raw_logs:
            uid = log.get("user_id")
            if uid:
                user_logs[uid].append(log)

        if len(user_logs) < 10:
            logger.info("[AuditRiskRetrainer] Too few unique users. Skipping.")
            return False

        # ── Build feature rows per user ──────────────────────────────────────
        rows = []
        for uid, logs in user_logs.items():
            try:
                # analyzer.prepare_audit_data_from_logs expects two lists:
                # (recent_logs last-24h, last-hour logs).
                # We approximate with all logs for this user from the window
                # and a synthetic "last hour" subset.
                now = datetime.now()
                one_hour_ago = now - timedelta(hours=1)
                last_hour = [
                    l for l in logs
                    if l.get("timestamp") and (
                        (l["timestamp"] if isinstance(l["timestamp"], datetime)
                         else datetime.strptime(str(l["timestamp"]), '%Y-%m-%d %H:%M:%S'))
                        >= one_hour_ago
                    )
                ]
                # convert to tuple format expected by prepare_audit_data_from_logs:
                # (action, entity_type, entity_id, result, timestamp, ip, device, risk_score)
                def to_tuple(l):
                    return (
                        l.get("action", ""),
                        l.get("entity_type", ""),
                        None,
                        l.get("result", "Success"),
                        l.get("timestamp"),
                        l.get("ip_address", ""),
                        l.get("device_info", ""),
                        l.get("risk_score", 0),
                    )

                recent_tuples = [to_tuple(l) for l in logs]
                hour_tuples   = [to_tuple(l) for l in last_hour]

                raw_features = analyzer.prepare_audit_data_from_logs(recent_tuples, hour_tuples)

                # Run through extract_features() so the 6 computed columns
                # (entity_diversity_score, unusual_time_score, is_night_hours,
                #  action_velocity, risk_score_trend, anomaly_score) are included.
                # This gives us all 23 columns that the scaler/models expect.
                full_features = analyzer.detector.extract_features(raw_features)

                # Label: 'suspicious' if the user's average stored risk_score > 0.5
                scores = [l.get("risk_score") or 0 for l in logs]
                label = 1 if (sum(scores) / len(scores)) > 0.5 else 0

                feature_row = dict(full_features)
                feature_row["is_suspicious"] = label
                rows.append(feature_row)
            except Exception as e:
                logger.debug(f"[AuditRiskRetrainer] Skipping user {uid}: {e}")
                continue

        if len(rows) < 10:
            logger.info("[AuditRiskRetrainer] Not enough feature rows. Skipping.")
            return False

        df = pd.DataFrame(rows).fillna(0)

        # Must match detector.feature_columns exactly — all 23 columns
        # (the 6 computed ones are now present because we ran extract_features above)
        feature_cols = analyzer.detector.feature_columns
        # Only keep columns that actually exist in df (safety guard)
        feature_cols = [c for c in feature_cols if c in df.columns]

        X = df[feature_cols]
        y = df['is_suspicious']

        # ── Retrain ──────────────────────────────────────────────────────────
        X_normal = X[y == 0]
        if len(X_normal) >= 5:
            analyzer.detector.train_anomaly_model(X_normal)

        if len(X) >= 10 and y.sum() >= 2:
            analyzer.detector.train_classifier(X, y)

        analyzer.detector.save_models(model_path)
        logger.info(
            f"[AuditRiskRetrainer] ✅ Retrained on {len(df)} user profiles "
            f"({int(y.sum())} suspicious). Saved to {model_path}"
        )
        return True

    except Exception as e:
        logger.error(f"[AuditRiskRetrainer] ❌ Retraining failed: {e}", exc_info=True)
        return False


def schedule_audit_risk_retraining(
    analyzer,
    interval_days: int = 7,
    min_new_samples: int = 200,
    model_path: str = 'audit-risk-detector/models/',
    startup_delay_seconds: int = 120,
):
    """
    Start a background thread that retrains the audit risk model every
    ``interval_days`` days.

    Parameters
    ----------
    analyzer : AuditRiskAnalyzer
        The live analyzer instance used by the Flask app.
    interval_days : int
        How often to retrain (default: 7 days).
    min_new_samples : int
        Minimum number of audit log rows needed to trigger a retrain.
    model_path : str
        Where to save the updated model.
    startup_delay_seconds : int
        Seconds to wait after app start before the first retrain attempt
        (gives the app time to fully initialise).
    """

    def _worker():
        logger.info(
            f"[AuditRiskRetrainer] Scheduler started — "
            f"retraining every {interval_days} day(s). "
            f"First run in {startup_delay_seconds}s."
        )
        time.sleep(startup_delay_seconds)

        interval_seconds = interval_days * 86_400
        while True:
            ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            logger.info(f"[AuditRiskRetrainer] [{ts}] Starting scheduled retrain…")
            retrain_audit_risk_model(
                analyzer=analyzer,
                model_path=model_path,
                min_samples=min_new_samples,
            )
            time.sleep(interval_seconds)

    t = threading.Thread(target=_worker, daemon=True, name="AuditRiskRetrainer")
    t.start()
    return t

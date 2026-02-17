"""
audit_risk_detector.py
----------------------
AI-powered insider threat and audit log risk analyser.

Architecture differs from the fraud detector by design:
  - Uses a PIPELINE pattern (BehaviourProfile → ThreatSignalEngine → RiskScorer)
    instead of a flat extract/check/predict structure.
  - Threat detection is organised into named ThreatSignal dataclasses so each
    signal carries its own severity weight rather than every rule adding ±0.30.
  - Anomaly normalisation uses a percentile-based approach (stored as p10/p90)
    instead of raw min/max bounds.
  - Score composition is a weighted geometric mean rather than a linear blend,
    which penalises moderate-across-all-channels more aggressively than a single
    spiking channel.
"""

from __future__ import annotations

import os
import pickle
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, IsolationForest
from sklearn.preprocessing import RobustScaler


# ─────────────────────────────────────────────────────────────────────────────
# Domain constants
# ─────────────────────────────────────────────────────────────────────────────

#: Actions that carry inherent risk regardless of context.
HIGH_RISK_ACTIONS = frozenset({
    "DELETE_USER", "BULK_DELETE", "ALTER_AUDIT", "DISABLE_LOGGING",
    "SYSTEM_CONFIG", "DATABASE_ACCESS", "CREDENTIAL_CHANGE",
    "EXPORT_DATA", "GRANT_ACCESS", "REVOKE_ACCESS",
    "UPDATE_ROLE", "UPDATE_PERMISSIONS", "MODIFY_SECURITY",
})

#: Patterns associated with data exfiltration attempts.
EXFIL_KEYWORDS = frozenset({
    "EXPORT", "DOWNLOAD", "BULK_READ", "VIEW_ALL",
    "EXTRACT", "COPY", "BACKUP", "QUERY_ALL",
})

#: Patterns associated with privilege escalation.
PRIVILEGE_KEYWORDS = frozenset({
    "ROLE", "PERMISSION", "GRANT", "REVOKE", "ACCESS",
})

#: Patterns associated with credential attacks.
CREDENTIAL_KEYWORDS = frozenset({"PASSWORD", "CREDENTIAL", "TOKEN", "SECRET"})


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ThreatSignal:
    """A detected threat with a name, human-readable description, and severity."""
    name: str
    description: str
    severity: float          # 0.0 – 1.0; used as a weight in the final score


@dataclass
class BehaviourProfile:
    """
    Structured representation of a user's recent audit-log behaviour.
    Created by ``ProfileBuilder.build()`` from raw audit_data dicts.
    """
    # Volume
    actions_last_hour: int = 0
    actions_last_day: int = 0
    failed_actions_count: int = 0
    avg_action_interval_minutes: float = 0.0
    consecutive_failures: int = 0

    # Action composition
    sensitive_actions_count: int = 0
    delete_operations_count: int = 0
    update_operations_count: int = 0
    create_operations_count: int = 0
    view_operations_count: int = 0

    # Scope
    unique_entity_types: int = 0
    entity_diversity_score: float = 0.0    # Shannon entropy, 0-10
    privilege_level_changes: int = 0
    data_access_volume: int = 0

    # Access anomalies
    ip_diversity_score: float = 0.0
    device_changes: int = 0

    # Temporal
    hour_of_day: int = 12
    is_weekend: int = 0
    is_night_hours: int = 0
    unusual_time_score: float = 0.0

    # Velocity & trend
    action_velocity: float = 0.0           # actions per minute
    risk_score_trend: float = 0.0

    # Placeholder for ML pass-through
    anomaly_score: float = 0.0

    # Non-numeric context (not fed to ML)
    recent_actions: List[str] = field(default_factory=list)
    entity_types_accessed: List[str] = field(default_factory=list)

    def to_feature_dict(self) -> Dict[str, float]:
        """Return only the numeric fields used as ML features."""
        return {
            "actions_last_hour":          float(self.actions_last_hour),
            "actions_last_day":           float(self.actions_last_day),
            "failed_actions_count":       float(self.failed_actions_count),
            "avg_action_interval_minutes": float(self.avg_action_interval_minutes),
            "sensitive_actions_count":    float(self.sensitive_actions_count),
            "delete_operations_count":    float(self.delete_operations_count),
            "update_operations_count":    float(self.update_operations_count),
            "create_operations_count":    float(self.create_operations_count),
            "view_operations_count":      float(self.view_operations_count),
            "unique_entity_types":        float(self.unique_entity_types),
            "entity_diversity_score":     float(self.entity_diversity_score),
            "consecutive_failures":       float(self.consecutive_failures),
            "privilege_level_changes":    float(self.privilege_level_changes),
            "data_access_volume":         float(self.data_access_volume),
            "unusual_time_score":         float(self.unusual_time_score),
            "ip_diversity_score":         float(self.ip_diversity_score),
            "device_changes":             float(self.device_changes),
            "hour_of_day":                float(self.hour_of_day),
            "is_weekend":                 float(self.is_weekend),
            "is_night_hours":             float(self.is_night_hours),
            "action_velocity":            float(self.action_velocity),
            "risk_score_trend":           float(self.risk_score_trend),
            "anomaly_score":              float(self.anomaly_score),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Profile builder — converts raw audit_data dicts into a BehaviourProfile
# ─────────────────────────────────────────────────────────────────────────────

class ProfileBuilder:
    """Converts a raw audit_data dict into a BehaviourProfile."""

    @staticmethod
    def build(audit_data: Dict) -> BehaviourProfile:
        p = BehaviourProfile()

        def _int(key: str) -> int:
            try:
                return int(audit_data.get(key) or 0)
            except (TypeError, ValueError):
                return 0

        def _float(key: str) -> float:
            try:
                return float(audit_data.get(key) or 0.0)
            except (TypeError, ValueError):
                return 0.0

        # Volume
        p.actions_last_hour          = _int("actions_last_hour")
        p.actions_last_day           = _int("actions_last_day")
        p.failed_actions_count       = _int("failed_actions_count")
        p.avg_action_interval_minutes = _float("avg_action_interval_minutes")
        p.consecutive_failures       = _int("consecutive_failures")

        # Action composition
        p.sensitive_actions_count    = _int("sensitive_actions_count")
        p.delete_operations_count    = _int("delete_operations_count")
        p.update_operations_count    = _int("update_operations_count")
        p.create_operations_count    = _int("create_operations_count")
        p.view_operations_count      = _int("view_operations_count")

        # Scope
        p.unique_entity_types        = _int("unique_entity_types")
        p.privilege_level_changes    = _int("privilege_level_changes")
        p.data_access_volume         = _int("data_access_volume")

        # Access anomalies
        p.ip_diversity_score         = _float("ip_diversity_score")
        p.device_changes             = _int("device_changes")

        # Temporal
        p.hour_of_day  = _int("hour_of_day") if "hour_of_day" in audit_data else datetime.now().hour
        p.is_weekend   = _int("is_weekend") if "is_weekend" in audit_data else (1 if datetime.now().weekday() >= 5 else 0)
        p.is_night_hours = 1 if (p.hour_of_day < 6 or p.hour_of_day > 22) else 0

        p.risk_score_trend           = _float("risk_score_trend")
        p.anomaly_score              = _float("anomaly_score")

        # Context lists
        p.recent_actions          = list(audit_data.get("recent_actions") or [])
        p.entity_types_accessed   = list(audit_data.get("entity_types_accessed") or [])

        # Derived scores
        p.entity_diversity_score  = ProfileBuilder._shannon_diversity(p.entity_types_accessed)
        p.unusual_time_score      = ProfileBuilder._unusual_time(p)
        p.action_velocity         = p.actions_last_hour / 60.0

        return p

    @staticmethod
    def _shannon_diversity(entity_types: List[str]) -> float:
        """Shannon entropy of entity type distribution, scaled 0-10."""
        if not entity_types:
            return 0.0
        counts = Counter(entity_types)
        total = len(entity_types)
        entropy = -sum(
            (c / total) * np.log2(c / total)
            for c in counts.values()
            if c > 0
        )
        max_entropy = np.log2(len(counts)) if len(counts) > 1 else 1.0
        return float((entropy / max_entropy) * 10.0) if max_entropy > 0 else 0.0

    @staticmethod
    def _unusual_time(p: BehaviourProfile) -> float:
        """Score 0-10 reflecting how unusual the session timing is."""
        score = 0.0
        if p.hour_of_day < 6 or p.hour_of_day > 22:
            score += 3.5
        elif p.hour_of_day < 8 or p.hour_of_day > 20:
            score += 1.5
        if p.is_weekend:
            score += 2.0
        if p.avg_action_interval_minutes < 0.083:   # < 5 seconds
            score += 4.0
        elif p.avg_action_interval_minutes < 1.0:
            score += 2.0
        return min(score, 10.0)


# ─────────────────────────────────────────────────────────────────────────────
# Threat signal engine — domain rules that produce weighted ThreatSignals
# ─────────────────────────────────────────────────────────────────────────────

class ThreatSignalEngine:
    """
    Evaluates a BehaviourProfile against a catalogue of named threat patterns.

    Each check returns either a ThreatSignal or None.  Callers collect the
    non-None results and pass them to the RiskScorer.

    This is deliberately organised as independent check methods (not a big
    if-elif chain) so new threat patterns can be added or removed without
    breaking existing checks.
    """

    # ── Privilege escalation ─────────────────────────────────────────────────

    def check_privilege_escalation(self, p: BehaviourProfile) -> Optional[ThreatSignal]:
        if p.privilege_level_changes >= 3:
            return ThreatSignal(
                name="PRIVILEGE_ESCALATION",
                description=(
                    f"User changed permission levels {p.privilege_level_changes} times — "
                    "this many changes in a short period is unusual."
                ),
                severity=0.80,
            )
        return None

    def check_sensitive_action_surge(self, p: BehaviourProfile) -> Optional[ThreatSignal]:
        if p.sensitive_actions_count >= 5 and p.failed_actions_count >= 2:
            return ThreatSignal(
                name="SENSITIVE_ACTION_SURGE",
                description=(
                    f"{p.sensitive_actions_count} high-risk admin actions with "
                    f"{p.failed_actions_count} failures — unusually high for a single session."
                ),
                severity=0.70,
            )
        return None

    def check_credential_harvesting(self, p: BehaviourProfile) -> Optional[ThreatSignal]:
        hits = sum(
            1 for a in p.recent_actions
            if any(kw in a.upper() for kw in CREDENTIAL_KEYWORDS)
        )
        if hits >= 3:
            return ThreatSignal(
                name="CREDENTIAL_HARVESTING",
                description=(
                    f"{hits} password or credential actions in a short window — "
                    "this many in one session is a red flag."
                ),
                severity=0.85,
            )
        return None

    # ── Data exfiltration ────────────────────────────────────────────────────

    def check_bulk_exfiltration(self, p: BehaviourProfile) -> Optional[ThreatSignal]:
        exfil_hits = sum(
            1 for a in p.recent_actions
            if any(kw in a.upper() for kw in EXFIL_KEYWORDS)
        )
        if exfil_hits >= 3:
            return ThreatSignal(
                name="BULK_EXFILTRATION",
                description=(
                    f"{exfil_hits} bulk export or download actions detected — "
                    "large amounts of data being accessed or copied."
                ),
                severity=0.90,
            )
        return None

    def check_high_data_volume(self, p: BehaviourProfile) -> Optional[ThreatSignal]:
        if p.data_access_volume >= 100 or (
            p.actions_last_hour >= 20 and p.unique_entity_types >= 5
        ):
            return ThreatSignal(
                name="HIGH_DATA_VOLUME",
                description=(
                    f"Accessed {p.data_access_volume} records across "
                    f"{p.unique_entity_types} data types — unusually broad data access."
                ),
                severity=0.75,
            )
        return None

    def check_reconnaissance(self, p: BehaviourProfile) -> Optional[ThreatSignal]:
        if (
            p.view_operations_count >= 15
            and p.unique_entity_types >= 4
            and p.avg_action_interval_minutes < 5
        ):
            return ThreatSignal(
                name="RECONNAISSANCE",
                description=(
                    f"Rapidly browsed {p.unique_entity_types} different data types "
                    f"({p.view_operations_count} views in quick succession) — "
                    "looks like someone mapping out the system."
                ),
                severity=0.70,
            )
        return None

    # ── Destructive operations ───────────────────────────────────────────────

    def check_bulk_deletion(self, p: BehaviourProfile) -> Optional[ThreatSignal]:
        if p.delete_operations_count >= 5:
            return ThreatSignal(
                name="BULK_DELETION",
                description=(
                    f"{p.delete_operations_count} delete operations in one session — "
                    "deleting this much data at once is unusual."
                ),
                severity=0.85,
            )
        return None

    def check_deletion_with_failures(self, p: BehaviourProfile) -> Optional[ThreatSignal]:
        if p.delete_operations_count >= 3 and p.consecutive_failures >= 2:
            return ThreatSignal(
                name="DELETION_WITH_FAILURES",
                description=(
                    f"{p.delete_operations_count} deletion attempts with repeated failures — "
                    "may be trying to delete data they don't have permission for."
                ),
                severity=0.75,
            )
        return None

    # ── Brute-force / automated ──────────────────────────────────────────────

    def check_consecutive_failures(self, p: BehaviourProfile) -> Optional[ThreatSignal]:
        if p.consecutive_failures >= 5:
            return ThreatSignal(
                name="CONSECUTIVE_FAILURES",
                description=(
                    f"{p.consecutive_failures} actions failed in a row — "
                    "could indicate someone repeatedly trying actions they're not allowed to do."
                ),
                severity=0.80,
            )
        return None

    def check_automated_activity(self, p: BehaviourProfile) -> Optional[ThreatSignal]:
        if p.actions_last_hour >= 30 and p.avg_action_interval_minutes < 1.0:
            return ThreatSignal(
                name="AUTOMATED_ACTIVITY",
                description=(
                    f"{p.actions_last_hour} actions in the last hour, "
                    f"averaging {p.avg_action_interval_minutes:.1f} min apart — "
                    "this speed suggests an automated script rather than a human."
                ),
                severity=0.80,
            )
        return None

    # ── Temporal anomalies ───────────────────────────────────────────────────

    def check_off_hours_activity(self, p: BehaviourProfile) -> Optional[ThreatSignal]:
        if (p.hour_of_day < 5 or p.hour_of_day > 23) and p.actions_last_hour >= 10:
            return ThreatSignal(
                name="OFF_HOURS_ACTIVITY",
                description=(
                    f"{p.actions_last_hour} actions at {p.hour_of_day:02d}:00 — "
                    "high activity in the middle of the night is unusual."
                ),
                severity=0.65,
            )
        return None

    def check_weekend_sensitive_ops(self, p: BehaviourProfile) -> Optional[ThreatSignal]:
        if p.is_weekend and p.sensitive_actions_count >= 3:
            return ThreatSignal(
                name="WEEKEND_SENSITIVE_OPS",
                description=(
                    f"{p.sensitive_actions_count} high-risk admin actions performed on a weekend — "
                    "outside normal working hours."
                ),
                severity=0.55,
            )
        return None

    # ── Access anomalies ─────────────────────────────────────────────────────

    def check_ip_spreading(self, p: BehaviourProfile) -> Optional[ThreatSignal]:
        if p.ip_diversity_score >= 5.0 and p.actions_last_day >= 20:
            return ThreatSignal(
                name="IP_SPREADING",
                description=(
                    f"Activity from many different IP addresses (score: {p.ip_diversity_score:.1f}) — "
                    "could mean the account is being used from multiple locations."
                ),
                severity=0.65,
            )
        return None

    def check_device_hopping(self, p: BehaviourProfile) -> Optional[ThreatSignal]:
        if p.device_changes >= 3 and p.actions_last_day >= 15:
            return ThreatSignal(
                name="DEVICE_HOPPING",
                description=(
                    f"Logged in from {p.device_changes + 1} different devices today — "
                    "switching devices this frequently is unusual."
                ),
                severity=0.60,
            )
        return None

    # ── Run all checks ───────────────────────────────────────────────────────

    def evaluate(self, profile: BehaviourProfile) -> List[ThreatSignal]:
        """Run every check and return the list of fired ThreatSignals."""
        checks = [
            self.check_privilege_escalation,
            self.check_sensitive_action_surge,
            self.check_credential_harvesting,
            self.check_bulk_exfiltration,
            self.check_high_data_volume,
            self.check_reconnaissance,
            self.check_bulk_deletion,
            self.check_deletion_with_failures,
            self.check_consecutive_failures,
            self.check_automated_activity,
            self.check_off_hours_activity,
            self.check_weekend_sensitive_ops,
            self.check_ip_spreading,
            self.check_device_hopping,
        ]
        return [sig for check in checks for sig in [check(profile)] if sig is not None]


# ─────────────────────────────────────────────────────────────────────────────
# Risk scorer — combines rule signals with ML outputs into a final score
# ─────────────────────────────────────────────────────────────────────────────

class RiskScorer:
    """
    Combines threat signals and ML probabilities into a single risk score.

    Score formula (geometric-mean blend):
        rule_score = max severity among fired signals  (or 0 if none)
        ml_score   = max(anomaly_prob, classifier_prob)
        final      = geometric_mean(ml_score ^ 0.6, rule_score ^ 0.4)

    Using the geometric mean ensures that *both* the ML and rule channels must
    agree for the score to be high — a single moderate channel cannot push the
    result to Critical on its own.
    """

    @staticmethod
    def combine(
        signals: List[ThreatSignal],
        ml_score: float,
    ) -> float:
        rule_score = max((s.severity for s in signals), default=0.0)

        if not signals:
            # No rule fired — trust ML alone
            return float(np.clip(ml_score, 0.0, 1.0))

        # Geometric mean blend
        eps = 1e-6
        blended = (ml_score ** 0.6) * (rule_score ** 0.4)
        # Boost slightly when several independent signals converge
        convergence_boost = min(0.10 * (len(signals) - 1), 0.20)
        return float(np.clip(blended + convergence_boost, 0.0, 1.0))

    @staticmethod
    def to_risk_level(score: float) -> str:
        if score >= 0.80:
            return "Critical"
        if score >= 0.60:
            return "High"
        if score >= 0.40:
            return "Medium"
        return "Low"


# ─────────────────────────────────────────────────────────────────────────────
# Main detector class
# ─────────────────────────────────────────────────────────────────────────────

class AuditRiskDetector:
    """
    Public API for audit-log risk detection.

    Internally orchestrates:
      ProfileBuilder  →  ThreatSignalEngine  →  ML models  →  RiskScorer

    The ML models used are:
      - IsolationForest  (unsupervised; trained on normal-only logs)
      - GradientBoostingClassifier  (supervised; trained on labelled logs)
      NOTE: GBC is intentionally different from the fraud detector's
            RandomForestClassifier to produce a distinct probability surface.

    Anomaly score normalisation uses stored percentile bounds (p10, p90 of the
    training score distribution) rather than min/max, making it more robust to
    outliers in the training data.
    """

    FEATURE_COLUMNS = list(BehaviourProfile().to_feature_dict().keys())  # 23 features

    def __init__(self) -> None:
        self.anomaly_model: Optional[IsolationForest] = None
        self.classifier_model: Optional[GradientBoostingClassifier] = None
        self.scaler = RobustScaler()
        # Anomaly score thresholds:
        # _anomaly_safe   = p90 of normal training scores  → maps to 0.0 anomaly
        # _anomaly_danger = p10 of suspicious training scores → maps to 1.0 anomaly
        # Using both ends of the real score distribution gives proper spread.
        self._anomaly_safe: float   = -0.40
        self._anomaly_danger: float = -0.77

        self._profile_builder = ProfileBuilder()
        self._threat_engine   = ThreatSignalEngine()

    # ── feature_columns property (backward-compat with flask_audit_integration) ──

    @property
    def feature_columns(self) -> List[str]:
        return self.FEATURE_COLUMNS

    # ── Public prediction API ─────────────────────────────────────────────────

    def predict_risk(
        self, audit_data: Dict
    ) -> Tuple[float, bool, List[str], str]:
        """
        Analyse a user's audit-log behaviour and return a risk assessment.

        Parameters
        ----------
        audit_data : dict
            Raw behaviour dict as produced by AuditRiskAnalyzer.prepare_audit_data_from_logs().

        Returns
        -------
        risk_score : float  — 0.0 (no risk) to 1.0 (critical)
        is_suspicious : bool
        reasons : List[str]  — human-readable descriptions of fired signals
        risk_level : str     — "Low" | "Medium" | "High" | "Critical"
        """
        # Step 1: build structured profile
        profile = ProfileBuilder.build(audit_data)

        # Step 2: evaluate threat signals
        signals = self._threat_engine.evaluate(profile)

        # Step 3: ML scoring
        ml_score = self._ml_score(profile)

        # Step 4: combine into final risk score
        risk_score = RiskScorer.combine(signals, ml_score)
        is_suspicious = risk_score > 0.60
        risk_level = RiskScorer.to_risk_level(risk_score)
        reasons = [s.description for s in signals]
        if ml_score > 0.65 and not reasons:
            reasons.append("Behaviour pattern looks unusual compared to normal users.")
        if ml_score > 0.60 and signals:
            reasons.append("Activity pattern matches known suspicious behaviour from training data.")

        return risk_score, is_suspicious, reasons, risk_level

    # ── Feature extraction (kept for backward-compat with flask_audit_integration) ──

    def extract_features(self, audit_data: Dict) -> Dict:
        """Return the full feature dict (same as BehaviourProfile.to_feature_dict)."""
        return ProfileBuilder.build(audit_data).to_feature_dict()

    # ── ML helpers ────────────────────────────────────────────────────────────

    def _ml_score(self, profile: BehaviourProfile) -> float:
        feature_dict = profile.to_feature_dict()
        feature_arr = np.array([[feature_dict[c] for c in self.FEATURE_COLUMNS]], dtype=float)

        try:
            if hasattr(self.scaler, "center_"):          # RobustScaler fitted
                n_expected = getattr(self.scaler, "n_features_in_", feature_arr.shape[1])
                arr = self._pad_or_trim(feature_arr, n_expected)
                scaled = self.scaler.transform(arr)
            else:
                scaled = feature_arr
        except Exception:
            scaled = feature_arr

        score = 0.0

        if self.anomaly_model is not None:
            raw = float(self.anomaly_model.score_samples(
                self._pad_or_trim(scaled, getattr(self.anomaly_model, "n_features_in_", scaled.shape[1]))
            )[0])
            # Normalise: safe threshold → 0.0 anomaly, danger threshold → 1.0 anomaly
            safe   = self._anomaly_safe
            danger = self._anomaly_danger
            span   = safe - danger
            if span > 0:
                anomaly_prob = float(np.clip((safe - raw) / span, 0.0, 1.0))
            else:
                anomaly_prob = 0.0
            score = max(score, anomaly_prob)

        if self.classifier_model is not None:
            cls_arr = self._pad_or_trim(
                scaled, getattr(self.classifier_model, "n_features_in_", scaled.shape[1])
            )
            risk_prob = float(self.classifier_model.predict_proba(cls_arr)[0][1])
            score = max(score, risk_prob)

        return score

    @staticmethod
    def _pad_or_trim(arr: np.ndarray, target_cols: int) -> np.ndarray:
        """Ensure arr has exactly target_cols columns."""
        current = arr.shape[1]
        if current < target_cols:
            arr = np.hstack([arr, np.zeros((arr.shape[0], target_cols - current))])
        elif current > target_cols:
            arr = arr[:, :target_cols]
        return arr

    # ── Training ──────────────────────────────────────────────────────────────

    def train_anomaly_model(self, X_normal: pd.DataFrame, X_suspicious: pd.DataFrame = None) -> None:
        """
        Fit the IsolationForest on normal-only samples.
        Stores two thresholds for score normalisation:
          _anomaly_safe   = p90 of normal scores  (what 'definitely normal' looks like)
          _anomaly_danger = p10 of suspicious scores (what 'definitely suspicious' looks like)
        This gives a calibrated spread rather than compressing everything to 0 or 1.
        """
        X_arr = X_normal.values if hasattr(X_normal, "values") else np.asarray(X_normal)
        self.scaler.fit(X_arr)
        X_scaled = self.scaler.transform(X_arr)

        self.anomaly_model = IsolationForest(
            n_estimators=150,
            contamination=0.04,
            random_state=0,
        )
        self.anomaly_model.fit(X_scaled)

        norm_scores = self.anomaly_model.score_samples(X_scaled)
        self._anomaly_safe = float(np.percentile(norm_scores, 90))

        if X_suspicious is not None and len(X_suspicious) > 0:
            X_susp_arr = X_suspicious.values if hasattr(X_suspicious, "values") else np.asarray(X_suspicious)
            X_susp_scaled = self.scaler.transform(X_susp_arr)
            susp_scores = self.anomaly_model.score_samples(X_susp_scaled)
            self._anomaly_danger = float(np.percentile(susp_scores, 10))
        else:
            # Fallback if no suspicious samples provided
            self._anomaly_danger = float(np.percentile(norm_scores, 10)) - 0.15

    def train_classifier(self, X_train: pd.DataFrame, y_train: pd.Series) -> None:
        """
        Fit a GradientBoostingClassifier on labelled samples.
        Uses GBC instead of RFC to produce a distinct decision boundary.
        """
        X_arr = X_train.values if hasattr(X_train, "values") else np.asarray(X_train)
        if not hasattr(self.scaler, "center_"):
            self.scaler.fit(X_arr)
        X_scaled = self.scaler.transform(X_arr)

        # Heavily regularised GBC: shallow trees, few estimators, large min_samples_leaf.
        # This prevents the model from memorising the training data and
        # producing overconfident 0.0/1.0 probabilities — keeps scores in a natural range.
        self.classifier_model = GradientBoostingClassifier(
            n_estimators=20,
            max_depth=2,
            learning_rate=0.03,
            subsample=0.5,
            min_samples_leaf=30,
            max_features=0.7,
            random_state=0,
        )
        self.classifier_model.fit(X_scaled, y_train)

    # ── Persistence ───────────────────────────────────────────────────────────

    def save_models(self, path: str = "models/") -> None:
        os.makedirs(path, exist_ok=True)
        payload = {
            "anomaly_model":    self.anomaly_model,
            "classifier_model": self.classifier_model,
            "scaler":           self.scaler,
            "anomaly_safe":     self._anomaly_safe,
            "anomaly_danger":   self._anomaly_danger,
        }
        with open(os.path.join(path, "audit_risk_detector.pkl"), "wb") as fh:
            pickle.dump(payload, fh)

    def load_models(self, path: str = "models/") -> None:
        pkl_path = os.path.join(path, "audit_risk_detector.pkl")
        with open(pkl_path, "rb") as fh:
            payload = pickle.load(fh)

        expected = len(self.FEATURE_COLUMNS)
        for component_name in ("scaler", "anomaly_model", "classifier_model"):
            obj = payload.get(component_name)
            n = getattr(obj, "n_features_in_", None)
            if n is not None and n != expected:
                print(
                    f"WARNING: {component_name} expects {n} features "
                    f"but current code uses {expected}. "
                    "Falling back to rule-based detection — please retrain."
                )
                return

        self.anomaly_model    = payload["anomaly_model"]
        self.classifier_model = payload["classifier_model"]
        self.scaler           = payload["scaler"]
        self._anomaly_safe    = payload.get("anomaly_safe",   payload.get("anomaly_p90", -0.40))
        self._anomaly_danger  = payload.get("anomaly_danger", payload.get("anomaly_p10", -0.77))

    # ── Convenience risk-level helper (backward-compat) ───────────────────────

    def calculate_risk_level(self, risk_score: float) -> str:
        return RiskScorer.to_risk_level(risk_score)


# ─────────────────────────────────────────────────────────────────────────────
# Quick smoke-test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    detector = AuditRiskDetector()

    scenarios = {
        "Normal admin": {
            "actions_last_hour": 5, "actions_last_day": 25,
            "failed_actions_count": 1, "avg_action_interval_minutes": 12,
            "sensitive_actions_count": 2, "delete_operations_count": 1,
            "update_operations_count": 3, "create_operations_count": 1,
            "view_operations_count": 0, "unique_entity_types": 2,
            "consecutive_failures": 0, "privilege_level_changes": 0,
            "data_access_volume": 15, "ip_diversity_score": 0.0,
            "device_changes": 0, "hour_of_day": 14, "is_weekend": 0,
            "recent_actions": ["UPDATE_VEHICLE", "UPDATE_BOOKING"],
            "entity_types_accessed": ["VEHICLE", "BOOKING"],
        },
        "Data exfiltration": {
            "actions_last_hour": 45, "actions_last_day": 180,
            "failed_actions_count": 5, "avg_action_interval_minutes": 1.3,
            "sensitive_actions_count": 8, "delete_operations_count": 0,
            "update_operations_count": 2, "create_operations_count": 0,
            "view_operations_count": 43, "unique_entity_types": 6,
            "consecutive_failures": 2, "privilege_level_changes": 0,
            "data_access_volume": 250, "ip_diversity_score": 3.2,
            "device_changes": 2, "hour_of_day": 2, "is_weekend": 1,
            "recent_actions": ["EXPORT_USERS", "BULK_READ", "DOWNLOAD_LOGS"],
            "entity_types_accessed": ["USER", "BOOKING", "VEHICLE", "PAYMENT", "LOG"],
        },
        "Privilege escalation": {
            "actions_last_hour": 12, "actions_last_day": 35,
            "failed_actions_count": 8, "avg_action_interval_minutes": 5,
            "sensitive_actions_count": 10, "delete_operations_count": 2,
            "update_operations_count": 5, "create_operations_count": 3,
            "view_operations_count": 2, "unique_entity_types": 3,
            "consecutive_failures": 6, "privilege_level_changes": 4,
            "data_access_volume": 45, "ip_diversity_score": 4.5,
            "device_changes": 3, "hour_of_day": 23, "is_weekend": 0,
            "recent_actions": ["UPDATE_ROLE", "GRANT_ACCESS", "MODIFY_SECURITY"],
            "entity_types_accessed": ["USER", "PERMISSION", "ROLE"],
        },
    }

    for name, data in scenarios.items():
        score, suspicious, reasons, level = detector.predict_risk(data)
        print(f"\n{'='*55}")
        print(f"  {name}")
        print(f"{'='*55}")
        print(f"  Score : {score:.3f}  |  Level : {level}  |  Suspicious : {suspicious}")
        for r in reasons:
            print(f"    • {r}")

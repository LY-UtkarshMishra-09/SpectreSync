"""
CyberSentinel: Multi-Agent Network Intrusion Detection & Adaptive Defense
Agent 2: Anomaly Detection Agent (src/agent2_anomaly.py)
JAYPEE AGENTIC AI INTERNATIONAL SUMMIT 2026 - TRACK 1

Requirements:
- Independently assess unusual flows using unsupervised/statistical modeling.
- Outputs continuous anomaly score (0.0 to 1.0) where 1.0 is extremely anomalous.
- Identifies supporting feature evidence (top anomalous deviations from baseline).
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Union, Optional
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

MODEL_DIR = os.path.join("models")
ANOMALY_MODEL_PATH = os.path.join(MODEL_DIR, "agent2_isolation_forest.joblib")
ANOMALY_SCALER_PATH = os.path.join(MODEL_DIR, "agent2_scaler.joblib")
ANOMALY_META_PATH = os.path.join(MODEL_DIR, "agent2_baseline_stats.json")
DEFAULT_DATA_PATH = os.path.join("data", "cleaned_cicids2017.csv")


class AnomalyDetectionAgent:
    """
    Agent 2: Independent Anomaly Detection Agent
    Uses an Isolation Forest & feature-level Z-score statistical engine
    to score unusual network flows without relying on supervised labels.
    """

    def __init__(self, contamination: float = 0.15):
        self.contamination = contamination
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.feature_names: List[str] = []
        self.baseline_means: Dict[str, float] = {}
        self.baseline_stds: Dict[str, float] = {}

    def load_or_train(self, data_path: str = DEFAULT_DATA_PATH) -> "AnomalyDetectionAgent":
        if (
            os.path.exists(ANOMALY_MODEL_PATH)
            and os.path.exists(ANOMALY_SCALER_PATH)
            and os.path.exists(ANOMALY_META_PATH)
        ):
            print(f"[Agent 2] Loading pre-trained Anomaly Agent from {ANOMALY_MODEL_PATH}...")
            self.model = joblib.load(ANOMALY_MODEL_PATH)
            self.scaler = joblib.load(ANOMALY_SCALER_PATH)
            with open(ANOMALY_META_PATH, "r") as f:
                meta = json.load(f)
                self.feature_names = meta.get("feature_names", [])
                self.baseline_means = meta.get("means", {})
                self.baseline_stds = meta.get("stds", {})
            print(f"[Agent 2] Anomaly model loaded ({len(self.feature_names)} features).")
            return self

        print(f"[Agent 2] Training Anomaly Detection Agent on {data_path}...")
        return self.train(data_path)

    def train(self, data_path: str = DEFAULT_DATA_PATH) -> "AnomalyDetectionAgent":
        if not os.path.exists(data_path):
            raise FileNotFoundError(f"Dataset not found at {data_path}")

        print(f"[Agent 2] Fitting baseline statistical distribution on {data_path}...")
        df = pd.read_parquet(data_path) if str(data_path).endswith(".parquet") else pd.read_csv(data_path)
        
        # Clean column names
        df.columns = [c.strip() for c in df.columns]

        non_features = [
            "target_label", "Label", "label", "Attack_Type", "Flow ID", "Source IP",
            "Destination IP", "Timestamp", "Flow_ID", "Source_IP", "Destination_IP",
            "id", "Unnamed: 0"
        ]
        self.feature_names = [
            c for c in df.columns if c not in non_features and pd.api.types.is_numeric_dtype(df[c])
        ]

        # Extract features and replace inf/nan
        clean_df = df[self.feature_names].replace([np.inf, -np.inf], np.nan)
        for col in self.feature_names:
            median_val = clean_df[col].median()
            clean_df[col] = clean_df[col].fillna(0.0 if pd.isna(median_val) else median_val)

        X = np.asarray(clean_df.to_numpy(), dtype=np.float64)

        # Compute baseline means and standard deviations for explainable feature evidence
        for col in self.feature_names:
            mean = float(clean_df[col].mean())
            std = float(clean_df[col].std())
            self.baseline_means[col] = mean
            self.baseline_stds[col] = std if std > 1e-6 else 1.0

        # Scale features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        # Train Isolation Forest
        print(f"[Agent 2] Training Isolation Forest (n_estimators=100, contamination={self.contamination})...")
        self.model = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=42,
            n_jobs=1
        )
        self.model.fit(X_scaled)

        # Save artifacts
        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump(self.model, ANOMALY_MODEL_PATH)
        joblib.dump(self.scaler, ANOMALY_SCALER_PATH)
        with open(ANOMALY_META_PATH, "w") as f:
            json.dump({
                "feature_names": self.feature_names,
                "means": self.baseline_means,
                "stds": self.baseline_stds,
                "contamination": self.contamination
            }, f, indent=2)

        print(f"[Agent 2] Artifacts successfully saved to {MODEL_DIR}/")
        return self

    def predict_anomaly(
        self, sample_features: Union[Dict[str, Any], list, np.ndarray, pd.DataFrame]
    ) -> Dict[str, Any]:
        """
        Assess flow for anomalous characteristics.
        
        Returns:
            dict containing:
                - anomaly_score: float (0.0 to 1.0)
                - is_anomaly: bool
                - feature_evidence: list of dicts with top deviating features and Z-scores
        """
        if self.model is None or self.scaler is None:
            self.load_or_train()

        # Format input to ordered array
        feature_dict = {}
        if isinstance(sample_features, dict):
            feature_dict = sample_features
            arr = [float(sample_features.get(f, 0.0)) for f in self.feature_names]
            X = np.array([arr], dtype=np.float64)
        elif isinstance(sample_features, pd.DataFrame):
            row = sample_features.iloc[0]
            feature_dict = row.to_dict()
            arr = [float(row.get(f, 0.0)) for f in self.feature_names]
            X = np.array([arr], dtype=np.float64)
        elif isinstance(sample_features, (list, np.ndarray)):
            X = np.asarray(sample_features, dtype=np.float64)
            if X.ndim == 1:
                X = X.reshape(1, -1)
            feature_dict = {
                self.feature_names[i]: float(X[0, i])
                for i in range(min(len(self.feature_names), X.shape[1]))
            }
        else:
            raise TypeError(f"Unsupported input type: {type(sample_features)}")

        # Handle NaN/Inf
        X = np.nan_to_num(X, nan=0.0, posinf=1e9, neginf=-1e9)
        X_scaled = self.scaler.transform(X)

        # Isolation Forest decision_function: lower means more anomalous (negative for anomalies)
        raw_score = float(self.model.decision_function(X_scaled)[0])
        
        # Normalize to [0.0, 1.0] where 1.0 is extremely anomalous
        # decision_function typically in [-0.5, 0.5]
        normalized_score = 1.0 / (1.0 + np.exp(raw_score * 8.0))
        anomaly_score = float(np.clip(normalized_score, 0.0, 1.0))
        is_anomaly = bool(anomaly_score >= 0.50)

        # Compute feature-level evidence (Z-score deviation from baseline)
        evidence_list = []
        for feat in self.feature_names:
            val = float(feature_dict.get(feat, 0.0))
            mean = self.baseline_means.get(feat, 0.0)
            std = self.baseline_stds.get(feat, 1.0)
            z = (val - mean) / std if std > 1e-6 else 0.0

            if abs(z) >= 1.5 or (feat in ["SYN Flag Count", "RST Flag Count"] and val >= 1):
                note = "Elevated volume deviation"
                if "SYN" in feat:
                    note = "Unusual SYN handshake pattern"
                elif "RST" in feat:
                    note = "Abrupt connection reset pattern"
                elif "Packets" in feat or "Bytes" in feat:
                    note = "High packet/byte velocity surge"
                elif "Duration" in feat:
                    note = "Atypical flow duration profile"

                evidence_list.append({
                    "feature": feat,
                    "value": round(val, 2),
                    "baseline_mean": round(mean, 2),
                    "z_score": round(z, 2),
                    "note": note
                })

        # Sort by absolute Z-score descending and take top 4
        evidence_list.sort(key=lambda x: abs(x["z_score"]), reverse=True)
        top_evidence = evidence_list[:4]

        return {
            "anomaly_score": round(anomaly_score, 4),
            "is_anomaly": is_anomaly,
            "raw_decision_score": round(raw_score, 4),
            "feature_evidence": top_evidence
        }


# Global singleton instance
_anomaly_agent_instance: Optional[AnomalyDetectionAgent] = None

def get_anomaly_agent() -> AnomalyDetectionAgent:
    global _anomaly_agent_instance
    if _anomaly_agent_instance is None:
        _anomaly_agent_instance = AnomalyDetectionAgent()
    return _anomaly_agent_instance

def predict_anomaly(sample_features: Union[Dict[str, Any], list, np.ndarray, pd.DataFrame]) -> Dict[str, Any]:
    """Convenience helper for Agent 2 anomaly scoring."""
    agent = get_anomaly_agent()
    return agent.predict_anomaly(sample_features)


if __name__ == "__main__":
    agent = get_anomaly_agent()
    dataset_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DATA_PATH
    agent.train(dataset_path)

    # Quick test flow
    test_flow = {
        "Destination Port": 80,
        "Flow Duration": 60000,
        "Total Fwd Packets": 180,
        "Total Backward Packets": 2,
        "Flow Bytes/s": 2500000,
        "Flow Packets/s": 3500,
        "Packet Length Mean": 64,
        "SYN Flag Count": 1,
        "ACK Flag Count": 0,
        "RST Flag Count": 1
    }
    res = agent.predict_anomaly(test_flow)
    print("\nSample Anomaly Prediction Output:")
    print(json.dumps(res, indent=2))


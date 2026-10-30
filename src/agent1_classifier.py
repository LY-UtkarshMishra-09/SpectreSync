"""
CyberSentinel: Multi-Agent Network Intrusion Detection & Adaptive Defense
Agent 1: Threat Detection Agent (src/agent1_classifier.py)
JAYPEE AGENTIC AI INTERNATIONAL SUMMIT 2026 - TRACK 1

Requirements:
- Predicts one of the 5 benchmark classes: BENIGN, BRUTE_FORCE, DOS, DDOS, PORT_SCAN
- Outputs predicted class & confidence score (0.0 to 1.0)
- Handles missing/infinite values and feature scaling
- Reports accuracy and macro-F1 on validation split
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple, Optional, Union
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, f1_score

# 5 Canonical Benchmark Classes
BENCHMARK_CLASSES = ["BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"]

# Mapping dictionary for raw CICIDS2017 labels to the 5 benchmark classes
LABEL_MAPPING = {
    # Benign
    "BENIGN": "BENIGN",
    "NORMAL": "BENIGN",
    
    # Brute Force
    "FTP-PATATOR": "BRUTE_FORCE",
    "SSH-PATATOR": "BRUTE_FORCE",
    "BRUTE FORCE": "BRUTE_FORCE",
    "BRUTEFORCE": "BRUTE_FORCE",
    "BRUTE_FORCE": "BRUTE_FORCE",
    
    # DoS
    "DOS": "DOS",
    "DOS SLOWLORIS": "DOS",
    "DOS SLOWHTTPTEST": "DOS",
    "DOS HULK": "DOS",
    "DOS GOLDENEYE": "DOS",
    "HEARTBLEED": "DOS",
    
    # DDoS
    "DDOS": "DDOS",
    "DDoS": "DDOS",
    
    # Port Scan
    "PORT SCAN": "PORT_SCAN",
    "PORTSCAN": "PORT_SCAN",
    "PORT_SCAN": "PORT_SCAN",
}

DEFAULT_DATA_PATH = os.path.join("data", "cleaned_cicids2017.csv")
MODEL_DIR = os.path.join("models")
MODEL_PATH = os.path.join(MODEL_DIR, "agent1_rf.joblib")
SCALER_PATH = os.path.join(MODEL_DIR, "agent1_scaler.joblib")
METADATA_PATH = os.path.join(MODEL_DIR, "agent1_metadata.json")


def map_to_benchmark_class(raw_label: str) -> str:
    """Normalize raw label strings to the 5 canonical benchmark classes."""
    if not isinstance(raw_label, str):
        return "BENIGN"
    cleaned = raw_label.strip().upper().replace("_", " ").replace("-", " ")
    for k, v in LABEL_MAPPING.items():
        if k.replace("_", " ").replace("-", " ") == cleaned:
            return v
    # Fallback substring checks
    if "DDOS" in cleaned:
        return "DDOS"
    if "DOS" in cleaned:
        return "DOS"
    if "PORT" in cleaned or "SCAN" in cleaned:
        return "PORT_SCAN"
    if "PATATOR" in cleaned or "BRUTE" in cleaned:
        return "BRUTE_FORCE"
    return "BENIGN"


def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Clean infinite and NaN values and standardize column names."""
    df = df.copy()
    # Strip whitespace from column names
    df.columns = [c.strip() for c in df.columns]
    
    # Identify target column
    target_col = None
    for cand in ["target_label", "Label", "label", "Attack_Type", "attack_type", "class"]:
        if cand in df.columns:
            target_col = cand
            break
            
    if target_col and target_col != "target_label":
        df = df.rename(columns={target_col: "target_label"})
        
    if "target_label" in df.columns:
        df["target_label"] = df["target_label"].apply(map_to_benchmark_class)

    # Replace inf and -inf with NaN, then forward/median fill
    num_cols = df.select_dtypes(include=[np.number]).columns
    df[num_cols] = df[num_cols].replace([np.inf, -np.inf], np.nan)
    for col in num_cols:
        col_median = df[col].median()
        if pd.isna(col_median):
            col_median = 0.0
        df[col] = df[col].fillna(col_median)

    return df


class ThreatDetectionAgent:
    """
    Agent 1: Threat Detection Agent
    Performs multi-class network traffic flow classification into:
    BENIGN, BRUTE_FORCE, DOS, DDOS, PORT_SCAN
    """

    def __init__(self):
        self.model: Optional[RandomForestClassifier] = None
        self.scaler: Optional[StandardScaler] = None
        self.feature_names: list = []
        self.classes_: list = BENCHMARK_CLASSES

    def load_or_train(self, data_path: str = DEFAULT_DATA_PATH, force_retrain: bool = False):
        """Load trained model from disk or train on dataset."""
        if not force_retrain and os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH) and os.path.exists(METADATA_PATH):
            print(f"[Agent 1] Loading pre-trained model from {MODEL_PATH}...")
            self.model = joblib.load(MODEL_PATH)
            self.scaler = joblib.load(SCALER_PATH)
            with open(METADATA_PATH, "r") as f:
                metadata = json.load(f)
                self.feature_names = metadata.get("feature_names", [])
                self.classes_ = metadata.get("classes", BENCHMARK_CLASSES)
            print(f"[Agent 1] Model loaded successfully ({len(self.feature_names)} features, {len(self.classes_)} classes).")
            return self

        print(f"[Agent 1] Training Threat Detection Agent using {data_path}...")
        return self.train(data_path)

    def train(self, data_path: str = DEFAULT_DATA_PATH) -> "ThreatDetectionAgent":
        if not os.path.exists(data_path):
            raise FileNotFoundError(
                f"Dataset not found at {data_path}. Please place 'cleaned_cicids2017.csv' in the './data/' folder."
            )

        print(f"[Agent 1] Loading dataset from {data_path}...")
        df = pd.read_csv(data_path)
        df = clean_dataframe(df)

        if "target_label" not in df.columns:
            raise ValueError("Target column 'target_label' (or 'Label') not found in dataset.")

        # Drop non-feature and ID columns
        non_features = [
            "target_label", "Flow ID", "Source IP", "Destination IP", "Timestamp",
            "Flow_ID", "Source_IP", "Destination_IP", "id", "Unnamed: 0"
        ]
        feature_cols = [c for c in df.columns if c not in non_features and pd.api.types.is_numeric_dtype(df[c])]

        X = np.asarray(df[feature_cols].to_numpy(), dtype=np.float64)
        y = np.array(df["target_label"].tolist(), dtype=object)

        self.feature_names = feature_cols
        print(f"[Agent 1] Total samples: {len(X)}, Features: {len(self.feature_names)}")
        print(f"[Agent 1] Class distribution:\n{pd.Series(y).value_counts()}")

        # Stratified Train-Validation Split (80% / 20%)
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=0.20, random_state=42, stratify=y
        )

        # Standardize features
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)

        # Train Balanced Random Forest Classifier
        print("[Agent 1] Fitting Random Forest Classifier (100 estimators, balanced weights)...")
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            class_weight="balanced",
            n_jobs=1,
            random_state=42
        )
        self.model.fit(X_train_scaled, y_train)
        self.classes_ = list(self.model.classes_)

        # Validation Evaluation
        y_pred = self.model.predict(X_val_scaled)
        acc = accuracy_score(y_val, y_pred)
        macro_f1 = f1_score(y_val, y_pred, average="macro", zero_division=0)

        print("\n" + "=" * 60)
        print("AGENT 1: THREAT DETECTION VALIDATION RESULTS")
        print("=" * 60)
        print(f"Accuracy: {acc * 100:.2f}%")
        print(f"Macro-F1: {macro_f1:.4f}")
        print("\nDetailed Classification Report:")
        print(classification_report(y_val, y_pred, digits=4, zero_division=0))
        print("=" * 60 + "\n")

        # Save artifacts
        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump(self.model, MODEL_PATH)
        joblib.dump(self.scaler, SCALER_PATH)
        with open(METADATA_PATH, "w") as f:
            json.dump({
                "feature_names": self.feature_names,
                "classes": self.classes_,
                "accuracy": acc,
                "macro_f1": macro_f1
            }, f, indent=2)
        print(f"[Agent 1] Artifacts saved to {MODEL_DIR}/")

        return self

    def predict_threat(self, sample_features: Union[Dict[str, Any], list, np.ndarray, pd.DataFrame]) -> Dict[str, Any]:
        """
        Predict threat class and confidence for input network flow features.
        
        Returns:
            dict with:
                - predicted_class: str (e.g. 'DOS', 'BENIGN')
                - confidence: float (e.g. 0.985)
                - class_probabilities: dict mapping each class to its probability
        """
        if self.model is None or self.scaler is None:
            self.load_or_train()

        # Handle different input formats
        if isinstance(sample_features, dict):
            # Extract in order of training features
            arr = [float(sample_features.get(f, 0.0)) for f in self.feature_names]
            X = np.array([arr])
        elif isinstance(sample_features, pd.DataFrame):
            # Ensure columns align
            missing = [c for c in self.feature_names if c not in sample_features.columns]
            df_aligned = sample_features.copy()
            for m in missing:
                df_aligned[m] = 0.0
            X = df_aligned[self.feature_names].values
        elif isinstance(sample_features, list):
            X = np.array([sample_features]) if not isinstance(sample_features[0], list) else np.array(sample_features)
        elif isinstance(sample_features, np.ndarray):
            X = sample_features if sample_features.ndim == 2 else sample_features.reshape(1, -1)
        else:
            raise TypeError(f"Unsupported feature input type: {type(sample_features)}")

        # Handle NaN/Inf in input
        X = np.nan_to_num(X, nan=0.0, posinf=1e9, neginf=-1e9)

        # Scale features
        X_scaled = self.scaler.transform(X)

        # Predict probabilities
        probs = self.model.predict_proba(X_scaled)[0]
        max_idx = int(np.argmax(probs))
        predicted_class = self.classes_[max_idx]
        confidence = float(probs[max_idx])

        class_probabilities = {
            self.classes_[i]: float(probs[i]) for i in range(len(self.classes_))
        }

        return {
            "predicted_class": predicted_class,
            "confidence": round(confidence, 4),
            "class_probabilities": {k: round(v, 4) for k, v in class_probabilities.items()}
        }


# Global singleton instance for easy import across pipeline agents
_agent_instance: Optional[ThreatDetectionAgent] = None

def get_threat_detection_agent() -> ThreatDetectionAgent:
    global _agent_instance
    if _agent_instance is None:
        _agent_instance = ThreatDetectionAgent()
    return _agent_instance

def predict_threat(sample_features: Union[Dict[str, Any], list, np.ndarray, pd.DataFrame]) -> Dict[str, Any]:
    """Convenience function specified in problem requirements."""
    agent = get_threat_detection_agent()
    return agent.predict_threat(sample_features)


if __name__ == "__main__":
    agent = get_threat_detection_agent()
    dataset_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DATA_PATH

    if os.path.exists(dataset_path):
        agent.train(dataset_path)
    else:
        print(f"[!] Dataset not found at '{dataset_path}'.")
        print("Please place 'cleaned_cicids2017.csv' in './data/' or pass the path as an argument.")
        print("Usage: python src/agent1_classifier.py [path_to_cleaned_cicids2017.csv]")

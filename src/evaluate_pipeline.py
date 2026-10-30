"""
CyberSentinel: Multi-Agent Network Intrusion Detection & Adaptive Defense
End-to-End Pipeline Evaluation & Validation Script (src/evaluate_pipeline.py)
JAYPEE AGENTIC AI INTERNATIONAL SUMMIT 2026 - TRACK 1

Requirements:
1. Pipeline Execution:
   - Loads validation records from CICIDS2017.
   - Passes each flow through Agent 1 (Threat Classifier), Agent 2 (Anomaly Detector),
     and Agent 3 (Evidence Fusion).
2. Metrics & Output:
   - Computes overall validation Accuracy & Macro-F1 across the 5 benchmark classes:
     BENIGN, BRUTE_FORCE, DOS, DDOS, PORT_SCAN.
   - Records agreement vs disagreement statistics and evidence status distribution.
   - Generates summary report saved to results/day1_level1_submission.json for API submission.
"""

import os
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import json
import time
import numpy as np
import pandas as pd
from typing import Dict, Any, List
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix

from src.agent1_classifier import get_threat_detection_agent, map_to_benchmark_class, clean_dataframe, BENCHMARK_CLASSES
from src.agent2_anomaly import get_anomaly_agent
from src.agent3_fusion import get_fusion_agent

DEFAULT_DATA_PATH = os.path.join("data", "cleaned_cicids2017.csv")
RESULTS_DIR = os.path.join("results")
SUBMISSION_JSON_PATH = os.path.join(RESULTS_DIR, "day1_level1_submission.json")


def evaluate_cyber_sentinel_pipeline(
    data_path: str = DEFAULT_DATA_PATH,
    test_size: float = 0.20,
    random_state: int = 42
) -> Dict[str, Any]:
    start_time = time.time()
    print("=" * 75)
    print("CYBERSENTINEL: MULTI-AGENT INTRUSION DETECTION PIPELINE EVALUATION")
    print("=" * 75)

    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Validation dataset not found at '{data_path}'")

    print(f"\n[1/4] Loading & preprocessing dataset from: {data_path}")
    df = pd.read_csv(data_path)
    df = clean_dataframe(df)

    if "target_label" not in df.columns:
        raise ValueError("Target label column missing from dataset.")

    # Drop non-feature columns
    non_features = [
        "target_label", "Flow ID", "Source IP", "Destination IP", "Timestamp",
        "Flow_ID", "Source_IP", "Destination_IP", "id", "Unnamed: 0"
    ]
    feature_cols = [c for c in df.columns if c not in non_features and pd.api.types.is_numeric_dtype(df[c])]

    X_full = np.asarray(df[feature_cols].to_numpy(), dtype=np.float64)
    y_full = np.array(df["target_label"].tolist(), dtype=object)

    # Perform stratified split to extract the exact validation set
    print(f"Total dataset records: {len(df)} | Features: {len(feature_cols)}")
    print(f"Extracting stratified validation split ({int(test_size*100)}% holdout)...")
    _, X_val, _, y_val = train_test_split(
        X_full, y_full, test_size=test_size, random_state=random_state, stratify=y_full
    )

    val_df = pd.DataFrame(X_val, columns=feature_cols)
    val_labels = list(y_val)
    n_val = len(val_labels)
    print(f"Validation records to evaluate: {n_val}")
    print("Validation ground truth distribution:")
    for k, v in pd.Series(val_labels).value_counts().items():
        print(f"  - {k:<15}: {v}")

    # Initialize Agents
    print("\n[2/4] Initializing Multi-Agent Defensive Pipeline...")
    agent1 = get_threat_detection_agent()
    agent1.load_or_train(data_path)

    agent2 = get_anomaly_agent()
    agent2.load_or_train(data_path)

    agent3 = get_fusion_agent()

    # Pipeline Execution
    print(f"\n[3/4] Streaming {n_val} validation records through Agent 1 -> Agent 2 -> Agent 3...")
    agent1_preds = []
    agent2_scores = []
    fused_preds = []
    evidence_statuses = []
    agreement_counts = {"agreed": 0, "disagreed": 0}
    detailed_audit_logs = []

    for idx in range(n_val):
        row_dict = val_df.iloc[idx].to_dict()
        true_class = val_labels[idx]

        # 1. Agent 1: Threat Detection
        a1_out = agent1.predict_threat(row_dict)
        a1_pred = a1_out["predicted_class"]
        agent1_preds.append(a1_pred)

        # 2. Agent 2: Anomaly Detection
        a2_out = agent2.predict_anomaly(row_dict)
        agent2_scores.append(a2_out["anomaly_score"])

        # 3. Agent 3: Evidence Fusion
        a3_out = agent3.fuse_evidence(a1_out, a2_out, row_dict)
        fused_class = a3_out["final_class"]
        fused_preds.append(fused_class)
        evidence_statuses.append(a3_out["evidence_status"])

        if a3_out["agreement"]:
            agreement_counts["agreed"] += 1
        else:
            agreement_counts["disagreed"] += 1

        if idx < 5 or not a3_out["agreement"]:
            detailed_audit_logs.append({
                "record_index": idx,
                "ground_truth": true_class,
                "agent1_predicted": a1_pred,
                "agent1_confidence": a1_out["confidence"],
                "agent2_anomaly_score": a2_out["anomaly_score"],
                "fused_final_class": fused_class,
                "evidence_status": a3_out["evidence_status"],
                "agreement": a3_out["agreement"],
                "policy": a3_out["policy"],
                "rationale": a3_out["rationale"]
            })

    # Metrics Calculation
    print("\n[4/4] Computing Final Validation Benchmark Metrics...")

    # Agent 1 Standalone Metrics
    a1_acc = accuracy_score(val_labels, agent1_preds)
    a1_macro_f1 = f1_score(val_labels, agent1_preds, average="macro", zero_division=0)

    # Agent 3 Fused Pipeline Metrics
    fused_acc = accuracy_score(val_labels, fused_preds)
    fused_macro_f1 = f1_score(val_labels, fused_preds, average="macro", zero_division=0)

    clf_report = classification_report(val_labels, fused_preds, digits=4, zero_division=0, output_dict=True)
    clf_report_text = classification_report(val_labels, fused_preds, digits=4, zero_division=0)

    elapsed_time = round(time.time() - start_time, 2)

    # Print Formatted Report
    print("\n" + "=" * 75)
    print("                    FINAL BENCHMARK EVALUATION REPORT")
    print("=" * 75)
    print(f"Overall Fused Accuracy : {fused_acc * 100:.2f}%")
    print(f"Overall Macro-F1 Score : {fused_macro_f1:.4f}")
    print(f"Agent 1 Standalone Acc : {a1_acc * 100:.2f}% | Macro-F1: {a1_macro_f1:.4f}")
    print(f"Agent Consensus Rate   : {agreement_counts['agreed'] / n_val * 100:.1f}% ({agreement_counts['agreed']}/{n_val})")
    print(f"Disagreement Handled   : {agreement_counts['disagreed']} records")
    print("-" * 75)
    print("Detailed Classification Report by Benchmark Class:")
    print(clf_report_text)
    print("-" * 75)
    print("Evidence Status Distribution:")
    for status, count in pd.Series(evidence_statuses).value_counts().items():
        print(f"  - {status:<32}: {count:>4} ({count/n_val*100:>5.1f}%)")
    print("=" * 75)

    # Build Submission Payload
    submission_payload = {
        "event": "JAYPEE AGENTIC AI INTERNATIONAL SUMMIT 2026",
        "track": "TRACK 1: Agentic AI for CYBERSECURITY",
        "project": "CyberSentinel: Multi-Agent Network Intrusion Detection & Adaptive Defense",
        "day": "Day 1 (Level 1)",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "validation_summary": {
            "total_validation_records": n_val,
            "overall_accuracy": round(fused_acc, 4),
            "macro_f1_score": round(fused_macro_f1, 4),
            "standalone_agent1_accuracy": round(a1_acc, 4),
            "standalone_agent1_macro_f1": round(a1_macro_f1, 4),
            "consensus_agreement_rate": round(agreement_counts["agreed"] / n_val, 4),
            "evaluation_time_seconds": elapsed_time
        },
        "per_class_metrics": {
            cls: {
                "precision": round(clf_report.get(cls, {}).get("precision", 0.0), 4),
                "recall": round(clf_report.get(cls, {}).get("recall", 0.0), 4),
                "f1_score": round(clf_report.get(cls, {}).get("f1-score", 0.0), 4),
                "support": clf_report.get(cls, {}).get("support", 0)
            }
            for cls in BENCHMARK_CLASSES if cls in clf_report
        },
        "evidence_status_breakdown": {
            str(k): int(v) for k, v in pd.Series(evidence_statuses).value_counts().items()
        },
        "sample_agent_decisions": detailed_audit_logs[:8]
    }

    # Save to disk
    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(SUBMISSION_JSON_PATH, "w") as f:
        json.dump(submission_payload, f, indent=2)

    print(f"\n[+] API submission summary successfully exported to: {SUBMISSION_JSON_PATH}")
    return submission_payload


if __name__ == "__main__":
    dataset_file = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DATA_PATH
    evaluate_cyber_sentinel_pipeline(dataset_file)

"""
SpectreSync — Enterprise Anomaly Detection Engine
=================================================
Unsupervised Network Threat & Outlier Detection using Scikit-Learn's Isolation Forest.

Author: Senior Machine Learning Engineer
Project: SpectreSync Cybersecurity Deception & Threat Monitoring
"""

import argparse
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import RobustScaler, StandardScaler

# ─────────────────────────────────────────────────────────────────────────────
# Logging Setup
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("SpectreSync.AnomalyDetector")


# ─────────────────────────────────────────────────────────────────────────────
# Configuration Dataclass
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class AnomalyDetectorConfig:
    """Hyperparameters and configuration for the Isolation Forest pipeline."""

    n_estimators: int = 150
    contamination: Union[float, str] = 0.10  # Expected proportion of outliers (or 'auto')
    max_samples: Union[str, int, float] = "auto"  # Default 256 avoids swamping & masking
    random_state: int = 42
    scaler_type: str = "robust"  # 'robust' or 'standard'
    top_k_features: int = 3  # Number of root-cause supporting features to extract
    sample_size: Optional[int] = None  # None for full dataset, or int for subsample
    n_jobs: int = 1  # 1 is safe across Windows multiprocessing environments
    drop_constant_features: bool = True
    output_dir: Path = Path(__file__).resolve().parent / "data"


# ─────────────────────────────────────────────────────────────────────────────
# Data Preprocessor
# ─────────────────────────────────────────────────────────────────────────────
class DataPreprocessor:
    """
    Handles robust ingestion, sanitization, missing-value imputation,
    and feature scaling for network flow telemetry.
    """

    def __init__(self, config: AnomalyDetectorConfig):
        self.config = config
        self.scaler = RobustScaler() if config.scaler_type == "robust" else StandardScaler()
        self.imputer = SimpleImputer(strategy="median")
        self.feature_columns: List[str] = []
        self.dropped_constant_columns: List[str] = []
        self.metadata_columns: List[str] = []
        self.medians: Optional[pd.Series] = None
        self.scales: Optional[np.ndarray] = None

    def find_dataset_path(self, user_path: Optional[str] = None) -> Path:
        """
        Locate the dataset in the workspace with automatic discovery fallbacks.
        """
        if user_path and Path(user_path).exists():
            return Path(user_path)

        candidate_paths = [
            Path(__file__).resolve().parent / "data" / "flows_eval.parquet",
            Path(__file__).resolve().parent / "data" / "flows.parquet",
            Path(__file__).resolve().parent / "__pycache__" / "cyber-pack" / "Cyber" / "eval" / "flows.parquet",
            Path(__file__).resolve().parent / "__pycache__" / "cyber-pack" / "Cyber" / "training" / "flows.parquet",
            Path("C:/Users/lenovo/Downloads/cyber-pack/Cyber/eval/flows.parquet"),
        ]

        for p in candidate_paths:
            if p.exists():
                logger.info(f"Auto-discovered dataset at: {p}")
                return p

        raise FileNotFoundError(
            f"No dataset found. Checked candidates:\n" + "\n".join(str(c) for c in candidate_paths)
        )

    def load_data(self, file_path: Path, sample_size: Optional[int] = None) -> pd.DataFrame:
        """
        Loads dataset from Parquet or CSV format with optional stratified/random subsampling.
        """
        logger.info(f"Loading telemetry data from: {file_path}")
        start_t = time.time()

        if str(file_path).endswith(".parquet"):
            df = pd.read_parquet(file_path)
        elif str(file_path).endswith(".csv"):
            df = pd.read_csv(file_path)
        else:
            raise ValueError(f"Unsupported file format for {file_path}. Use .parquet or .csv")

        elapsed = time.time() - start_t
        logger.info(f"Loaded {len(df):,} records ({df.shape[1]} columns) in {elapsed:.2f}s")

        if sample_size and sample_size < len(df):
            logger.info(f"Subsampling {sample_size:,} records (random_state={self.config.random_state})")
            if "label" in df.columns:
                # Maintain class representation during subsampling for realistic validation
                frac = min(1.0, sample_size / len(df))
                df = df.groupby("label", group_keys=False).sample(
                    frac=frac, random_state=self.config.random_state
                ).reset_index(drop=True)
            else:
                df = df.sample(n=sample_size, random_state=self.config.random_state).reset_index(drop=True)
            logger.info(f"Active working subset size: {len(df):,} records")

        return df

    def inspect_data(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Comprehensive data inspection reporting missing values, data types, and infinite values.
        """
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        non_numeric_cols = [c for c in df.columns if c not in numeric_cols]

        nan_count = int(df.isna().sum().sum())
        inf_count = int(np.isinf(df[numeric_cols].values).sum()) if numeric_cols else 0

        inspection = {
            "total_records": len(df),
            "total_columns": df.shape[1],
            "numeric_feature_count": len(numeric_cols),
            "non_numeric_columns": non_numeric_cols,
            "missing_values_count": nan_count,
            "infinite_values_count": inf_count,
            "memory_usage_mb": round(df.memory_usage(deep=True).sum() / (1024 * 1024), 2),
        }

        if "label" in df.columns:
            inspection["ground_truth_label_distribution"] = df["label"].value_counts().to_dict()

        logger.info(
            f"Data Inspection Summary: {inspection['total_records']:,} rows, "
            f"{inspection['numeric_feature_count']} numeric features, "
            f"{nan_count} NaNs, {inf_count} Infs, {inspection['memory_usage_mb']} MB"
        )
        return inspection

    def fit_transform(self, df: pd.DataFrame) -> Tuple[np.ndarray, pd.DataFrame, List[str]]:
        """
        Prepares the feature matrix:
        1. Separates metadata columns (e.g. record_id, label).
        2. Drops zero-variance/constant features.
        3. Sanitizes infinite/NaN values.
        4. Scales features via RobustScaler (median & IQR).
        5. Computes robust baseline statistics for root cause explanation.
        """
        # Distinguish metadata from learning features
        id_candidates = ["record_id", "id", "flow_id", "timestamp"]
        label_candidates = ["label", "class", "target", "attack_type"]

        self.metadata_columns = [c for c in df.columns if c.lower() in id_candidates + label_candidates]
        meta_df = df[self.metadata_columns].copy() if self.metadata_columns else pd.DataFrame(index=df.index)

        feature_df = df.drop(columns=self.metadata_columns).select_dtypes(include=[np.number]).copy()

        # Handle infinite values by replacing with NaN
        feature_df = feature_df.replace([np.inf, -np.inf], np.nan)

        # Drop zero-variance columns (constant values offer no discriminative power)
        if self.config.drop_constant_features:
            variances = feature_df.var()
            self.dropped_constant_columns = variances[variances == 0].index.tolist()
            if self.dropped_constant_columns:
                logger.info(
                    f"Dropped {len(self.dropped_constant_columns)} zero-variance column(s): "
                    f"{self.dropped_constant_columns}"
                )
                feature_df = feature_df.drop(columns=self.dropped_constant_columns)

        self.feature_columns = feature_df.columns.tolist()

        # Compute robust baseline statistics for anomaly explanation (Median & MAD)
        self.medians = feature_df.median()
        # MAD * 1.4826 approximates standard deviation for normally distributed inliers
        mads = (feature_df - self.medians).abs().median() * 1.4826
        stds = feature_df.std()
        # Fallback to standard deviation if MAD is 0 (common in sparse count features)
        self.scales = np.where(mads > 1e-6, mads, np.where(stds > 1e-6, stds, 1.0))

        # Impute missing values with median
        imputed_features = self.imputer.fit_transform(feature_df)

        # Scale features
        scaled_features = self.scaler.fit_transform(imputed_features)

        logger.info(f"Engineered feature matrix: {scaled_features.shape[1]} active scaled features")
        return scaled_features, meta_df, self.feature_columns


# ─────────────────────────────────────────────────────────────────────────────
# Root Cause / Supporting Feature Explainer
# ─────────────────────────────────────────────────────────────────────────────
class AnomalyExplainer:
    """
    Computes explainability metrics and root-cause attribution for flagged anomalies.
    Calculates robust feature deviations against the normal population baseline.
    """

    def __init__(self, feature_columns: List[str], medians: pd.Series, scales: np.ndarray):
        self.feature_columns = feature_columns
        self.medians = medians
        self.scales = scales

    def explain(
        self,
        raw_features_df: pd.DataFrame,
        anomaly_mask: np.ndarray,
        top_k: int = 3,
    ) -> Tuple[List[str], List[str], List[float]]:
        """
        For each record flagged as an anomaly, identify the top K features exhibiting
        the greatest normalized deviation (|z-score|) from the population median.
        """
        logger.info(f"Extracting top-{top_k} root-cause supporting features for flagged anomalies...")
        start_t = time.time()

        n_records = len(raw_features_df)
        supporting_features_list: List[str] = [""] * n_records
        primary_causes: List[str] = [""] * n_records
        primary_devs: List[float] = [0.0] * n_records

        anomaly_indices = np.where(anomaly_mask)[0]
        if len(anomaly_indices) == 0:
            return supporting_features_list, primary_causes, primary_devs

        # Vectorized normalized deviation computation: (X - median) / scale
        features_values = raw_features_df.values
        norm_diffs = (features_values[anomaly_indices] - self.medians.values) / self.scales
        abs_diffs = np.abs(norm_diffs)

        for i, idx in enumerate(anomaly_indices):
            row_abs = abs_diffs[i]
            row_norm = norm_diffs[i]
            row_raw = features_values[idx]

            # Top K feature indices with largest absolute deviation
            top_indices = np.argsort(row_abs)[::-1][:top_k]

            explanations = []
            for rank, feat_idx in enumerate(top_indices):
                feat_name = self.feature_columns[feat_idx]
                z_score = row_norm[feat_idx]
                val = row_raw[feat_idx]
                direction = "HIGH" if z_score > 0 else "LOW"

                explanations.append(
                    f"{feat_name}: {direction} (|z|={abs(z_score):.1f}, val={val:.2f})"
                )

                if rank == 0:
                    primary_causes[idx] = feat_name
                    primary_devs[idx] = round(float(z_score), 2)

            supporting_features_list[idx] = " | ".join(explanations)

        logger.info(
            f"Root cause attribution completed for {len(anomaly_indices):,} anomalies in {time.time() - start_t:.2f}s"
        )
        return supporting_features_list, primary_causes, primary_devs


# ─────────────────────────────────────────────────────────────────────────────
# Isolation Forest Anomaly Detection Engine
# ─────────────────────────────────────────────────────────────────────────────
class IsolationForestAnomalyDetector:
    """
    Production-ready Unsupervised Anomaly Detection Pipeline using Scikit-Learn IsolationForest.
    """

    def __init__(self, config: Optional[AnomalyDetectorConfig] = None):
        self.config = config or AnomalyDetectorConfig()
        self.preprocessor = DataPreprocessor(self.config)
        self.model = IsolationForest(
            n_estimators=self.config.n_estimators,
            contamination=self.config.contamination,
            max_samples=self.config.max_samples,
            random_state=self.config.random_state,
            n_jobs=self.config.n_jobs,
            bootstrap=False,
        )
        self.explainer: Optional[AnomalyExplainer] = None
        self.is_fitted: bool = False

    def fit_predict(
        self,
        raw_df: pd.DataFrame,
    ) -> pd.DataFrame:
        """
        Executes end-to-end anomaly detection on the provided dataframe:
        1. Preprocesses and scales features.
        2. Fits the Isolation Forest model.
        3. Computes binary anomaly predictions (-1 vs 1).
        4. Calculates decision function scores and calibrated threat risk scores.
        5. Identifies root-cause supporting features.
        6. Constructs and returns the final enriched results dataframe.
        """
        logger.info(
            f"Configuring Isolation Forest: n_estimators={self.config.n_estimators}, "
            f"contamination={self.config.contamination}, max_samples={self.config.max_samples}, "
            f"random_state={self.config.random_state}"
        )

        # Step 1: Preprocessing & Scaling
        X_scaled, meta_df, feature_cols = self.preprocessor.fit_transform(raw_df)

        # Step 2: Fit Isolation Forest
        logger.info("Fitting unsupervised Isolation Forest ensemble...")
        fit_start = time.time()
        self.model.fit(X_scaled)
        self.is_fitted = True
        logger.info(f"Model fitted successfully in {time.time() - fit_start:.2f}s")

        # Step 3: Inference & Score Generation
        logger.info("Generating anomaly predictions and decision function scores...")
        pred_start = time.time()
        binary_preds = self.model.predict(X_scaled)  # -1 = anomaly, 1 = normal
        decision_scores = self.model.decision_function(X_scaled)  # < 0 is anomaly
        sample_scores = self.model.score_samples(X_scaled)  # opposite of path length
        logger.info(f"Inference completed in {time.time() - pred_start:.2f}s")

        # Step 4: Calibrated Threat Risk Score (0.0 to 1.0)
        # Invert decision function: lower decision function means higher anomaly risk
        min_score = decision_scores.min()
        max_score = decision_scores.max()
        if max_score > min_score:
            risk_scores = (max_score - decision_scores) / (max_score - min_score)
        else:
            risk_scores = np.zeros_like(decision_scores)

        # Step 5: Root-Cause / Supporting Features Extraction
        anomaly_mask = binary_preds == -1
        self.explainer = AnomalyExplainer(
            feature_cols,
            self.preprocessor.medians,
            self.preprocessor.scales,
        )
        supporting_feats, primary_causes, primary_devs = self.explainer.explain(
            raw_df[feature_cols],
            anomaly_mask,
            top_k=self.config.top_k_features,
        )

        # Step 6: Construct Enriched Result DataFrame
        results_df = raw_df.copy()

        # Append detection outputs
        results_df["anomaly_prediction"] = binary_preds  # -1: Anomaly, 1: Normal
        results_df["prediction_label"] = np.where(binary_preds == -1, "ANOMALY", "NORMAL")
        results_df["anomaly_score"] = np.round(decision_scores, 5)
        results_df["sample_score"] = np.round(sample_scores, 5)
        results_df["threat_risk_score"] = np.round(risk_scores, 4)
        results_df["threat_risk_percent"] = np.round(risk_scores * 100, 1)

        # Supporting features
        results_df["supporting_features"] = supporting_feats
        results_df["primary_root_cause"] = primary_causes
        results_df["primary_deviation_sigma"] = primary_devs

        # Categorize threat severity
        severity_conditions = [
            (results_df["prediction_label"] == "NORMAL"),
            (results_df["threat_risk_percent"] >= 80.0),
            (results_df["threat_risk_percent"] >= 60.0),
        ]
        severity_choices = ["NORMAL", "CRITICAL_ANOMALY", "HIGH_ANOMALY"]
        results_df["anomaly_severity"] = np.select(
            severity_conditions,
            severity_choices,
            default="ELEVATED_ANOMALY",
        )

        return results_df

    def summarize_results(self, results_df: pd.DataFrame) -> Dict[str, Any]:
        """
        Generates a clear statistical summary of detection results,
        including attack class recall breakdowns if ground-truth labels exist.
        """
        total = len(results_df)
        anomaly_count = int((results_df["anomaly_prediction"] == -1).sum())
        normal_count = int((results_df["anomaly_prediction"] == 1).sum())
        anomaly_pct = round((anomaly_count / total) * 100, 2)
        normal_pct = round((normal_count / total) * 100, 2)

        summary: Dict[str, Any] = {
            "execution_metadata": {
                "total_instances": total,
                "n_estimators": self.config.n_estimators,
                "configured_contamination": self.config.contamination,
                "scaler": self.config.scaler_type,
            },
            "detection_counts": {
                "normal_instances": normal_count,
                "normal_percentage": normal_pct,
                "anomalous_instances": anomaly_count,
                "anomalous_percentage": anomaly_pct,
            },
            "anomaly_score_distribution": {
                "min_decision_score": float(results_df["anomaly_score"].min()),
                "median_decision_score": float(results_df["anomaly_score"].median()),
                "max_decision_score": float(results_df["anomaly_score"].max()),
                "avg_risk_score_anomaly": float(
                    results_df.loc[results_df["anomaly_prediction"] == -1, "threat_risk_score"].mean()
                )
                if anomaly_count > 0
                else 0.0,
            },
            "severity_breakdown": results_df["anomaly_severity"].value_counts().to_dict(),
        }

        # Ground-truth label cross-validation (if available in cybersecurity dataset)
        if "label" in results_df.columns:
            ctab = pd.crosstab(
                results_df["label"],
                results_df["prediction_label"],
                margins=True,
            )
            summary["ground_truth_cross_tabulation"] = ctab.to_dict()

            # Calculate detection recall per attack class
            attack_recalls = {}
            for lbl, grp in results_df.groupby("label"):
                anom_in_grp = (grp["anomaly_prediction"] == -1).sum()
                attack_recalls[lbl] = {
                    "total_samples": len(grp),
                    "flagged_as_anomaly": int(anom_in_grp),
                    "anomaly_detection_rate_pct": round((anom_in_grp / len(grp)) * 100, 2),
                }
            summary["attack_class_detection_rates"] = attack_recalls

        # Top root cause attributes flagged
        anomalies_only = results_df[results_df["anomaly_prediction"] == -1]
        if not anomalies_only.empty:
            top_causes = (
                anomalies_only["primary_root_cause"]
                .replace("", np.nan)
                .dropna()
                .value_counts()
                .head(5)
                .to_dict()
            )
            summary["top_root_cause_features"] = top_causes

        return summary

    def save_results(
        self,
        results_df: pd.DataFrame,
        summary: Dict[str, Any],
        output_dir: Optional[Path] = None,
        prefix: str = "spectresync_anomaly_results",
    ) -> Tuple[Path, Path]:
        """
        Exports the results dataframe to CSV and the summary report to JSON.
        """
        out_dir = output_dir or self.config.output_dir
        out_dir.mkdir(parents=True, exist_ok=True)

        csv_path = out_dir / f"{prefix}.csv"
        json_path = out_dir / f"{prefix}_summary.json"

        logger.info(f"Saving enriched results dataframe to: {csv_path}")
        results_df.to_csv(csv_path, index=False)

        logger.info(f"Saving execution summary to: {json_path}")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        return csv_path, json_path


# ─────────────────────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────────────────────
def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SpectreSync Isolation Forest Anomaly Detection Engine",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--data-path",
        type=str,
        default=None,
        help="Path to input dataset (.parquet or .csv). Defaults to auto-discovery in data/.",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=25000,
        help="Subsample size for high-speed analysis (set to 0 for entire dataset).",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.10,
        help="Expected anomaly contamination rate (e.g. 0.05, 0.10, 0.15).",
    )
    parser.add_argument(
        "--n-estimators",
        type=int,
        default=150,
        help="Number of isolation trees in the ensemble.",
    )
    parser.add_argument(
        "--scaler",
        type=str,
        choices=["robust", "standard"],
        default="robust",
        help="Feature scaling technique.",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data",
        help="Directory to save output CSV and summary JSON.",
    )
    return parser.parse_args()


def run_pipeline(
    data_path: Optional[str] = None,
    sample_size: Optional[int] = 25000,
    contamination: float = 0.10,
    n_estimators: int = 150,
    scaler_type: str = "robust",
    output_dir: str = "data",
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Convenience function to run the full anomaly detection pipeline programmatically.
    """
    config = AnomalyDetectorConfig(
        n_estimators=n_estimators,
        contamination=contamination,
        scaler_type=scaler_type,
        sample_size=sample_size if sample_size and sample_size > 0 else None,
        output_dir=Path(output_dir),
    )

    detector = IsolationForestAnomalyDetector(config)

    # 1. Locate and inspect dataset
    target_path = detector.preprocessor.find_dataset_path(data_path)
    df = detector.preprocessor.load_data(target_path, sample_size=config.sample_size)
    detector.preprocessor.inspect_data(df)

    # 2. Fit model and predict
    results_df = detector.fit_predict(df)

    # 3. Generate summary
    summary = detector.summarize_results(results_df)

    # 4. Save results
    detector.save_results(results_df, summary)

    return results_df, summary


def main():
    args = parse_arguments()
    sample_size = None if args.sample_size == 0 else args.sample_size

    print("=" * 80)
    print(" SpectreSync — Enterprise Threat Anomaly Detection (Isolation Forest)")
    print("=" * 80)

    results_df, summary = run_pipeline(
        data_path=args.data_path,
        sample_size=sample_size,
        contamination=args.contamination,
        n_estimators=args.n_estimators,
        scaler_type=args.scaler,
        output_dir=args.output_dir,
    )

    print("\n" + "=" * 80)
    print(" EXECUTION SUMMARY")
    print("=" * 80)
    counts = summary["detection_counts"]
    print(f"Total Evaluated Records:   {summary['execution_metadata']['total_instances']:,}")
    print(f"Normal Instances Detected: {counts['normal_instances']:,} ({counts['normal_percentage']}%)")
    print(f"Anomalies Detected:        {counts['anomalous_instances']:,} ({counts['anomalous_percentage']}%)")
    print(f"Contamination Threshold:   {summary['execution_metadata']['configured_contamination']}")
    print(f"Severity Distribution:     {summary['severity_breakdown']}")

    if "attack_class_detection_rates" in summary:
        print("\n" + "-" * 80)
        print(" GROUND TRUTH ATTACK VALIDATION BREAKDOWN")
        print("-" * 80)
        for atk, stats in summary["attack_class_detection_rates"].items():
            print(
                f"  • {atk:<14}: {stats['flagged_as_anomaly']:>5} / {stats['total_samples']:>5} "
                f"flagged as anomaly ({stats['anomaly_detection_rate_pct']:>5.1f}%)"
            )

    if "top_root_cause_features" in summary:
        print("\n" + "-" * 80)
        print(" TOP ROOT-CAUSE ATTRIBUTES IN ISOLATED ANOMALIES")
        print("-" * 80)
        for feat, count in summary["top_root_cause_features"].items():
            print(f"  • {feat:<35}: {count} occurrences as primary deviation")

    print("\n" + "-" * 80)
    print(" SAMPLE ANOMALOUS RECORDS & SUPPORTING ROOT-CAUSE FEATURES")
    print("-" * 80)
    flagged = results_df[results_df["anomaly_prediction"] == -1].head(5)
    cols_to_show = ["record_id", "prediction_label", "threat_risk_percent", "primary_root_cause"]
    if "label" in results_df.columns:
        cols_to_show.insert(1, "label")

    for _, row in flagged.iterrows():
        id_str = row.get("record_id", "N/A")
        lbl_str = f" [True Label: {row['label']}]" if "label" in row else ""
        print(f"\nRecord {id_str}{lbl_str}:")
        print(f"  Risk Index: {row['threat_risk_percent']}% | Severity: {row['anomaly_severity']}")
        print(f"  Supporting Root Cause: {row['supporting_features']}")

    print("\n" + "=" * 80)
    print(" Pipeline completed successfully.")
    print("=" * 80)


if __name__ == "__main__":
    main()

"""
Unit & Integration Tests for SpectreSync Anomaly Detection Engine
=================================================================
Validates preprocessing, Isolation Forest modeling, anomaly score generation,
and root-cause supporting feature attribution.
"""

import unittest
from pathlib import Path
import numpy as np
import pandas as pd

from anomaly_detector import (
    AnomalyDetectorConfig,
    DataPreprocessor,
    IsolationForestAnomalyDetector,
    run_pipeline,
)


class TestAnomalyDetector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create a synthetic dataset mimicking network flow telemetry
        np.random.seed(42)
        n_samples = 200
        cls.data = pd.DataFrame(
            {
                "record_id": [f"TEST_{i:04d}" for i in range(n_samples)],
                "flow_duration": np.random.exponential(scale=1000, size=n_samples),
                "total_fwd_packets": np.random.poisson(lam=10, size=n_samples).astype(float),
                "total_bwd_packets": np.random.poisson(lam=8, size=n_samples).astype(float),
                "packet_length_mean": np.random.normal(loc=500, scale=50, size=n_samples),
                "constant_feature": np.zeros(n_samples),  # zero-variance test
                "label": ["BENIGN"] * (n_samples - 10) + ["DOS"] * 10,
            }
        )
        # Inject artificial extreme outliers in the last 5 records
        cls.data.loc[n_samples - 5 :, "flow_duration"] = 500000.0
        cls.data.loc[n_samples - 5 :, "total_fwd_packets"] = 2500.0

    def test_config_initialization(self):
        config = AnomalyDetectorConfig(n_estimators=100, contamination=0.05)
        self.assertEqual(config.n_estimators, 100)
        self.assertEqual(config.contamination, 0.05)
        self.assertEqual(config.random_state, 42)

    def test_preprocessor_pipeline(self):
        config = AnomalyDetectorConfig(drop_constant_features=True)
        preprocessor = DataPreprocessor(config)

        inspection = preprocessor.inspect_data(self.data)
        self.assertEqual(inspection["total_records"], 200)
        self.assertEqual(inspection["missing_values_count"], 0)

        X_scaled, meta_df, feature_cols = preprocessor.fit_transform(self.data)

        # Constant feature should be dropped
        self.assertNotIn("constant_feature", feature_cols)
        self.assertIn("record_id", meta_df.columns)
        self.assertIn("label", meta_df.columns)
        self.assertEqual(X_scaled.shape[0], 200)
        self.assertEqual(X_scaled.shape[1], len(feature_cols))

    def test_detector_fit_predict_and_root_cause(self):
        config = AnomalyDetectorConfig(
            n_estimators=50,
            contamination=0.05,
            top_k_features=2,
            random_state=42,
        )
        detector = IsolationForestAnomalyDetector(config)
        results_df = detector.fit_predict(self.data)

        # Check required output columns
        expected_cols = [
            "anomaly_prediction",
            "prediction_label",
            "anomaly_score",
            "threat_risk_score",
            "supporting_features",
            "primary_root_cause",
        ]
        for col in expected_cols:
            self.assertIn(col, results_df.columns)

        # Verify predictions contain -1 (anomaly) and 1 (normal)
        unique_preds = set(results_df["anomaly_prediction"].unique())
        self.assertTrue(unique_preds.issubset({-1, 1}))

        # Verify anomalies have non-empty supporting root causes
        anomalies = results_df[results_df["anomaly_prediction"] == -1]
        self.assertGreater(len(anomalies), 0)
        for _, row in anomalies.iterrows():
            self.assertGreater(len(row["supporting_features"]), 0)
            self.assertGreater(len(row["primary_root_cause"]), 0)

        # Summary verification
        summary = detector.summarize_results(results_df)
        self.assertEqual(
            summary["detection_counts"]["normal_instances"]
            + summary["detection_counts"]["anomalous_instances"],
            200,
        )


if __name__ == "__main__":
    unittest.main()

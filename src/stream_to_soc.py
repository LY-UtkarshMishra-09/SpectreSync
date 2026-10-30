"""
CyberSentinel Agent 1 -> SpectreSync SOC Threat Feed Bridge
Reads flows from ./data/cleaned_cicids2017.csv, runs predict_threat(),
and populates the SpectreSync SOC Threat Feed (spectresync.db & REST API).
"""

import os
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import uuid
import sqlite3
import datetime
import random
import pandas as pd
import requests
from src.agent1_classifier import get_threat_detection_agent, map_to_benchmark_class

DB_PATH = "spectresync.db"
API_URL = "http://localhost:5000/api/defense/events"

ATTACK_SIGNATURES = {
    "DOS": {
        "target": "/api/v1/vault/session",
        "ua": "CyberSentinel-Agent1 // Slowloris-DoS (Python-urllib)",
        "delay_range": (5500, 8500),
        "status_tpl": "Suspended ({delay:.1f}s Tarpit)"
    },
    "DDOS": {
        "target": "/api/v1/auth/keys",
        "ua": "CyberSentinel-Agent1 // High-Velocity Packet Flood (UDP/SYN)",
        "delay_range": (7000, 10000),
        "status_tpl": "Suspended ({delay:.1f}s Tarpit)"
    },
    "PORT_SCAN": {
        "target": "/admin/config.php",
        "ua": "CyberSentinel-Agent1 // PortScan-Recon (Masscan v1.3)",
        "delay_range": (3500, 6000),
        "status_tpl": "Suspended ({delay:.1f}s Tarpit)"
    },
    "BRUTE_FORCE": {
        "target": "AWS_SECRET_ACCESS_KEY",
        "ua": "CyberSentinel-Agent1 // Credential-Burst (Hydra/Patator)",
        "delay_range": (4500, 7500),
        "status_tpl": "CANARY_TRIGGERED (Quarantine Enforced)"
    },
    "BENIGN": {
        "target": "/public/health",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0",
        "delay_range": (200, 500),
        "status_tpl": "Passive Monitoring (ALLOW)"
    }
}

def stream_predictions_to_soc(csv_path: str = "data/cleaned_cicids2017.csv", sample_count: int = 15):
    print("=" * 65)
    print("CYBERSENTINEL AGENT 1 -> SOC THREAT FEED INGESTION")
    print("=" * 65)

    if not os.path.exists(csv_path):
        print(f"[!] Dataset not found at {csv_path}")
        return

    agent = get_threat_detection_agent()
    agent.load_or_train()

    df = pd.read_csv(csv_path)
    print(f"Loaded {len(df)} records from {csv_path}")

    # Pick representative samples including all attacks and benign flows
    attack_samples = []
    for cls in ["DDOS", "DOS", "PORT_SCAN", "BRUTE_FORCE", "BENIGN"]:
        sub_df = df[df["target_label"] == cls]
        if not sub_df.empty:
            take_n = min(3, len(sub_df))
            attack_samples.append(sub_df.sample(take_n, random_state=42))

    if attack_samples:
        test_df = pd.concat(attack_samples).sample(frac=1.0, random_state=42)
    else:
        test_df = df.head(sample_count)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    now = datetime.datetime.now(datetime.timezone.utc)
    inserted_count = 0

    print(f"\nProcessing {len(test_df)} sample network flows through Agent 1 Classifier...\n")

    for i, (_, row) in enumerate(test_df.iterrows()):
        flow_dict = row.to_dict()
        true_label = flow_dict.pop("target_label", "UNKNOWN")
        
        # Agent 1 inference
        prediction = agent.predict_threat(flow_dict)
        pred_class = prediction["predicted_class"]
        confidence = prediction["confidence"]
        
        # Don't flood feed with only benign flows; highlight all threats and 1-2 verified benigns
        meta = ATTACK_SIGNATURES.get(pred_class, ATTACK_SIGNATURES["DOS"])
        delay_ms = random.randint(*meta["delay_range"])
        suspension_status = meta["status_tpl"].format(delay=delay_ms / 1000)

        # Generate timestamps staggered over the past 20 minutes
        stagger_seconds = (len(test_df) - i) * random.randint(45, 120)
        timestamp = (now - datetime.timedelta(seconds=stagger_seconds)).isoformat()

        # Format simulated source IP based on attack category
        if pred_class == "DDOS":
            source_ip = f"185.220.{random.randint(10, 250)}.{random.randint(2, 254)}"
        elif pred_class == "DOS":
            source_ip = f"198.51.100.{random.randint(10, 99)}"
        elif pred_class == "PORT_SCAN":
            source_ip = f"192.0.2.{random.randint(10, 99)}"
        elif pred_class == "BRUTE_FORCE":
            source_ip = f"203.0.113.{random.randint(50, 180)}"
        else:
            source_ip = f"10.0.4.{random.randint(2, 50)} (Internal)"

        alert_id = f"nids-{uuid.uuid4().hex[:10]}"
        target_asset = meta["target"]
        user_agent = f"{meta['ua']} [Conf: {confidence*100:.1f}%]"

        # Direct SQLite ingestion
        cursor.execute(
            """
            INSERT INTO alerts (id, trap_id, timestamp, ip, type, status, tarpit_duration)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (alert_id, target_asset, timestamp, source_ip, user_agent, suspension_status, delay_ms)
        )
        inserted_count += 1

        print(f"[{i+1}/{len(test_df)}] {pred_class:<12} (Conf: {confidence*100:.1f}%) | "
              f"IP: {source_ip:<18} | Target: {target_asset:<25} -> {suspension_status}")

        # Optional: post to live Active Defense Agent REST endpoint if backend is running
        try:
            requests.post(
                API_URL,
                json={
                    "type": "PORT_SCAN_DETECTED" if pred_class == "PORT_SCAN" else "CANARY_EXPOSED",
                    "sourceIp": source_ip,
                    "targetAsset": target_asset,
                    "userAgent": user_agent,
                    "metadata": {
                        "agent1_predicted_class": pred_class,
                        "agent1_confidence": confidence,
                        "delayMs": delay_ms
                    }
                },
                timeout=0.3
            )
        except Exception:
            pass

    conn.commit()
    conn.close()

    print("\n" + "=" * 65)
    print(f"SUCCESS: Ingested {inserted_count} Agent 1 detections into {DB_PATH}")
    print("Refresh your browser on http://localhost:3000 to view them on the SOC Threat Feed!")
    print("=" * 65)

if __name__ == "__main__":
    stream_predictions_to_soc()

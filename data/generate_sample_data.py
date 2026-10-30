"""
Utility to generate a schema-accurate synthetic validation & test dataset for CICIDS2017
Includes the 5 benchmark classes: BENIGN, BRUTE_FORCE, DOS, DDOS, PORT_SCAN
"""

import os
import numpy as np
import pandas as pd

def generate_sample_dataset(output_path: str = "data/cleaned_cicids2017.csv", n_samples: int = 2500):
    np.random.seed(42)
    classes = ["BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"]
    class_probs = [0.45, 0.12, 0.15, 0.15, 0.13]
    
    labels = np.random.choice(classes, size=n_samples, p=class_probs)
    
    data = []
    for label in labels:
        if label == "BENIGN":
            flow_duration = np.random.exponential(scale=5000)
            tot_fwd_pkts = np.random.poisson(lam=12)
            tot_bwd_pkts = np.random.poisson(lam=15)
            pkt_len_mean = np.random.normal(loc=450, scale=80)
            flow_bytes_s = np.random.exponential(scale=20000)
            flow_pkts_s = np.random.exponential(scale=80)
            syn_flag = int(np.random.rand() < 0.05)
            ack_flag = int(np.random.rand() < 0.90)
            rst_flag = int(np.random.rand() < 0.01)
            dst_port = np.random.choice([80, 443, 8080, 53, 22])
            
        elif label == "DOS":
            flow_duration = np.random.exponential(scale=45000)
            tot_fwd_pkts = np.random.poisson(lam=80)
            tot_bwd_pkts = np.random.poisson(lam=5)
            pkt_len_mean = np.random.normal(loc=80, scale=20)
            flow_bytes_s = np.random.exponential(scale=800000)
            flow_pkts_s = np.random.exponential(scale=1200)
            syn_flag = int(np.random.rand() < 0.85)
            ack_flag = int(np.random.rand() < 0.15)
            rst_flag = int(np.random.rand() < 0.40)
            dst_port = np.random.choice([80, 443])
            
        elif label == "DDOS":
            flow_duration = np.random.exponential(scale=60000)
            tot_fwd_pkts = np.random.poisson(lam=150)
            tot_bwd_pkts = np.random.poisson(lam=2)
            pkt_len_mean = np.random.normal(loc=64, scale=10)
            flow_bytes_s = np.random.exponential(scale=2500000)
            flow_pkts_s = np.random.exponential(scale=3500)
            syn_flag = int(np.random.rand() < 0.95)
            ack_flag = int(np.random.rand() < 0.05)
            rst_flag = int(np.random.rand() < 0.50)
            dst_port = np.random.choice([80, 443, 8080])

        elif label == "PORT_SCAN":
            flow_duration = np.random.exponential(scale=200)
            tot_fwd_pkts = np.random.poisson(lam=2)
            tot_bwd_pkts = np.random.poisson(lam=1)
            pkt_len_mean = np.random.normal(loc=40, scale=5)
            flow_bytes_s = np.random.exponential(scale=1200)
            flow_pkts_s = np.random.exponential(scale=40)
            syn_flag = int(np.random.rand() < 0.98)
            ack_flag = int(np.random.rand() < 0.02)
            rst_flag = int(np.random.rand() < 0.75)
            dst_port = np.random.randint(1, 65535)

        elif label == "BRUTE_FORCE":
            flow_duration = np.random.exponential(scale=15000)
            tot_fwd_pkts = np.random.poisson(lam=35)
            tot_bwd_pkts = np.random.poisson(lam=30)
            pkt_len_mean = np.random.normal(loc=120, scale=30)
            flow_bytes_s = np.random.exponential(scale=35000)
            flow_pkts_s = np.random.exponential(scale=150)
            syn_flag = int(np.random.rand() < 0.10)
            ack_flag = int(np.random.rand() < 0.80)
            rst_flag = int(np.random.rand() < 0.35)
            dst_port = np.random.choice([21, 22, 3389, 445])
            
        data.append({
            "Destination Port": dst_port,
            "Flow Duration": max(1, flow_duration),
            "Total Fwd Packets": max(1, tot_fwd_pkts),
            "Total Backward Packets": max(0, tot_bwd_pkts),
            "Flow Bytes/s": max(0, flow_bytes_s),
            "Flow Packets/s": max(0, flow_pkts_s),
            "Packet Length Mean": max(20, pkt_len_mean),
            "SYN Flag Count": syn_flag,
            "ACK Flag Count": ack_flag,
            "RST Flag Count": rst_flag,
            "target_label": label
        })
        
    df = pd.DataFrame(data)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"Generated sample CICIDS2017 dataset at: {output_path} ({len(df)} records)")
    print("Class breakdown:\n", df["target_label"].value_counts())
    return df

if __name__ == "__main__":
    generate_sample_dataset()


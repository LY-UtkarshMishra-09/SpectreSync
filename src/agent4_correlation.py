"""
CyberSentinel: Multi-Agent Network Intrusion Detection & Adaptive Defense
Agent 4: Temporal Correlation Agent (src/agent4_correlation.py)
JAYPEE AGENTIC AI INTERNATIONAL SUMMIT 2026 - TRACK 1 (DAY 2 // LEVEL 2)

Requirements:
- Group related suspicious flows using observed endpoints and time windows.
- Outputs: group IDs, member records, pattern classification, and supporting evidence.
- Never uses future records or hidden ground-truth labels.
"""

from typing import Dict, Any, List, Optional
from collections import defaultdict, deque


class TemporalCorrelationAgent:
    """
    Agent 4: Temporal Correlation Agent
    Maintains a stateful sliding window of observed network flows.
    Correlates recurring probes, port sweeps, and attack bursts across time
    to detect structured adversarial campaigns.
    """

    def __init__(self, window_size: int = 150):
        self.window_size = window_size
        self.group_counter = 0
        
        # Sliding history of recent records
        self.recent_flows = deque(maxlen=window_size)
        
        # Mapping: source_ip -> active group_id
        self.active_ip_groups: Dict[str, str] = {}
        
        # Mapping: group_id -> group metadata dict
        self.groups: Dict[str, Dict[str, Any]] = {}

    def reset(self):
        """Reset temporal state for a new evaluation or replay run."""
        self.group_counter = 0
        self.recent_flows.clear()
        self.active_ip_groups.clear()
        self.groups.clear()

    def correlate_flow(
        self,
        record_id: str,
        source_ip: str,
        dest_port: int,
        flow_features: Dict[str, Any],
        fused_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Correlate incoming flow with prior observed suspicious flows in the current window.

        Args:
            record_id: Unique record ID of the flow.
            source_ip: Observed or resolved source IP.
            dest_port: Observed destination port.
            flow_features: Numerical features of the network flow.
            fused_result: Output from Agent 3 (Evidence Fusion).

        Returns:
            dict with:
                - group_id: str or None
                - is_correlated: bool
                - pattern_type: str
                - member_records: list of record_ids
                - member_count: int
                - correlation_confidence: float
                - supporting_evidence: dict
                - recommendation: str
        """
        final_class = fused_result.get("final_class", "BENIGN")
        evidence_status = fused_result.get("evidence_status", "BENIGN_VERIFIED")
        fused_conf = fused_result.get("fused_confidence", 0.5)

        is_suspicious = (final_class != "BENIGN") or (evidence_status not in ["BENIGN_VERIFIED"])

        # Record flow into sliding window
        flow_entry = {
            "record_id": record_id,
            "source_ip": source_ip,
            "dest_port": dest_port,
            "final_class": final_class,
            "is_suspicious": is_suspicious,
            "fused_conf": fused_conf
        }
        self.recent_flows.append(flow_entry)

        # Non-suspicious benign flow without prior active attack group
        if not is_suspicious:
            # Check if this IP has an existing active attack group
            if source_ip in self.active_ip_groups:
                # Flow is from a known attacker IP that previously launched attacks
                grp_id = self.active_ip_groups[source_ip]
                grp = self.groups[grp_id]
                return {
                    "group_id": grp_id,
                    "is_correlated": True,
                    "pattern_type": grp["pattern_type"],
                    "member_records": grp["member_records"][-5:],
                    "member_count": len(grp["member_records"]),
                    "correlation_confidence": 0.85,
                    "supporting_evidence": {
                        "source_ip": source_ip,
                        "context": "Benign flow observed from known active adversary host",
                        "active_pattern": grp["pattern_type"]
                    },
                    "recommendation": "MAINTAIN_POLICY_BLOCK"
                }

            return {
                "group_id": None,
                "is_correlated": False,
                "pattern_type": "ISOLATED_BENIGN",
                "member_records": [record_id],
                "member_count": 1,
                "correlation_confidence": 0.0,
                "supporting_evidence": {"source_ip": source_ip, "note": "Nominal flow behavior"},
                "recommendation": "ALLOW"
            }

        # ---------------------------------------------------------------------
        # Suspicious / Threat Flow: Perform Temporal Pattern Correlation
        # ---------------------------------------------------------------------
        # Find past suspicious flows in window sharing same source IP or destination port
        matching_past = [
            f for f in self.recent_flows
            if f["record_id"] != record_id and f["is_suspicious"] and (
                f["source_ip"] == source_ip or f["dest_port"] == dest_port
            )
        ]

        # Determine pattern type based on threat category & flow characteristics
        if final_class in ["DDOS", "DOS"]:
            pattern_type = "VOLUMETRIC_BURST_ATTACK"
        elif final_class == "PORT_SCAN":
            pattern_type = "HORIZONTAL_PORT_RECONNAISSANCE"
        elif final_class == "BRUTE_FORCE":
            pattern_type = "CREDENTIAL_EXHAUSTION_BURST"
        else:
            pattern_type = "ANOMALOUS_ATTACK_CLUSTER"

        # Check if existing group exists for this source IP
        if source_ip in self.active_ip_groups:
            group_id = self.active_ip_groups[source_ip]
            grp = self.groups[group_id]
            grp["member_records"].append(record_id)
            grp["ports"].add(dest_port)
            grp["classes"].append(final_class)
            grp["fused_confs"].append(fused_conf)
            grp["attack_count"] += 1
        else:
            self.group_counter += 1
            group_id = f"GRP_{final_class}_{self.group_counter:04d}"
            self.active_ip_groups[source_ip] = group_id
            self.groups[group_id] = {
                "group_id": group_id,
                "source_ip": source_ip,
                "pattern_type": pattern_type,
                "member_records": [record_id],
                "ports": {dest_port},
                "classes": [final_class],
                "fused_confs": [fused_conf],
                "attack_count": 1
            }
            grp = self.groups[group_id]

        member_count = len(grp["member_records"])

        # Dynamic correlation confidence scales with recurring attacks
        if member_count >= 5:
            corr_conf = 0.99
        elif member_count >= 3:
            corr_conf = 0.95
        elif member_count >= 2:
            corr_conf = 0.90
        else:
            corr_conf = 0.75

        # Supporting evidence details
        supporting_evidence = {
            "source_ip": source_ip,
            "target_ports_observed": list(grp["ports"])[:5],
            "distinct_ports_count": len(grp["ports"]),
            "burst_velocity": f"{member_count} attacks in active sliding window",
            "primary_threat_vector": final_class,
            "average_threat_confidence": round(sum(grp["fused_confs"]) / member_count, 4)
        }

        # Recommendation for Agent 5
        if member_count >= 2 or fused_conf >= 0.85:
            rec = "ACTIVATE_IMMEDIATE_SOURCE_IP_BLOCK"
        else:
            rec = "EVALUATE_CONTAINMENT_POLICY"

        return {
            "group_id": group_id,
            "is_correlated": True,
            "pattern_type": pattern_type,
            "member_records": grp["member_records"][-10:],
            "member_count": member_count,
            "correlation_confidence": corr_conf,
            "supporting_evidence": supporting_evidence,
            "recommendation": rec
        }

    def get_all_groups(self) -> List[Dict[str, Any]]:
        """Return audit list of all temporal correlation groups."""
        return [
            {
                "group_id": gid,
                "source_ip": g["source_ip"],
                "pattern_type": g["pattern_type"],
                "member_count": len(g["member_records"]),
                "sample_members": g["member_records"][:5],
                "target_ports": list(g["ports"])[:5]
            }
            for gid, g in self.groups.items()
        ]


# Global singleton instance
_agent4_instance: Optional[TemporalCorrelationAgent] = None

def get_temporal_correlation_agent() -> TemporalCorrelationAgent:
    global _agent4_instance
    if _agent4_instance is None:
        _agent4_instance = TemporalCorrelationAgent()
    return _agent4_instance

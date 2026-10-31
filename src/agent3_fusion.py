"""
CyberSentinel: Multi-Agent Network Intrusion Detection & Adaptive Defense
Agent 3: Evidence Fusion Agent (src/agent3_fusion.py)
JAYPEE AGENTIC AI INTERNATIONAL SUMMIT 2026 - TRACK 1

Requirements:
- Combines Agent 1 (Threat Detection) and Agent 2 (Anomaly Detection).
- Handles agreement and disagreement scenarios.
- Demonstrable outputs: final_class, evidence_status, explainable rationale, and simulated policy (ALLOW/BLOCK/TARPIT).
"""

from typing import Dict, Any, Optional

BENCHMARK_CLASSES = ["BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"]

class EvidenceFusionAgent:
    """
    Agent 3: Evidence Fusion Agent
    Synthesizes multi-agent telemetry:
    - Agent 1: Supervised Threat Detection (predicted class, confidence, probabilities)
    - Agent 2: Unsupervised Anomaly Scoring (anomaly score, feature evidence)
    Resolves consensus vs disagreement and produces an explainable security decision.
    """

    def __init__(
        self,
        threat_confidence_threshold: float = 0.60,
        anomaly_threshold: float = 0.50,
        escalation_threshold: float = 0.68
    ):
        self.threat_threshold = threat_confidence_threshold
        self.anomaly_threshold = anomaly_threshold
        self.escalation_threshold = escalation_threshold

    def fuse_evidence(
        self,
        threat_result: Dict[str, Any],
        anomaly_result: Dict[str, Any],
        flow_features: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Synthesize Agent 1 and Agent 2 outputs.

        Args:
            threat_result: dict from Agent 1 (predicted_class, confidence, class_probabilities)
            anomaly_result: dict from Agent 2 (anomaly_score, is_anomaly, feature_evidence)
            flow_features: optional raw flow feature dict

        Returns:
            dict containing:
                - final_class: str (one of the 5 benchmark classes)
                - evidence_status: str (CONFIRMED_THREAT, BENIGN_VERIFIED, DISAGREEMENT_ESCALATION, etc.)
                - agreement: bool
                - policy: str (ALLOW, BLOCK, TARPIT, QUARANTINE)
                - confidence_score: float
                - rationale: str
                - supporting_evidence: list of key features
        """
        a1_class = threat_result.get("predicted_class", "BENIGN")
        a1_conf = float(threat_result.get("confidence", 0.5))
        a1_probs = threat_result.get("class_probabilities", {})

        a2_score = float(anomaly_result.get("anomaly_score", 0.0))
        a2_evidence = anomaly_result.get("feature_evidence", [])
        top_feats = [e["feature"] for e in a2_evidence[:2]] if a2_evidence else []
        feat_str = ", ".join(top_feats) if top_feats else "traffic rate variance"

        is_a1_attack = a1_class != "BENIGN"
        is_a2_anomalous = a2_score >= self.anomaly_threshold

        # ---------------------------------------------------------------------
        # Case 1: Strong Agreement on Attack
        # ---------------------------------------------------------------------
        if is_a1_attack and is_a2_anomalous:
            final_class = a1_class
            evidence_status = "CONFIRMED_THREAT"
            agreement = True
            policy = "BLOCK"
            if final_class in ["DOS", "DDOS"]:
                policy = "TARPIT"
            elif final_class == "BRUTE_FORCE":
                policy = "QUARANTINE"

            rationale = (
                f"Multi-Agent Consensus: Agent 1 classified hostile {a1_class} with {a1_conf*100:.1f}% confidence. "
                f"Agent 2 independently corroborated anomalous divergence (score: {a2_score:.2f}) driven by {feat_str}."
            )

        # ---------------------------------------------------------------------
        # Case 2: Strong Agreement on Benign
        # ---------------------------------------------------------------------
        elif not is_a1_attack and not is_a2_anomalous:
            final_class = "BENIGN"
            evidence_status = "BENIGN_VERIFIED"
            agreement = True
            policy = "ALLOW"
            rationale = (
                f"Multi-Agent Consensus: Agent 1 confirmed BENIGN profile ({a1_conf*100:.1f}%). "
                f"Agent 2 observed nominal baseline telemetry (anomaly score: {a2_score:.2f})."
            )

        # ---------------------------------------------------------------------
        # Case 3: Disagreement - A1 says Benign, but A2 detects Anomaly
        # Potential stealth probe, novel attack, or bursty nominal transfer
        # ---------------------------------------------------------------------
        elif not is_a1_attack and is_a2_anomalous:
            agreement = False
            attack_candidates = {k: v for k, v in a1_probs.items() if k != "BENIGN"}
            best_attack = max(attack_candidates.items(), key=lambda x: x[1])[0] if attack_candidates else "PORT_SCAN"
            best_attack_prob = attack_candidates.get(best_attack, 0.0)

            # Only escalate class label if Agent 1 has low confidence in BENIGN AND significant attack runner-up probability
            if a2_score >= self.escalation_threshold and a1_conf < 0.70 and best_attack_prob >= 0.25:
                final_class = best_attack
                evidence_status = "DISAGREEMENT_ANOMALY_ESCALATION"
                policy = "TARPIT"
                rationale = (
                    f"Disagreement Escalation: Agent 1 had low BENIGN confidence ({a1_conf*100:.1f}%), and Agent 2 flagged severe "
                    f"statistical anomaly (score: {a2_score:.2f}) in {feat_str}. Escalated to {final_class} with runner-up prob {best_attack_prob*100:.1f}%."
                )
            else:
                # Retain BENIGN classification to preserve high precision, while logging suspicious anomaly evidence
                final_class = "BENIGN"
                evidence_status = "DISAGREEMENT_ANOMALY_ESCALATION" if a2_score >= self.escalation_threshold else "SUSPICIOUS_MONITOR"
                policy = "ALLOW_INSPECT"
                rationale = (
                    f"Disagreement Monitored: Agent 1 classified BENIGN ({a1_conf*100:.1f}%), but Agent 2 observed statistical anomaly "
                    f"(score: {a2_score:.2f}) driven by {feat_str}. Preserved BENIGN with active session monitoring."
                )

        # ---------------------------------------------------------------------
        # Case 4: Disagreement - A1 flags Attack, but A2 sees Normal Baseline
        # ---------------------------------------------------------------------
        else:
            agreement = False
            # High-confidence attack signatures override generic statistical baseline
            if a1_conf >= 0.85:
                final_class = a1_class
                evidence_status = "TARGETED_SIGNATURE_MATCH"
                policy = "BLOCK"
                rationale = (
                    f"Targeted Threat Override: Agent 1 matched specific attack signature for {a1_class} with high confidence "
                    f"({a1_conf*100:.1f}%), despite subtle statistical footprint reported by Agent 2 (score: {a2_score:.2f})."
                )
            else:
                # Moderate/low confidence threat with normal baseline -> potential false alarm
                final_class = a1_class
                evidence_status = "PROBATIONARY_CONTAINMENT"
                policy = "TARPIT"
                rationale = (
                    f"Disagreement Review: Agent 1 flagged {a1_class} with moderate confidence ({a1_conf*100:.1f}%), but Agent 2 "
                    f"recorded nominal flow metrics ({a2_score:.2f}). Applied precautionary tarpit."
                )

        # Unified fused confidence metric
        fused_confidence = round(
            a1_conf * 0.70 + (a2_score if is_a1_attack else (1.0 - a2_score)) * 0.30, 4
        )

        return {
            "final_class": final_class,
            "evidence_status": evidence_status,
            "agreement": agreement,
            "policy": policy,
            "fused_confidence": fused_confidence,
            "threat_agent": {
                "predicted_class": a1_class,
                "confidence": a1_conf
            },
            "anomaly_agent": {
                "anomaly_score": a2_score,
                "is_anomaly": is_a2_anomalous,
                "top_evidence": a2_evidence[:3]
            },
            "rationale": rationale
        }


# Global singleton instance
_fusion_agent_instance: Optional[EvidenceFusionAgent] = None

def get_fusion_agent() -> EvidenceFusionAgent:
    global _fusion_agent_instance
    if _fusion_agent_instance is None:
        _fusion_agent_instance = EvidenceFusionAgent()
    return _fusion_agent_instance

def fuse_evidence(
    threat_result: Dict[str, Any],
    anomaly_result: Dict[str, Any],
    flow_features: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Convenience helper for Agent 3 fusion."""
    agent = get_fusion_agent()
    return agent.fuse_evidence(threat_result, anomaly_result, flow_features)


"""
CyberSentinel: Multi-Agent Network Intrusion Detection & Adaptive Defense
Agent 5: Adaptive Defense Agent (src/agent5_adaptive_defense.py)
JAYPEE AGENTIC AI INTERNATIONAL SUMMIT 2026 - TRACK 1 (DAY 2 // LEVEL 2)

Requirements:
- Enforces active defense policies BEFORE analyzing newly allowed flows.
- Activates temporary simulated ALLOW/BLOCK policies based on A3 fusion + A4 correlation.
- Only later matching flows are BLOCKED.
- Generates policy activation, scope, and expiry logs complying with official submission schema.
"""

from typing import Dict, Any, List, Optional, Tuple


class AdaptiveDefenseAgent:
    """
    Agent 5: Adaptive Defense Agent
    Maintains simulated runtime firewall / proxy policies:
    - Evaluates pre-inspection policy matches before any flow analysis.
    - Activates scoped SOURCE_IP policies after a confirmed triggering attack flow.
    - Manages deterministic expiration windows.
    """

    def __init__(self, default_duration_records: int = 250):
        self.default_duration_records = default_duration_records
        self.policy_counter = 0

        # Registry of all generated policies (for policy.csv)
        self.all_policies: List[Dict[str, Any]] = []

        # Currently active policies: mapping policy_id -> policy dict
        self.active_policies: Dict[str, Dict[str, Any]] = {}

        # Fast lookup mapping: source_ip -> policy_id for active policies
        self.active_ip_to_policy: Dict[str, str] = {}

        # Log of all replay decisions (for replay.csv)
        self.replay_decisions: List[Dict[str, Any]] = []

        # Statistics
        self.stats = {
            "total_evaluated": 0,
            "total_allowed": 0,
            "total_blocked": 0,
            "policies_created": 0,
            "policies_expired": 0,
        }

    def reset(self):
        """Reset state for a fresh replay evaluation run."""
        self.policy_counter = 0
        self.all_policies.clear()
        self.active_policies.clear()
        self.active_ip_to_policy.clear()
        self.replay_decisions.clear()
        for k in self.stats:
            self.stats[k] = 0

    def check_pre_inspection_policy(
        self,
        record_id: str,
        source_ip: str,
        current_index: int
    ) -> Tuple[str, str]:
        """
        Step 1 of Replay Rule: Apply already-active defense policies BEFORE analyzing newly allowed flow.

        Returns:
            Tuple of (action, applied_policy_id)
            - action: "BLOCK" or "ALLOW"
            - applied_policy_id: policy_id if BLOCK, or "" if ALLOW
        """
        # Expire any outdated policies whose expiration record has passed
        self._expire_policies(current_index)

        # Check if an active policy covers this source_ip
        if source_ip in self.active_ip_to_policy:
            policy_id = self.active_ip_to_policy[source_ip]
            pol = self.active_policies.get(policy_id)
            if pol and pol["activated_after_index"] < current_index:
                # Flow is blocked by already-active policy!
                self.stats["total_blocked"] += 1
                self.stats["total_evaluated"] += 1
                return ("BLOCK", policy_id)

        # No active policy matched -> Flow is ALLOWED into inspection pipeline
        self.stats["total_allowed"] += 1
        self.stats["total_evaluated"] += 1
        return ("ALLOW", "")

    def process_allowed_flow(
        self,
        record_id: str,
        source_ip: str,
        current_index: int,
        fused_result: Dict[str, Any],
        correlation_result: Dict[str, Any],
        all_record_ids: List[str]
    ) -> Optional[Dict[str, Any]]:
        """
        Step 2 of Replay Rule: If flow was ALLOWED, analyze it and possibly activate
        a temporary policy for LATER records.

        Args:
            record_id: current record_id
            source_ip: current source IP
            current_index: 0-indexed position in replay sequence
            fused_result: output from Agent 3
            correlation_result: output from Agent 4
            all_record_ids: full list of record IDs in replay order (to calculate future expiry ID)

        Returns:
            Newly created policy dict, or None if no policy created.
        """
        final_class = fused_result.get("final_class", "BENIGN")
        fused_conf = fused_result.get("fused_confidence", 0.5)
        corr_count = correlation_result.get("member_count", 1)

        # Decision rule: High-precision policy activation to preserve benign traffic
        # Requires high threat confidence (>= 0.85) or verified multi-flow attack correlation
        should_block = (
            (final_class != "BENIGN") and
            (fused_conf >= 0.85 or (corr_count >= 2 and fused_conf >= 0.75))
        )

        if not should_block:
            return None

        # Do not duplicate policy if source_ip already has an active policy
        if source_ip in self.active_ip_to_policy:
            return None

        # Determine adaptive duration based on attack category
        if final_class in ["DDOS", "DOS"]:
            duration = 350
        elif final_class == "PORT_SCAN":
            duration = 200
        elif final_class == "BRUTE_FORCE":
            duration = 300
        else:
            duration = self.default_duration_records

        expiry_index = min(len(all_record_ids) - 1, current_index + duration)
        expires_after_record_id = all_record_ids[expiry_index]

        self.policy_counter += 1
        policy_id = f"POL_{self.policy_counter:05d}"

        new_policy = {
            "policy_id": policy_id,
            "activated_after_record_id": record_id,
            "activated_after_index": current_index,
            "scope_type": "SOURCE_IP",
            "scope_value": source_ip,
            "expires_after_record_id": expires_after_record_id,
            "expires_after_index": expiry_index,
            "policy_action": "BLOCK",
            "triggering_class": final_class,
            "triggering_confidence": fused_conf,
            "correlation_group": correlation_result.get("group_id")
        }

        # Register policy
        self.all_policies.append(new_policy)
        self.active_policies[policy_id] = new_policy
        self.active_ip_to_policy[source_ip] = policy_id
        self.stats["policies_created"] += 1

        return new_policy

    def record_replay_step(self, record_id: str, action: str, applied_policy_id: str):
        """Record the replay action for replay.csv."""
        self.replay_decisions.append({
            "record_id": record_id,
            "action": action,
            "applied_policy_id": applied_policy_id if action == "BLOCK" else ""
        })

    def _expire_policies(self, current_index: int):
        """Expire policies whose expiration index has been reached."""
        to_expire = []
        for pid, pol in self.active_policies.items():
            if current_index > pol["expires_after_index"]:
                to_expire.append(pid)

        for pid in to_expire:
            pol = self.active_policies.pop(pid)
            ip = pol["scope_value"]
            if self.active_ip_to_policy.get(ip) == pid:
                del self.active_ip_to_policy[ip]
            self.stats["policies_expired"] += 1

    def get_policy_dataframe_records(self) -> List[Dict[str, Any]]:
        """
        Return records formatted exactly for policy.csv:
        Columns: policy_id, activated_after_record_id, scope_type, scope_value, expires_after_record_id, policy_action
        """
        return [
            {
                "policy_id": p["policy_id"],
                "activated_after_record_id": p["activated_after_record_id"],
                "scope_type": p["scope_type"],
                "scope_value": p["scope_value"],
                "expires_after_record_id": p["expires_after_record_id"],
                "policy_action": p["policy_action"]
            }
            for p in self.all_policies
        ]

    def get_replay_dataframe_records(self) -> List[Dict[str, Any]]:
        """
        Return records formatted exactly for replay.csv:
        Columns: record_id, action, applied_policy_id
        """
        return self.replay_decisions


# Global singleton instance
_agent5_instance: Optional[AdaptiveDefenseAgent] = None

def get_adaptive_defense_agent() -> AdaptiveDefenseAgent:
    global _agent5_instance
    if _agent5_instance is None:
        _agent5_instance = AdaptiveDefenseAgent()
    return _agent5_instance

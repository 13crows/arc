import re
import yaml
from typing import Dict, Any, List, Optional

class PolicyEngine:
    def __init__(self, config_path: str = "config/compliance_policy.yaml"):
        self.config_path = config_path
        self.policy = self._load_policy()
        self.rules = self.policy.get("policy_rules", [])
        self.mappings = self.policy.get("regulatory_mappings", {})

    def _load_policy(self) -> Dict[str, Any]:
        """Parses the YAML compliance policy safety configuration."""
        with open(self.config_path, 'r') as file:
            return yaml.safe_load(file)

    def evaluate(self, action_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates a normalized action against the active regulatory policy rules.
        
        Args:
            action_context: Dict containing:
                - resource_type: 'database', 'external_api', 'financial_api'
                - action: 'DELETE', 'TRANSFER', 'POST', etc.
                - value: Optional float/int numerical values (e.g., transaction amount)
                - data: Optional string payload being evaluated (e.g., generated prompt response)
        """
        resource_type = action_context.get("resource_type")
        action = action_context.get("action")
        value = action_context.get("value", 0.0)
        data = action_context.get("data", "")

        # Find the matching rule block for the resource type
        rule = next((r for r in self.rules if r["resource_type"] == resource_type), None)
        
        if not rule:
            return {"decision": "ALLOW", "rule_id": None, "reason": "No policy rule defined for this resource type."}

        # 1. Evaluate Explicit Denied Actions (e.g., Rule 01 Database Safety)
        if "denied_actions" in rule and action in rule["denied_actions"]:
            return self._build_violation(rule, "unauthorized_action", f"Action '{action}' is explicitly banned on resource '{resource_type}'.")

        # 2. Evaluate Maximum Value Limits (e.g., Rule 03 Financial Threshold)
        if "max_value_limit" in rule and value > rule["max_value_limit"]:
            return self._build_violation(rule, "unauthorized_action", f"Value {value} exceeds the maximum allowable limit of {rule['max_value_limit']}.")

        # 3. Evaluate Blocked Patterns / PII Leakage (e.g., Rule 02 PII Exfiltration)
        if "blocked_patterns" in rule and data:
            for pattern in rule["blocked_patterns"]:
                if re.search(pattern, str(data)):
                    return self._build_violation(rule, "data_leakage", "Sensitive data pattern matching prohibited expression detected.")

        return {
            "decision": "ALLOW",
            "rule_id": rule["id"],
            "reason": "Action successfully verified against policy boundaries."
        }

    def _build_violation(self, rule: Dict[str, Any], violation_type: str, reason: str) -> Dict[str, Any]:
        """Maps a technical rule failure to its corresponding regulatory frameworks."""
        mapping = self.mappings.get(violation_type, {})
        return {
            "decision": rule["fallback_strategy"],  # e.g., BLOCK_AND_ALERT, REDACT_AND_PROCEED
            "rule_id": rule["id"],
            "severity": rule["severity"],
            "reason": reason,
            "compliance_impact": {
                "nist_id": mapping.get("nist_id", "Unknown"),
                "eu_ai_act_id": mapping.get("eu_ai_act_id", "Unknown")
            }
        }
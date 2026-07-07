import json
from typing import Dict, Any, List
from gateway.core import BasePolicyEnforcementPoint
from gateway.engine import PolicyEngine
from gateway.ledger import ComplianceLedger

class LangGraphComplianceProxy(BasePolicyEnforcementPoint):
    def __init__(self):
        """
        Initializes the proxy by instantiating the Policy Engine (for rules)
        and the Compliance Ledger (for cryptographic logging).
        """
        self.engine = PolicyEngine()
        self.ledger = ComplianceLedger()

    def intercept_action(self, tool_call: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translates a LangGraph tool_call dictionary into the normalized
        format required by our PolicyEngine.
        
        Assumes LangGraph tool_call format:
        { "name": "query_database", "args": {"query": "DROP TABLE users;"} }
        """
        tool_name = tool_call.get("name", "")
        args = tool_call.get("args", {})

        # --- Normalization Logic ---
        # Map specific LangGraph tools to our YAML Resource Types
        resource_type = "unknown"
        action = "UNKNOWN"
        value = 0.0
        data = json.dumps(args) # stringify args for PII regex scanning

        if "database" in tool_name or "sql" in tool_name:
            resource_type = "database"
            # Basic SQL action extraction for demonstration
            if "select" in data.lower(): action = "SELECT"
            if "delete" in data.lower() or "drop" in data.lower(): action = "DELETE"
            if "update" in data.lower(): action = "UPDATE"
            
        elif "api" in tool_name or "request" in tool_name:
            resource_type = "external_api"
            action = "POST"
            
        elif "transfer" in tool_name or "finance" in tool_name:
            resource_type = "financial_api"
            action = "TRANSFER"
            value = float(args.get("amount", 0.0))

        return {
            "raw_tool": tool_name,
            "resource_type": resource_type,
            "action": action,
            "value": value,
            "data": data
        }

    def enforce(self, tool_call: Dict[str, Any]) -> Dict[str, Any]:
        """
        The main execution loop. Intercepts the LangGraph tool call, 
        evaluates it, logs it, and returns the modified state.
        """
        # 1. Normalize the LangGraph specific context
        normalized_context = self.intercept_action(tool_call)

        # 2. Evaluate against the YAML Policy Engine
        evaluation_result = self.engine.evaluate(normalized_context)

        # 3. Cryptographically append to the ledger (or Hashgraph later)
        self.ledger.record_action(normalized_context, evaluation_result)

        decision = evaluation_result.get("decision", "ALLOW")
        
        # 4. Construct the Graph state mutation
        if decision == "ALLOW":
            return {
                "status": "APPROVED",
                "message": "Action cleared by gateway."
            }
        else:
            # If blocked, we mutate the response so the tool does not execute,
            # feeding the compliance failure back to the agent's context.
            return {
                "status": "BLOCKED",
                "message": f"COMPLIANCE OVERRIDE: {evaluation_result['reason']}",
                "violation_details": evaluation_result
            }
import os
import json
import hash_utils # standard library hashlib
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional

##################
# A word on why this ledger exists:
#
#  By structuring our ledger to calculate standard SHA-256 hashes and maintain a parent_hash pointer
#  we have manually implemented a basic cryptographic chain. 
#  If we (or you) decide to migrate this to Hedera Hashgraph in the future, the pivot is simple:
#  1. You would import the hedera-sdk-python (or the new hedera-agent-kit-py).
#  2. Instead of appending the payload to a local .jsonl file 
#     you would take that exact same JSON payload and submit it as a message to the Hedera Consensus Service (HCS).
#  3. HCS would natively handle the timestamping, tamper-evident ordering, and consensus 
#    providing you with a universally verifiable audit trail without changing how the rest of your agentic proxy functions.

#################

class ComplianceLedger:
    def __init__(self, log_path: str = "reports/audit_ledger.jsonl"):
        self.log_path = log_path
        self._initialize_ledger()

    def _initialize_ledger(self) -> None:
        """Ensures the log file exists and initializes the directory structure."""
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        if not os.path.exists(self.log_path):
            with open(self.log_path, "w") as f:
                pass # Create empty file

    def _get_last_hash(self) -> str:
        """Reads the last line of the ledger to extract its cryptographic hash."""
        if not os.path.exists(self.log_path) or os.path.getsize(self.log_path) == 0:
            return "0" * 64 # Genesis block hash representation

        with open(self.log_path, "rb") as f:
            try:
                f.seek(-2, os.SEEK_END)
                while f.read(1) != b"\n":
                    f.seek(-2, os.SEEK_CUR)
            except OSError:
                f.seek(0) # File only has one line
                
            last_line = f.readline().decode("utf-8").strip()
            if not last_line:
                return "0" * 64
                
            try:
                last_entry = json.loads(last_line)
                return last_entry.get("parent_hash", "0" * 64)
            except json.JSONDecodeError:
                return "CORRUPTED_LEDGER_HASH"

    def _calculate_hash(self, data_block: Dict[str, Any]) -> str:
        """Computes SHA-256 hash of a deterministic JSON string payload."""
        serialized = json.dumps(data_block, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def record_action(self, action_context: Dict[str, Any], evaluation_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Cryptographically binds an agent action and gateway decision into the ledger.
        
        Args:
            action_context: Normalized metadata of what the agent tried to do.
            evaluation_result: Output decision and regulatory mapping from the PolicyEngine.
        """
        parent_hash = self._get_last_hash()
        
        # Build payload skeleton structured for compliance auditing
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_context": action_context,
            "gateway_evaluation": {
                "decision": evaluation_result.get("decision"),
                "rule_id": evaluation_result.get("rule_id"),
                "reason": evaluation_result.get("reason"),
                "severity": evaluation_result.get("severity", "INFO"),
                "compliance_impact": evaluation_result.get("compliance_impact", {})
            }
        }
        
        # Cryptographic link binding
        current_hash = self._calculate_hash(payload)
        
        ledger_entry = {
            "parent_hash": current_hash, # Acts as the pointer for the next entry
            "payload_hash": current_hash,
            "previous_record_hash": parent_hash,
            "record": payload
        }

        # Append to the structural JSONL audit file
        with open(self.log_path, "a") as f:
            f.write(json.dumps(ledger_entry) + "\n")

        return ledger_entry

    def verify_integrity(self) -> bool:
        """
        Scans the entire ledger sequentially, recalculating hashes to verify 
        that no records have been modified, deleted, or reordered.
        """
        if not os.path.exists(self.log_path) or os.path.getsize(self.log_path) == 0:
            return True

        expected_parent_hash = "0" * 64
        with open(self.log_path, "r") as f:
            for line_number, line in enumerate(f, 1):
                try:
                    entry = json.loads(line.strip())
                    record = entry["record"]
                    
                    # Recalculate hash of the payload data
                    calculated_hash = self._calculate_hash(record)
                    if entry["payload_hash"] != calculated_hash:
                        return False # Data was altered inside this line
                        
                    if entry["previous_record_hash"] != expected_parent_hash:
                        return False # Chain integrity broken or record deleted/inserted
                        
                    expected_parent_hash = entry["parent_hash"]
                except (json.JSONDecodeError, KeyError):
                    return False # Structural tampering detected
                    
        return True
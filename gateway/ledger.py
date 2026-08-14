import os
import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any

##################
# A word on why this ledger exists:
#
#  Airgapped and disconnected deployments cannot rely on an external notary or
#  cloud audit service. This ledger gives them a local, append-only record of
#  every agent action and gateway decision, hashed into a tamper-evident chain.
#
#  Each entry stores H(previous_record_hash + record). Because every hash folds
#  in the one before it, editing, deleting, or reordering any record breaks the
#  chain from that point forward. An operator only needs to anchor the final
#  record_hash (print it, sign it, or read it into a separate log) to later
#  detect any change to the entire history.
#
#  If a decision is made to migrate to Hedera Hashgraph in the future the pivot
#  is simple: import the hedera-sdk-python, and instead of appending the payload
#  to a local .jsonl file, submit the exact same JSON payload as a message to the
#  Hedera Consensus Service (HCS), which natively handles timestamping,
#  tamper-evident ordering, and consensus without changing the rest of the proxy.
#################

GENESIS_HASH = "0" * 64


class ComplianceLedger:
    def __init__(self, log_path: str = "reports/audit_ledger.jsonl"):
        self.log_path = log_path
        self._initialize_ledger()

    def _initialize_ledger(self) -> None:
        """Ensures the log file exists and initializes the directory structure."""
        directory = os.path.dirname(self.log_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        if not os.path.exists(self.log_path):
            with open(self.log_path, "w"):
                pass  # Create empty file

    def _get_last_hash(self) -> str:
        """Reads the last line of the ledger to extract its chained record hash."""
        if not os.path.exists(self.log_path) or os.path.getsize(self.log_path) == 0:
            return GENESIS_HASH

        with open(self.log_path, "rb") as f:
            try:
                f.seek(-2, os.SEEK_END)
                while f.read(1) != b"\n":
                    f.seek(-2, os.SEEK_CUR)
            except OSError:
                f.seek(0)  # File only has one line

            last_line = f.readline().decode("utf-8").strip()
            if not last_line:
                return GENESIS_HASH

            try:
                last_entry = json.loads(last_line)
                return last_entry.get("record_hash", GENESIS_HASH)
            except json.JSONDecodeError:
                return "CORRUPTED_LEDGER_HASH"

    def _chain_hash(self, previous_record_hash: str, record: Dict[str, Any]) -> str:
        """
        Computes the chained SHA-256 hash for a record.

        The previous record's hash is folded into the digest, so every entry is
        cryptographically bound to the one before it. This is what makes the log
        tamper-evident rather than a set of independent per-record hashes.
        """
        material = json.dumps(
            {"previous_record_hash": previous_record_hash, "record": record},
            sort_keys=True,
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def record_action(
        self, action_context: Dict[str, Any], evaluation_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Binds an agent action and gateway decision into the tamper-evident ledger.

        Args:
            action_context: Normalized metadata of what the agent tried to do.
            evaluation_result: Output decision and regulatory mapping from the PolicyEngine.
        """
        previous_record_hash = self._get_last_hash()

        # Build payload skeleton structured for compliance auditing
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_context": action_context,
            "gateway_evaluation": {
                "decision": evaluation_result.get("decision"),
                "rule_id": evaluation_result.get("rule_id"),
                "reason": evaluation_result.get("reason"),
                "severity": evaluation_result.get("severity", "INFO"),
                "compliance_impact": evaluation_result.get("compliance_impact", {}),
            },
        }

        record_hash = self._chain_hash(previous_record_hash, record)

        ledger_entry = {
            "previous_record_hash": previous_record_hash,
            "record_hash": record_hash,
            "record": record,
        }

        with open(self.log_path, "a") as f:
            f.write(json.dumps(ledger_entry) + "\n")

        return ledger_entry

    def verify_integrity(self) -> bool:
        """
        Scans the entire ledger sequentially, recomputing each chained hash to
        verify that no records have been modified, deleted, or reordered.
        """
        if not os.path.exists(self.log_path) or os.path.getsize(self.log_path) == 0:
            return True

        expected_previous_hash = GENESIS_HASH
        with open(self.log_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    record = entry["record"]
                    previous_record_hash = entry["previous_record_hash"]

                    # The stored previous pointer must match the running chain.
                    if previous_record_hash != expected_previous_hash:
                        return False  # Record deleted, inserted, or reordered

                    # Recompute the chained hash and compare.
                    recomputed = self._chain_hash(previous_record_hash, record)
                    if entry["record_hash"] != recomputed:
                        return False  # Data was altered inside this line

                    expected_previous_hash = entry["record_hash"]
                except (json.JSONDecodeError, KeyError):
                    return False  # Structural tampering detected

        return True

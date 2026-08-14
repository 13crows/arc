"""
Unit tests for the compliance gateway: policy engine, LangGraph interceptor,
and the tamper-evident ledger.

Run from the repo root:

    pytest -v
"""
import json

import pytest

from conftest import POLICY_CONFIG_PATH
from gateway.engine import PolicyEngine
from gateway.ledger import ComplianceLedger, GENESIS_HASH
from gateway.interceptors.langgraph_proxy import LangGraphComplianceProxy


# --------------------------------------------------------------------------- #
# PolicyEngine
# --------------------------------------------------------------------------- #
@pytest.fixture
def engine():
    return PolicyEngine(config_path=POLICY_CONFIG_PATH)


def test_engine_allows_safe_read(engine):
    result = engine.evaluate(
        {"resource_type": "database", "action": "SELECT", "data": ""}
    )
    assert result["decision"] == "ALLOW"
    assert result["rule_id"] == "rule_01_database_safety"


def test_engine_blocks_destructive_database_action(engine):
    result = engine.evaluate(
        {"resource_type": "database", "action": "DELETE", "data": ""}
    )
    assert result["decision"] == "BLOCK_AND_ALERT"
    assert result["severity"] == "CRITICAL"
    assert "NIST" in result["compliance_impact"]["nist_id"]


def test_engine_enforces_financial_threshold(engine):
    over = engine.evaluate(
        {"resource_type": "financial_api", "action": "TRANSFER", "value": 25000.0}
    )
    assert over["decision"] == "FORCE_HUMAN_APPROVAL"

    under = engine.evaluate(
        {"resource_type": "financial_api", "action": "TRANSFER", "value": 100.0}
    )
    assert under["decision"] == "ALLOW"


def test_engine_flags_pii_pattern(engine):
    result = engine.evaluate(
        {
            "resource_type": "external_api",
            "action": "POST",
            "data": "user ssn is being sent",
        }
    )
    assert result["decision"] == "REDACT_AND_PROCEED"


def test_engine_defaults_to_allow_for_unknown_resource(engine):
    result = engine.evaluate({"resource_type": "carrier_pigeon", "action": "SEND"})
    assert result["decision"] == "ALLOW"
    assert result["rule_id"] is None


# --------------------------------------------------------------------------- #
# LangGraph interceptor / proxy
# --------------------------------------------------------------------------- #
@pytest.fixture
def proxy(tmp_path):
    """A proxy whose engine uses the real policy and whose ledger is isolated.

    Built via __new__ so the test does not depend on the current working
    directory (the default constructor resolves config/ledger paths relatively).
    """
    p = LangGraphComplianceProxy.__new__(LangGraphComplianceProxy)
    p.engine = PolicyEngine(config_path=POLICY_CONFIG_PATH)
    p.ledger = ComplianceLedger(log_path=str(tmp_path / "ledger.jsonl"))
    return p


def test_interceptor_normalizes_destructive_sql():
    interceptor = LangGraphComplianceProxy()
    normalized = interceptor.intercept_action(
        {"name": "query_database", "args": {"query": "DROP TABLE users;"}}
    )
    assert normalized["resource_type"] == "database"
    assert normalized["action"] == "DELETE"


def test_interceptor_parses_transfer_amount():
    interceptor = LangGraphComplianceProxy()
    normalized = interceptor.intercept_action(
        {"name": "execute_financial_transfer", "args": {"amount": 9000.0}}
    )
    assert normalized["resource_type"] == "financial_api"
    assert normalized["value"] == 9000.0


def test_proxy_approves_safe_action(proxy):
    result = proxy.enforce(
        {"name": "query_database", "args": {"query": "SELECT * FROM users;"}}
    )
    assert result["status"] == "APPROVED"


def test_proxy_blocks_and_records_violation(proxy):
    result = proxy.enforce(
        {"name": "query_database", "args": {"query": "DROP TABLE users;"}}
    )
    assert result["status"] == "BLOCKED"
    assert "violation_details" in result
    # The action must have been written to the ledger.
    assert proxy.ledger.verify_integrity() is True


# --------------------------------------------------------------------------- #
# Tamper-evident ledger
# --------------------------------------------------------------------------- #
@pytest.fixture
def ledger(tmp_path):
    return ComplianceLedger(log_path=str(tmp_path / "audit.jsonl"))


def _write_three(ledger):
    ledger.record_action(
        {"resource_type": "database", "action": "SELECT"}, {"decision": "ALLOW"}
    )
    ledger.record_action(
        {"resource_type": "database", "action": "DELETE"},
        {"decision": "BLOCK_AND_ALERT", "severity": "CRITICAL"},
    )
    ledger.record_action(
        {"resource_type": "financial_api", "action": "TRANSFER", "value": 25000.0},
        {"decision": "FORCE_HUMAN_APPROVAL", "severity": "CRITICAL"},
    )


def test_empty_ledger_is_valid(ledger):
    assert ledger.verify_integrity() is True


def test_chain_links_to_previous_record(ledger):
    first = ledger.record_action({"action": "A"}, {"decision": "ALLOW"})
    second = ledger.record_action({"action": "B"}, {"decision": "ALLOW"})
    assert first["previous_record_hash"] == GENESIS_HASH
    # Second entry must point at the first entry's hash: a real chain, not
    # independent per-record hashes.
    assert second["previous_record_hash"] == first["record_hash"]


def test_clean_ledger_verifies(ledger):
    _write_three(ledger)
    assert ledger.verify_integrity() is True


def test_detects_modified_record(ledger):
    _write_three(ledger)
    lines = _read_lines(ledger.log_path)
    entry = json.loads(lines[1])
    entry["record"]["gateway_evaluation"] = {"decision": "ALLOW"}  # forge a block into an allow
    lines[1] = json.dumps(entry)
    _write_lines(ledger.log_path, lines)
    assert ledger.verify_integrity() is False


def test_detects_deleted_record(ledger):
    _write_three(ledger)
    lines = _read_lines(ledger.log_path)
    del lines[1]  # remove a record from the middle
    _write_lines(ledger.log_path, lines)
    assert ledger.verify_integrity() is False


def test_detects_reordered_records(ledger):
    _write_three(ledger)
    lines = _read_lines(ledger.log_path)
    lines[0], lines[1] = lines[1], lines[0]
    _write_lines(ledger.log_path, lines)
    assert ledger.verify_integrity() is False


def _read_lines(path):
    with open(path, "r") as f:
        return [ln for ln in f.read().splitlines() if ln.strip()]


def _write_lines(path, lines):
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")

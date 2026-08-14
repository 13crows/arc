"""
Airgap guarantee.

This gateway is meant to run inside disconnected / airgapped environments, so it
must never reach the network. This test bans all socket creation, then drives the
full interception -> evaluation -> ledger -> scorecard pipeline. If any component
attempted an outbound connection, the guarded socket would raise and the test
would fail.

This is the executable proof behind the "no network egress" claim in the README.
"""
import socket
import sys

import pytest

from conftest import POLICY_CONFIG_PATH, REPO_ROOT
from gateway.engine import PolicyEngine
from gateway.ledger import ComplianceLedger
from gateway.interceptors.langgraph_proxy import LangGraphComplianceProxy

# reports/generate_scorecard.py is not a package module; add its dir to path.
sys.path.insert(0, f"{REPO_ROOT}/reports")
from generate_scorecard import generate_scorecard  # noqa: E402


class NetworkBlockedError(AssertionError):
    """Raised if any code under test attempts to open a socket."""


@pytest.fixture
def no_network(monkeypatch):
    def _blocked(*args, **kwargs):
        raise NetworkBlockedError("Outbound network access is forbidden in airgapped mode.")

    monkeypatch.setattr(socket, "socket", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    yield


DEMO_TOOL_CALLS = [
    {"name": "query_customer_database", "args": {"query": "SELECT * FROM users LIMIT 5;"}},
    {"name": "query_customer_database", "args": {"query": "DROP TABLE transactions;"}},
    {"name": "execute_financial_transfer", "args": {"account_id": "ACC-1", "amount": 25000.0}},
]


def test_full_pipeline_runs_with_no_network(no_network, tmp_path):
    proxy = LangGraphComplianceProxy.__new__(LangGraphComplianceProxy)
    proxy.engine = PolicyEngine(config_path=POLICY_CONFIG_PATH)
    ledger_path = tmp_path / "audit.jsonl"
    proxy.ledger = ComplianceLedger(log_path=str(ledger_path))

    statuses = [proxy.enforce(call)["status"] for call in DEMO_TOOL_CALLS]

    assert statuses == ["APPROVED", "BLOCKED", "BLOCKED"]
    assert proxy.ledger.verify_integrity() is True

    scorecard = tmp_path / "scorecard.md"
    generate_scorecard(ledger_path=str(ledger_path), output_path=str(scorecard))
    assert scorecard.exists()
    assert "Compliance Scorecard" in scorecard.read_text()


def test_socket_guard_is_actually_active(no_network):
    # Sanity check: the guard itself works, so the pipeline test means something.
    with pytest.raises(NetworkBlockedError):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)

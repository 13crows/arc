# arc — Airgapped Runtime Compliance gateway for AI agents

A runtime interception layer that enforces deterministic policy boundaries around
probabilistic agents, and writes a tamper-evident audit trail — **with zero
network egress**, so it can run inside disconnected, on-prem, or airgapped
environments where cloud evaluation services are not an option.

Most agent guardrail and evaluation tooling assumes you can ship telemetry to a
SaaS backend. That is a non-starter for defense, intelligence, and regulated
deployments running local models and agents behind an airgap. `arc` is built for
that case: it sits in the tool-calling path, evaluates each action against a
local policy, and records the decision to a local hash-chained ledger. Nothing
leaves the box.

The airgap guarantee is not just a claim — it is enforced by a test
(`tests/test_no_egress.py`) that bans all socket creation and then runs the full
pipeline. See [Airgap guarantee](#airgap-guarantee) below.

---

## Architecture Overview

The design decouples the agent's reasoning loop from the execution environment,
placing a **Policy Enforcement Point (PEP)** directly in the tool-calling path.

1. **The Interceptor** — captures intended tool-calls (database queries, API
   requests, transfers) from frameworks like LangGraph and normalizes them.
2. **The Policy Engine** — evaluates the normalized action against a strict,
   YAML-defined policy schema.
3. **The Ledger** — commits the action, context, and gateway decision to a
   local, append-only, SHA-256 **hash-chained** audit log.
4. **The Scorecard** — aggregates the ledger into a Markdown compliance report
   and re-verifies the chain's integrity.

## Core Features

* **Runtime action governance** — evaluates unauthorized, hallucinated, or
  injected agent actions at the point of the tool-call, before they execute.
* **Offline by design** — no outbound network calls; suitable for airgapped and
  disconnected deployments. Enforced by an automated no-egress test.
* **Tamper-evident audit trail** — a local hash chain where each record folds in
  the hash of the previous one. Editing, deleting, or reordering any record
  breaks the chain from that point on. Anchor the final hash to detect any change
  to the entire history.
* **Framework-decoupled** — built on an abstract `BasePolicyEnforcementPoint`
  interface, with a concrete **LangGraph** interceptor as the first implementation.
* **Regulatory mapping** — maps rule violations to **NIST AI RMF** and the
  **EU AI Act** for reporting.
* **Executive reporting** — auto-generates a Markdown compliance scorecard.

---

## Quick Start

Requires Python 3.9+.

```bash
git clone https://github.com/13crows/arc.git
cd arc
pip install -r requirements.txt
```

### 1. Define your policy

Boundaries live in `config/compliance_policy.yaml`:

```yaml
policy_rules:
  - id: "rule_01_database_safety"
    resource_type: "database"
    allowed_actions: ["READ", "SELECT"]
    denied_actions: ["DELETE", "DROP", "UPDATE"]
    severity: "CRITICAL"
    fallback_strategy: "BLOCK_AND_ALERT"
```

### 2. Run the simulation

```bash
python main.py
```

This drives a set of simulated LangGraph tool-calls through the gateway and
verifies the ledger at the end.

### 3. Generate the scorecard

```bash
python reports/generate_scorecard.py
```

Output is written to `reports/compliance_scorecard.md`, and the report re-runs
integrity verification over the ledger.

### 4. Run the tests

```bash
pytest -v
```

---

## Airgap guarantee

The whole point of `arc` is that it runs where the network doesn't. That is
enforced, not assumed:

```bash
pytest -v tests/test_no_egress.py
```

This test replaces `socket.socket` / `socket.create_connection` with guards that
raise on any call, then runs interception, evaluation, ledger writes, integrity
verification, and scorecard generation. If any component attempted an outbound
connection, the test fails. CI runs it on every push (`.github/workflows/ci.yml`).

---

## Repository Structure

```text
arc/
├── config/
│   └── compliance_policy.yaml
├── gateway/
│   ├── core.py                 # BasePolicyEnforcementPoint (abstract PEP)
│   ├── engine.py               # YAML-driven PolicyEngine
│   ├── ledger.py               # tamper-evident hash-chained ledger
│   └── interceptors/
│       └── langgraph_proxy.py  # LangGraph tool-call interceptor
├── reports/
│   ├── generate_scorecard.py
│   └── audit_ledger.jsonl      # sample output
├── tests/
│   ├── test_gateway.py         # engine, interceptor, ledger tamper-detection
│   └── test_no_egress.py       # airgap guarantee
├── main.py                     # simulation entry point
└── requirements.txt
```

---

## Scope and roadmap

This is a working prototype demonstrating the architecture, not a finished
product. Known limitations, stated plainly:

* **Enforcement is currently binary.** `ALLOW` passes; every other decision is
  blocked and logged. The richer `fallback_strategy` values (`REDACT_AND_PROCEED`,
  `FORCE_HUMAN_APPROVAL`) are recorded in the ledger but not yet enforced
  differentially — that is the next piece of work.
* **Action normalization is demo-grade.** The LangGraph interceptor uses simple
  string matching to classify tool-calls; a production version needs structured
  parsing of the tool schema rather than substring heuristics.
* **The ledger is local and unsigned.** The hash chain makes tampering evident to
  anyone who holds the anchored final hash, but it does not by itself prevent a
  writer with full file access from regenerating the log. The commented migration
  path to Hedera Consensus Service in `gateway/ledger.py` addresses external,
  independent notarization.

Planned: differential fallback enforcement, schema-driven normalization,
signed/anchored ledger checkpoints, and additional framework interceptors
(AutoGen, MCP).

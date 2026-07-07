# Universal Agentic Compliance Gateway

An enterprise-grade, runtime interception proxy designed to enforce deterministic compliance boundaries around probabilistic multi-agent systems (MAS). 

This gateway acts as the authoritative control plane for AI Third-Party Risk Management (TPRM). It intercepts, evaluates, and cryptographically logs agent actions in real-time, ensuring autonomous systems operate strictly within defined regulatory frameworks (NIST AI RMF, EU AI Act).

---

## 🏛️ Architecture Overview

The architecture decouples the agent reasoning loop from the execution environment, placing a **Policy Enforcement Point (PEP)** directly in the tool-calling path.

1. **The Interceptor:** Captures intended tool-calls (e.g., database queries, API requests) from frameworks like LangGraph before they execute.
2. **The Policy Engine:** Evaluates the intercepted payload against a strict, YAML-defined compliance schema.
3. **The Ledger:** Commits the action, context, and gateway decision to a tamper-evident, SHA-256 chained cryptographic log.
4. **The Scorecard:** Asynchronously aggregates the ledger data into executive-ready risk scorecards mapped to global regulatory standards.

## ✨ Core Features

* **Real-Time Action Governance:** Blocks unauthorized, hallucinated, or injected agent actions at runtime.
* **Abstract Framework Proxy:** Built with a decoupled base interface (`BasePolicyEnforcementPoint`), currently implementing a concrete **LangGraph** interceptor.
* **Tamper-Evident Auditing:** Implements a localized cryptographic chain-of-custody, ensuring non-repudiation of agent behaviors.
* **Regulatory Mapping:** Automatically maps technical rule violations to **NIST AI RMF** and the **EU AI Act**.
* **Executive Reporting:** Auto-generates Markdown compliance scorecards.

---

## �� Quick Start

### 1. Installation

Clone the repository and install the required dependencies:

```bash
git clone https://github.com/YOUR_USERNAME/agentic-compliance-gateway.git
cd agentic-compliance-gateway
pip install -r requirements.txt
```

*(Note: Requires Python 3.9+)*

### 2. Configuration

Define your enterprise boundaries in `config/compliance_policy.yaml`:

```yaml
policy_rules:
  - id: "rule_01_database_safety"
    resource_type: "database"
    allowed_actions: ["READ", "SELECT"]
    denied_actions: ["DELETE", "DROP", "UPDATE"]
    severity: "CRITICAL"
    fallback_strategy: "BLOCK_AND_ALERT"
```

### 3. Execution

Run the main simulation loop:

```bash
python main.py
```

### 4. Audit Generation

Generate the executive compliance scorecard:

```bash
python reports/generate_scorecard.py
```
*The output will be saved to `reports/compliance_scorecard.md`.*

---

## 📂 Repository Structure

```text
agentic-compliance-gateway/
├── config/
│   └── compliance_policy.yaml     
├── gateway/
│   ├── core.py                    
│   ├── engine.py                  
│   ├── ledger.py                  
│   └── interceptors/
│       └── langgraph_proxy.py     
├── reports/
│   ├── generate_scorecard.py      
│   └── audit_ledger.jsonl         
├── main.py                        
└── requirements.txt
```

## 🛡️ Strategic Viability

As enterprises adopt the Model Context Protocol (MCP) and third-party agentic systems, static evaluation is insufficient. This gateway proves the ability to engineer stateful, dynamic, and autonomous safety boundaries for the next decade of enterprise AI deployment.
import json
from gateway.interceptors.langgraph_proxy import LangGraphComplianceProxy
from gateway.ledger import ComplianceLedger

def run_compliance_demo():
    print("=" * 60)
    print("INITIALIZING UNIVERSAL AGENTIC COMPLIANCE GATEWAY")
    print("=" * 60)
    
    # Instantiate our proxy layer
    proxy = LangGraphComplianceProxy()
    
    # Simulated Tool Calls from a Third-Party LangGraph Agent
    simulated_tool_calls = [
        {
            "id": "call_01",
            "name": "query_customer_database",
            "args": {"query": "SELECT * FROM users WHERE active = 1 LIMIT 5;"}
        },
        {
            "id": "call_02",
            "name": "query_customer_database",
            "args": {"query": "DROP TABLE transactions; DELETE FROM users;"}
        },
        {
            "id": "call_03",
            "name": "execute_financial_transfer",
            "args": {"account_id": "ACC-9921", "amount": 25000.00, "routing": "021000021"}
        }
    ]

    # Process each tool call through the interceptor loop
    for tool_call in simulated_tool_calls:
        print(f"\n[AGENT ACTION] Intercepting Tool: '{tool_call['name']}'")
        print(f"       Payload: {json.dumps(tool_call['args'])}")
        
        # Run enforcement
        result = proxy.enforce(tool_call)
        
        print(f"[GATEWAY STATUS] Resulting Signal -> {result['status']}")
        print(f"       Message: {result['message']}")
        
        if result['status'] == 'BLOCKED':
            impact = result['violation_details']['compliance_impact']
            print(f"       [CRITICAL] NIST Mapping: {impact['nist_id']}")
            print(f"       [CRITICAL] EU AI Act Mapping: {impact['eu_ai_act_id']}")
        print("-" * 60)

    # Validate ledger integrity
    print("\n[AUDIT PLANE] Verifying Cryptographic Ledger Integrity...")
    ledger = ComplianceLedger()
    if ledger.verify_integrity():
        print("SUCCESS: Ledger chain is cryptographically intact and tamper-free.")
    else:
        print("ALERT: Ledger tampering or corruption detected!")
    print("=" * 60)

if __name__ == "__main__":
    run_compliance_demo()
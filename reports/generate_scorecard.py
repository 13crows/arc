import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gateway.ledger import ComplianceLedger


def generate_scorecard(ledger_path="reports/audit_ledger.jsonl", output_path="reports/compliance_scorecard.md"):
    if not os.path.exists(ledger_path):
        print(f"Error: Ledger file not found at {ledger_path}")
        return

    total_requests = 0
    approved = 0
    blocked = 0
    violations = []

    # Parse the immutable ledger
    with open(ledger_path, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
                record = entry.get("record", {})
                eval_result = record.get("gateway_evaluation", {})
                
                total_requests += 1
                decision = eval_result.get("decision")
                
                if decision == "ALLOW":
                    approved += 1
                else:
                    blocked += 1
                    violations.append(record)
            except json.JSONDecodeError:
                continue

    # Generate Markdown Output
    md = f"# Executive AI Compliance Scorecard\n"
    md += f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n"
    
    md += "## 1. High-Level Summary\n"
    md += f"- **Total Agent Actions Intercepted:** {total_requests}\n"
    md += f"- **Actions Approved:** {approved}\n"
    md += f"- **Actions Blocked (Policy Violations):** {blocked}\n\n"
    
    md += "## 2. Regulatory Mapping & Blocked Actions\n"
    if not violations:
        md += "*No compliance violations detected.*\n"
    else:
        md += "| Timestamp (UTC) | Target Resource | Attempted Action | NIST Violation | EU AI Act Violation |\n"
        md += "|---|---|---|---|---|\n"
        for v in violations:
            # Format timestamp for better readability
            raw_ts = v.get("timestamp", "N/A")
            try:
                dt = datetime.fromisoformat(raw_ts)
                ts = dt.strftime('%Y-%m-%d %H:%M:%S')
            except ValueError:
                ts = raw_ts

            ctx = v.get("agent_context", {})
            resource = ctx.get("resource_type", "Unknown")
            action = ctx.get("action", "Unknown")
            
            impact = v.get("gateway_evaluation", {}).get("compliance_impact", {})
            nist = impact.get("nist_id", "N/A")
            eu = impact.get("eu_ai_act_id", "N/A")
            
            md += f"| {ts} | `{resource}` | `{action}` | {nist} | {eu} |\n"
    
    md += "\n## 3. Cryptographic Chain of Custody\n"
    intact = ComplianceLedger(log_path=ledger_path).verify_integrity()
    if intact:
        md += "> **Status: VERIFIED.** Every logged action is bound into a SHA-256 hash chain (each record hashes in the previous one). Re-verification of the full ledger detected no modification, deletion, or reordering.\n"
    else:
        md += "> **Status: FAILED.** Ledger re-verification detected tampering: a record was modified, deleted, or reordered. This audit trail cannot be trusted.\n"
    
    # Write to Markdown file
    with open(output_path, 'w') as f:
        f.write(md)
        
    print(f"Scorecard successfully generated at: {output_path}")

if __name__ == "__main__":
    generate_scorecard()
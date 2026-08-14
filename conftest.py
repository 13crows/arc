import os
import sys

# Ensure the repository root is importable so `import gateway...` works when
# pytest is invoked from anywhere.
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

POLICY_CONFIG_PATH = os.path.join(REPO_ROOT, "config", "compliance_policy.yaml")

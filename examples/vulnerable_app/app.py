"""An intentionally insecure sample app.

This file exists only as a target for SecureGuard AI's static-analysis agent.
Each function below contains a well-known unsafe pattern that Bandit flags.
Do NOT copy any of this into real software.
"""

import subprocess

import yaml

# B105: hardcoded password.
API_PASSWORD = "supersecret123"


def run_command(user_input):
    # B602: subprocess call with shell=True is vulnerable to shell injection.
    return subprocess.call(user_input, shell=True)


def evaluate(expr):
    # B307: use of eval on untrusted input enables arbitrary code execution.
    return eval(expr)


def load_config(raw):
    # B506: yaml.load without SafeLoader can construct arbitrary objects.
    return yaml.load(raw)


def check_access(role):
    # B101: assert is stripped under `python -O`, defeating this check.
    assert role == "admin"
    return True

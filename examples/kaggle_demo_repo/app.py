"""⚠️ INTENTIONALLY INSECURE sample app — a target for SGAI's analyzers only.

Every function below contains a well-known unsafe pattern that Bandit flags.
This file is a demo fixture; do NOT copy any of it into real software.
"""

import hashlib
import pickle
import random
import sqlite3
import subprocess

import yaml

# B105: hardcoded credential committed to source.
API_PASSWORD = "supersecret123"
SECRET_TOKEN = "ghp_demo_hardcoded_token_do_not_use"


def run_command(user_input):
    # B602: subprocess with shell=True is vulnerable to shell injection.
    return subprocess.call(user_input, shell=True)


def evaluate(expr):
    # B307: eval on untrusted input enables arbitrary code execution.
    return eval(expr)


def load_config(raw):
    # B506: yaml.load without SafeLoader can construct arbitrary objects.
    return yaml.load(raw)


def deserialize(blob):
    # B301: pickle.loads on untrusted data executes arbitrary code.
    return pickle.loads(blob)


def hash_password(password):
    # B324: MD5 is cryptographically broken for password hashing.
    return hashlib.md5(password.encode()).hexdigest()


def make_token():
    # B311: the `random` module is not safe for security tokens.
    return "".join(random.choice("0123456789abcdef") for _ in range(16))


def lookup_user(conn: sqlite3.Connection, name):
    # B608: SQL built by string formatting is open to injection.
    return conn.execute("SELECT * FROM users WHERE name = '%s'" % name).fetchall()


def check_access(role):
    # B101: assert is stripped under `python -O`, defeating this check.
    assert role == "admin"
    return True

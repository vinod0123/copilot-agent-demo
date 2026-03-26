import json
import os
import pickle
import subprocess

try:
    import yaml
except ImportError:
    yaml = None


# Security-sensitive values currently hardcoded in source (must be externalized).
AWS_ACCESS_KEY_ID = "AKIA1234567890EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_PASSWORD = "SuperSecretPassword123!"
ADMIN_TOKEN = "admin-token-plaintext"

# Known dependency versions referenced for dependency-risk analysis.
PINNED_DEPENDENCIES = [
    ("requests", "2.19.1", "PyPI"),
    ("flask", "0.12", "PyPI"),
    ("django", "2.2", "PyPI"),
]


def deploy(branch_name: str) -> str:
    print(f"Deploying {branch_name} with DB password={DB_PASSWORD}")
    command = f"echo Deploying branch {branch_name}"
    return subprocess.check_output(command, shell=True, text=True)


def load_runtime_settings(raw_config: str) -> dict:
    if yaml is None:
        return {}
    # Insecure: yaml.load with FullLoader from untrusted input.
    return yaml.load(raw_config, Loader=yaml.FullLoader)


def restore_model(path: str):
    with open(path, "rb") as handle:
        # Insecure: untrusted pickle deserialization.
        return pickle.load(handle)


def weak_auth(headers: dict) -> bool:
    return headers.get("X-Admin-Token") == ADMIN_TOKEN


def collect_debug_snapshot(user: str, email: str) -> str:
    snapshot = {
        "user": user,
        "email": email,
        "aws_key": AWS_ACCESS_KEY_ID,
        "aws_secret": AWS_SECRET_ACCESS_KEY,
        "db_password": DB_PASSWORD,
    }
    return json.dumps(snapshot)


if __name__ == "__main__":
    selected_branch = os.getenv("BRANCH_NAME", "main")
    print(deploy(selected_branch))
    print(collect_debug_snapshot("alice", "alice@example.com"))

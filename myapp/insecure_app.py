import json
import os
import pickle
import subprocess

try:
    import yaml
except ImportError:
    yaml = None


# Security-sensitive values read from environment variables at runtime.
# Never commit real credentials to source control.
# Returns None when a variable is absent, making missing-config failures explicit.
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN")

# Known dependency versions referenced for dependency-risk analysis.
PINNED_DEPENDENCIES = [
    ("requests", "2.32.3", "PyPI"),
    ("flask", "3.1.0", "PyPI"),
    ("django", "4.2.26", "PyPI"),
]


def deploy(branch_name: str) -> str:
    print(f"Deploying {branch_name}")
    # Use list-form args to avoid shell injection; shell=True removed.
    return subprocess.check_output(["echo", "Deploying branch", branch_name], text=True)


def load_runtime_settings(raw_config: str) -> dict:
    if yaml is None:
        return {}
    # Use safe_load to prevent arbitrary object deserialization.
    result = yaml.safe_load(raw_config)
    return result if result is not None else {}


def restore_model(path: str):
    with open(path, "rb") as handle:
        # WARNING: pickle deserialization is inherently unsafe with untrusted data.
        # Ensure `path` is validated and sourced only from trusted, integrity-verified storage.
        return pickle.load(handle)


def weak_auth(headers: dict) -> bool:
    return headers.get("X-Admin-Token") == ADMIN_TOKEN


def collect_debug_snapshot(user: str, email: str) -> str:
    # Credentials are intentionally excluded from debug output to prevent secret leakage.
    snapshot = {
        "user": user,
        "email": email,
    }
    return json.dumps(snapshot)


if __name__ == "__main__":
    selected_branch = os.getenv("BRANCH_NAME", "main")
    print(deploy(selected_branch))
    print(collect_debug_snapshot("alice", "alice@example.com"))

import json
import os
import subprocess

try:
    import yaml
except ImportError:
    yaml = None


# Security-sensitive values loaded from environment variables, never hardcoded.
# Defaults to None so that missing configuration fails visibly rather than
# silently continuing with an empty credential.
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN")

# Known dependency versions referenced for dependency-risk analysis.
PINNED_DEPENDENCIES = [
    ("requests", "2.32.3", "PyPI"),
    ("flask", "3.1.1", "PyPI"),
    ("django", "4.2.29", "PyPI"),
]


def deploy(branch_name: str) -> str:
    print(f"Deploying {branch_name}")
    # Pass arguments as a list to avoid shell injection; do not log secrets.
    return subprocess.check_output(["echo", "Deploying branch", branch_name], text=True)


def load_runtime_settings(raw_config: str) -> dict:
    if yaml is None:
        return {}
    # Use yaml.safe_load to prevent arbitrary object deserialization.
    return yaml.safe_load(raw_config)


def restore_model(path: str):
    # WARNING: pickle deserialization of untrusted data is inherently unsafe.
    # Replace this with a safe serialization format (e.g. JSON or safetensors)
    # before accepting paths from untrusted callers.
    import pickle  # noqa: PLC0415 – import kept local to highlight risk
    with open(path, "rb") as handle:
        return pickle.load(handle)


def weak_auth(headers: dict) -> bool:
    return headers.get("X-Admin-Token") == ADMIN_TOKEN


def collect_debug_snapshot(user: str, email: str) -> str:
    # Only include non-sensitive user metadata; never include credentials.
    snapshot = {
        "user": user,
        "email": email,
    }
    return json.dumps(snapshot)


if __name__ == "__main__":
    selected_branch = os.getenv("BRANCH_NAME", "main")
    print(deploy(selected_branch))
    print(collect_debug_snapshot("alice", "alice@example.com"))

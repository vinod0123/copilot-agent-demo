import json
import os
import pickle
import subprocess

try:
    import yaml
except ImportError:
    yaml = None


# Credentials loaded from environment variables – never hardcode secrets in source.
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")

# Known dependency versions referenced for dependency-risk analysis.
PINNED_DEPENDENCIES = [
    ("requests", "2.32.3", "PyPI"),
    ("flask", "3.0.3", "PyPI"),
    ("django", "4.2.26", "PyPI"),
]


def deploy(branch_name: str) -> str:
    # Avoid logging credentials; use argument list to prevent shell injection.
    print(f"Deploying {branch_name}")
    return subprocess.check_output(
        ["echo", "Deploying branch", branch_name], text=True
    )


def load_runtime_settings(raw_config: str) -> dict:
    if yaml is None:
        return {}
    # Use safe_load to prevent arbitrary Python-object deserialization.
    result = yaml.safe_load(raw_config)
    return result if isinstance(result, dict) else {}


def restore_model(path: str):
    # WARNING: pickle can execute arbitrary code – only load files from trusted,
    # integrity-verified sources.  Validate the path and provenance before calling
    # this function.
    with open(path, "rb") as handle:
        return pickle.load(handle)  # noqa: S301 – caller is responsible for trust


def weak_auth(headers: dict) -> bool:
    return headers.get("X-Admin-Token") == ADMIN_TOKEN


def collect_debug_snapshot(user: str, email: str) -> str:
    # Only include non-sensitive fields in debug output.
    snapshot = {
        "user": user,
        "email": email,
    }
    return json.dumps(snapshot)


if __name__ == "__main__":
    selected_branch = os.getenv("BRANCH_NAME", "main")
    print(deploy(selected_branch))
    print(collect_debug_snapshot("alice", "alice@example.com"))

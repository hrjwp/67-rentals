"""
Auto-setup helpers for local development.
Ensures a .env file exists with required secrets.
"""
import base64
import os
import secrets
from typing import Dict, List, Tuple


def _read_env_lines(env_path: str) -> Tuple[List[str], Dict[str, str]]:
    lines: List[str] = []
    values: Dict[str, str] = {}
    if not os.path.exists(env_path):
        return lines, values

    with open(env_path, "r") as env_file:
        for raw_line in env_file:
            line = raw_line.rstrip("\n")
            lines.append(line)
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            values[key.strip()] = value.strip()
    return lines, values


def _generate_encryption_key() -> str:
    key = os.urandom(32)
    return base64.urlsafe_b64encode(key).decode("utf-8")


def ensure_env_file() -> None:
    """Ensure .env file exists and required keys are present."""
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
    env_path = os.path.join(base_dir, ".env")

    lines, values = _read_env_lines(env_path)

    data_key = values.get("DATA_ENCRYPTION_KEY") or _generate_encryption_key()
    secret_key = values.get("SECRET_KEY") or secrets.token_urlsafe(32)

    missing_keys = []
    if "DATA_ENCRYPTION_KEY" not in values:
        missing_keys.append(f"DATA_ENCRYPTION_KEY={data_key}")
    if "SECRET_KEY" not in values:
        missing_keys.append(f"SECRET_KEY={secret_key}")

    if not os.path.exists(env_path):
        with open(env_path, "w") as env_file:
            env_file.write("DATA_ENCRYPTION_KEY=" + data_key + "\n")
            env_file.write("SECRET_KEY=" + secret_key + "\n")
        return

    if missing_keys:
        with open(env_path, "a") as env_file:
            if lines and lines[-1].strip():
                env_file.write("\n")
            for entry in missing_keys:
                env_file.write(entry + "\n")

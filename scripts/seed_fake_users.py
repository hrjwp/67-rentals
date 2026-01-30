#!/usr/bin/env python3
"""
Seed the database with fake users and sellers.
Usage:
  python3 scripts/seed_fake_users.py --users 12 --sellers 8
"""
import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path
import sys

import mysql.connector
from werkzeug.security import generate_password_hash

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from db_config import DB_CONFIG
except ModuleNotFoundError:
    import importlib.util

    config_path = ROOT / "db_config.py"
    spec = importlib.util.spec_from_file_location("db_config", config_path)
    if spec and spec.loader:
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        DB_CONFIG = module.DB_CONFIG
    else:
        raise


FIRST_NAMES = [
    "Wei", "Li", "Hui", "Min", "Jun", "Jie", "Xin", "Kai", "Jia", "Ying",
    "Siti", "Aisyah", "Nur", "Fatin", "Haziq", "Irfan", "Muhammad", "Amir",
    "Arun", "Kumar", "Anand", "Priya", "Jasmine", "Ethan", "Lucas", "Chloe",
]

LAST_NAMES = [
    "Tan", "Lim", "Lee", "Ng", "Goh", "Wong", "Chua", "Teo", "Ong", "Koh",
    "Yeo", "Low", "Singh", "Kaur", "Nair", "Hassan", "Halim", "Rahman",
    "Ali", "Ibrahim", "Soh", "Lau",
]

EMAIL_DOMAINS = [
    "example.sg", "mail.sg", "singmail.com", "sgdemo.net",
]


def _connect():
    return mysql.connector.connect(**DB_CONFIG)


def _get_user_columns(cursor):
    cursor.execute(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = DATABASE() AND table_name = 'users'
        """
    )
    return {row[0] for row in cursor.fetchall()}


def _ensure_time_columns(cursor, existing_columns):
    if "created_at" not in existing_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP")
    if "last_login_at" not in existing_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN last_login_at DATETIME NULL")


def _random_phone():
    start = random.choice(["8", "9"])
    rest = "".join(random.choice("0123456789") for _ in range(7))
    return f"+65{start}{rest}"


def _random_nric():
    prefix = random.choice(["S", "T", "F", "G"])
    digits = "".join(random.choice("0123456789") for _ in range(7))
    suffix = random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    return f"{prefix}{digits}{suffix}"


def _random_license():
    digits = "".join(random.choice("0123456789") for _ in range(7))
    return f"SGDL{digits}"


def _build_user_record(index, user_type):
    first = random.choice(FIRST_NAMES)
    last = random.choice(LAST_NAMES)
    domain = random.choice(EMAIL_DOMAINS)
    email = f"{first.lower()}.{last.lower()}.{index}@{domain}"

    age_days = random.randint(15, 720)
    created_at = datetime.now() - timedelta(days=age_days, hours=random.randint(0, 23))

    if random.random() < 0.25:
        last_login_at = None
    else:
        if age_days >= 90 and random.random() < 0.5:
            last_login_days = random.randint(90, age_days)
        else:
            last_login_days = random.randint(0, age_days)
        last_login_at = datetime.now() - timedelta(days=last_login_days, hours=random.randint(0, 23))

    return {
        "first_name": first,
        "last_name": last,
        "email": email,
        "phone_number": _random_phone(),
        "password_hash": generate_password_hash("Welcome123!"),
        "nric": _random_nric(),
        "license_number": _random_license(),
        "user_type": user_type,
        "verified": 1,
        "account_status": "active",
        "role": "customer",
        "created_at": created_at,
        "last_login_at": last_login_at,
    }


def _email_exists(cursor, email):
    cursor.execute("SELECT user_id FROM users WHERE email = %s", (email,))
    return cursor.fetchone() is not None


def _insert_user(cursor, user_data, columns):
    data = {key: value for key, value in user_data.items() if key in columns}
    col_names = ", ".join(data.keys())
    placeholders = ", ".join(["%s"] * len(data))
    cursor.execute(
        f"INSERT INTO users ({col_names}) VALUES ({placeholders})",
        tuple(data.values()),
    )


def main():
    parser = argparse.ArgumentParser(description="Seed fake users and sellers.")
    parser.add_argument("--users", type=int, default=12, help="Number of users to create")
    parser.add_argument("--sellers", type=int, default=8, help="Number of sellers to create")
    parser.add_argument("--seed", type=int, default=67, help="Random seed")
    args = parser.parse_args()

    random.seed(args.seed)

    conn = _connect()
    try:
        cursor = conn.cursor()
        columns = _get_user_columns(cursor)
        _ensure_time_columns(cursor, columns)
        conn.commit()
        columns = _get_user_columns(cursor)

        created = 0
        skipped = 0
        index = 1

        for _ in range(args.users):
            user_data = _build_user_record(index, "user")
            index += 1
            if _email_exists(cursor, user_data["email"]):
                skipped += 1
                continue
            _insert_user(cursor, user_data, columns)
            created += 1

        for _ in range(args.sellers):
            user_data = _build_user_record(index, "seller")
            index += 1
            if _email_exists(cursor, user_data["email"]):
                skipped += 1
                continue
            _insert_user(cursor, user_data, columns)
            created += 1

        conn.commit()
        print(f"Seed complete. Inserted: {created}, skipped: {skipped}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()

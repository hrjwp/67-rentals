#!/usr/bin/env python3
"""
CLI script to encrypt existing plaintext PII in users and incident_reports.
Run from project root: python scripts/encrypt_existing_data.py

Ensure .env has DATA_ENCRYPTION_KEY set before running.
"""
import os
import sys

# Load .env before any config imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from database import get_db_connection
from utils.encryption import encrypt_value, decrypt_value
from utils.field_encryption_config import SENSITIVE_FIELDS

TABLES = [("users", "user_id"), ("incident_reports", "id")]


def main():
    if not os.environ.get("DATA_ENCRYPTION_KEY"):
        print("ERROR: DATA_ENCRYPTION_KEY not set in .env")
        sys.exit(1)

    print("Encrypting existing plaintext data...")
    total = 0

    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        for table_name, pk_col in TABLES:
            cols = SENSITIVE_FIELDS.get(table_name, [])
            if not cols:
                continue
            cols_str = ", ".join([pk_col] + cols)
            try:
                cursor.execute(f"SELECT {cols_str} FROM {table_name}")
            except Exception as e:
                print(f"  {table_name}: SKIP ({e})")
                continue

            rows = cursor.fetchall()
            updated = 0
            for row in rows:
                updates = {}
                for col in cols:
                    val = row.get(col)
                    if not val:
                        continue
                    try:
                        maybe_plain = decrypt_value(val, fallback_on_error=True)
                    except Exception:
                        maybe_plain = val
                    if maybe_plain != val:
                        continue
                    try:
                        updates[col] = encrypt_value(val)
                    except Exception as e:
                        print(f"ERROR encrypting {table_name}.{col} (pk={row[pk_col]}): {e}")
                        conn.rollback()
                        sys.exit(1)

                if updates:
                    set_clause = ", ".join([f"{c} = %s" for c in updates.keys()])
                    params = list(updates.values()) + [row[pk_col]]
                    cursor.execute(
                        f"UPDATE {table_name} SET {set_clause} WHERE {pk_col} = %s",
                        params,
                    )
                    updated += 1

            total += updated
            print(f"  {table_name}: {updated} rows encrypted")

        cursor.close()

    print(f"\nDone. Total: {total} rows encrypted.")


if __name__ == "__main__":
    main()

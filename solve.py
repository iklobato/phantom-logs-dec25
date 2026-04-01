#!/usr/bin/env python3
"""Solve the Phantom Logs challenge with clean code principles."""

import csv
import json
import os

# Constants
CHARSET = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
XOR_KEY = "GlaDOS"
LOGS_DIR = "logs"
FILE_EXTENSION = ".dat"
PHANTOM_STATUS = "phantom_process"


def int_to_base62(n: int) -> str:
    """Convert integer to Base62 string."""
    if n == 0:
        return "0"
    result = []
    while n > 0:
        n, rem = divmod(n, 62)
        result.append(chr(CHARSET[rem]))
    return "".join(reversed(result))


def txn_id_to_base62(txn_id: str) -> str:
    """Convert transaction ID to Base62 via UTF-8 -> Big-Endian Integer."""
    bytes_val = txn_id.encode("utf-8")
    int_val = int.from_bytes(bytes_val, "big")
    return int_to_base62(int_val)


def xor_decrypt(data: bytes, key: str) -> bytes:
    """XOR decrypt data with repeating key."""
    key_bytes = key.encode("utf-8")
    return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))


def is_valid_transaction_hash(txn_id: str, expected_hash: str) -> bool:
    """Check if transaction ID matches expected Base62 hash."""
    return txn_id_to_base62(txn_id) == expected_hash


def load_valid_transaction_ids() -> list[str]:
    """Load and validate transaction IDs from manifest."""
    valid_txn_ids = []
    with open("manifest.csv", "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            txn_id = row["transaction_id"]
            expected_hash = row["verification_hash"]
            if is_valid_transaction_hash(txn_id, expected_hash):
                valid_txn_ids.append(txn_id)
    return valid_txn_ids


def decrypt_transaction_data(txn_id: str) -> dict | None:
    """Decrypt and parse transaction data, return None if invalid."""
    filepath = os.path.join(LOGS_DIR, f"{txn_id}{FILE_EXTENSION}")
    if not os.path.exists(filepath):
        return None

    try:
        with open(filepath, "rb") as f:
            encrypted_data = f.read()
        
        decrypted = xor_decrypt(encrypted_data, XOR_KEY)
        return json.loads(decrypted.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return None


def is_legitimate_transaction(transaction_data: dict) -> bool:
    """Check if transaction is legitimate (not phantom)."""
    return transaction_data.get("status") != PHANTOM_STATUS


def extract_transaction_amount(transaction_data: dict) -> float:
    """Extract amount from transaction data."""
    return transaction_data.get("amount", 0.0)


def calculate_total_amount() -> tuple[float, int]:
    """Calculate total amount of all verified transactions.
    
    Returns:
        tuple: (total_amount, valid_transaction_count)
    """
    valid_txn_ids = load_valid_transaction_ids()
    total = 0.0

    for txn_id in valid_txn_ids:
        transaction_data = decrypt_transaction_data(txn_id)
        if transaction_data is None:
            continue
            
        if is_legitimate_transaction(transaction_data):
            total += extract_transaction_amount(transaction_data)

    return total, len(valid_txn_ids)


def main() -> None:
    """Main execution function."""
    total, valid_count = calculate_total_amount()
    print(f"Valid transactions: {valid_count}")
    print(f"\nTotal Amount: {total}")


if __name__ == "__main__":
    main()

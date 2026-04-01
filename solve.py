#!/usr/bin/env python3
"""Solve the Phantom Logs challenge."""

import csv
import json
import os

CHARSET = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


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


def main():
    xor_key = "GlaDOS"
    logs_dir = "logs"

    # Load manifest
    valid_txn_ids = []
    with open("manifest.csv", "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            txn_id = row["transaction_id"]
            expected_hash = row["verification_hash"]

            # Verify hash
            computed_hash = txn_id_to_base62(txn_id)
            if computed_hash == expected_hash:
                valid_txn_ids.append(txn_id)

    print(f"Valid transactions: {len(valid_txn_ids)}")

    # Process valid transactions
    total = 0.0
    for txn_id in valid_txn_ids:
        filepath = os.path.join(logs_dir, f"{txn_id}.dat")
        if os.path.exists(filepath):
            with open(filepath, "rb") as f:
                encrypted_data = f.read()

            decrypted = xor_decrypt(encrypted_data, xor_key)

            try:
                json_data = json.loads(decrypted.decode("utf-8"))
                # Exclude phantom_process transactions (they're noise)
                if json_data.get("status") == "phantom_process":
                    continue
                amount = json_data.get("amount", 0)
                total += amount
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                print(f"Failed to parse {txn_id}: {e}")

    print(f"\nTotal Amount: {total}")


if __name__ == "__main__":
    main()

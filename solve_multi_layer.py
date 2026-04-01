#!/usr/bin/env python3
"""Alternative solution using multiple validation layers."""

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


def validate_transaction(json_data: dict, txn_id: str) -> tuple[bool, str]:
    """
    Validate a transaction using multiple criteria.
    Returns (is_valid, reason_if_invalid)
    """
    # 1. Check required fields exist
    required_fields = ["id", "amount", "status"]
    for field in required_fields:
        if field not in json_data:
            return False, f"Missing required field: {field}"

    # 2. Check ID matches transaction ID (case-insensitive to handle data inconsistencies)
    if json_data["id"].lower() != txn_id.lower():
        return False, f"ID mismatch: expected {txn_id}, got {json_data['id']}"

    # 3. Check status is exactly "verified"
    if json_data["status"] != "verified":
        return False, f"Invalid status: {json_data['status']}"

    # 4. Validate amount is numeric
    amount = json_data["amount"]
    if not isinstance(amount, (int, float)):
        return False, f"Amount is not numeric: {type(amount)}"

    # 5. Check amount is positive
    if amount <= 0:
        return False, f"Amount is not positive: {amount}"

    # 6. Check amount has at most 2 decimal places (currency standard)
    if isinstance(amount, float):
        # Convert to string and check decimal places
        amount_str = str(amount)
        if "." in amount_str:
            decimal_places = len(amount_str.split(".")[1])
            if decimal_places > 2:
                return False, f"Amount has too many decimal places: {decimal_places}"

    # 7. Check amount is within reasonable bounds
    # Assuming no transaction should exceed $1,000,000
    if amount > 1_000_000:
        return False, f"Amount exceeds reasonable maximum: {amount}"

    return True, ""


def main():
    xor_key = "GlaDOS"
    logs_dir = "logs"

    # Load manifest and find valid transactions
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

    print(f"Cryptographically valid transactions: {len(valid_txn_ids)}")

    # Process with multi-layer validation
    total = 0.0
    stats = {
        "passed_all": 0,
        "failed_id_match": 0,
        "failed_status": 0,
        "failed_amount_type": 0,
        "failed_amount_positive": 0,
        "failed_decimal_places": 0,
        "failed_amount_bounds": 0,
        "failed_missing_fields": 0,
        "failed_json_parse": 0,
        "failed_file_read": 0,
    }

    for txn_id in valid_txn_ids:
        filepath = os.path.join(logs_dir, f"{txn_id}.dat")
        if not os.path.exists(filepath):
            stats["failed_file_read"] += 1
            continue

        try:
            with open(filepath, "rb") as f:
                encrypted_data = f.read()

            decrypted = xor_decrypt(encrypted_data, xor_key)

            try:
                json_data = json.loads(decrypted.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                stats["failed_json_parse"] += 1
                continue

            # Apply multi-layer validation
            is_valid, reason = validate_transaction(json_data, txn_id)

            if is_valid:
                total += json_data["amount"]
                stats["passed_all"] += 1
            else:
                # Categorize failure reason
                if "Missing required field" in reason:
                    stats["failed_missing_fields"] += 1
                elif "ID mismatch" in reason:
                    stats["failed_id_match"] += 1
                elif "Invalid status" in reason:
                    stats["failed_status"] += 1
                elif "Amount is not numeric" in reason:
                    stats["failed_amount_type"] += 1
                elif "Amount is not positive" in reason:
                    stats["failed_amount_positive"] += 1
                elif "Amount has too many decimal places" in reason:
                    stats["failed_decimal_places"] += 1
                elif "Amount exceeds reasonable maximum" in reason:
                    stats["failed_amount_bounds"] += 1
                else:
                    # Fallback - count as status failure for simplicity
                    stats["failed_status"] += 1

        except Exception as e:
            stats["failed_file_read"] += 1
            print(f"Error reading {txn_id}: {e}")

    # Print statistics
    print("\nValidation Statistics:")
    print(f"  Passed all validations: {stats['passed_all']}")
    print(f"  Failed ID match: {stats['failed_id_match']}")
    print(f"  Failed status check: {stats['failed_status']}")
    print(f"  Failed amount type: {stats['failed_amount_type']}")
    print(f"  Failed amount positive: {stats['failed_amount_positive']}")
    print(f"  Failed decimal places: {stats['failed_decimal_places']}")
    print(f"  Failed amount bounds: {stats['failed_amount_bounds']}")
    print(f"  Failed missing fields: {stats['failed_missing_fields']}")
    print(f"  Failed JSON parse: {stats['failed_json_parse']}")
    print(f"  Failed file read: {stats['failed_file_read']}")

    print(f"\nTotal Amount: {total:.2f}")

    # Verify we got the expected result
    expected = 50227.93
    if abs(total - expected) < 0.01:
        print(f"✓ Result matches expected value: {expected}")
    else:
        print(f"✗ Result mismatch! Expected: {expected}, Got: {total}")


if __name__ == "__main__":
    main()

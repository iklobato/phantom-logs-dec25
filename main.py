import csv
import json
import string
import os

BASE62_ALPHABET = string.digits + string.ascii_letters

def base62_encode(s):
    n = int.from_bytes(s.encode("utf-8"), "big")
    if n == 0:
        return BASE62_ALPHABET[0]
    out = []
    b = len(BASE62_ALPHABET)
    while n > 0:
        n, r = divmod(n, b)
        out.append(BASE62_ALPHABET[r])
    return "".join(reversed(out))

def get_valid_transactions():
    valid_transactions = []
    with open("manifest.csv") as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            transaction_id, verification_hash, timestamp = row
            encoded = base62_encode(transaction_id)
            if encoded.lower() == verification_hash.lower():
                valid_transactions.append(transaction_id)
    return valid_transactions

def xor_bytes(data, key):
    out = []
    klen = len(key)
    for i, b in enumerate(data):
        out.append(b ^ key[i % klen])
    return bytes(out)

def decrypt_log(file_path, key):
    with open(file_path, "rb") as f:
        encrypted_data = f.read()
    
    for i in range(len(key)):
        rotated_key = key[i:] + key[:i]
        decrypted_data = xor_bytes(encrypted_data, rotated_key)
        if decrypted_data.startswith(b'{') and decrypted_data.endswith(b'}'):
            return json.loads(decrypted_data)
    return None

def main():
    valid_transactions = get_valid_transactions()
    total_amount = 0
    secret_key = b"GlaDOS"
    
    for transaction_id in valid_transactions:
        log_file = f"logs/{transaction_id}.dat"
        if os.path.exists(log_file):
            log_data = decrypt_log(log_file, secret_key)
            if log_data and "amount" in log_data:
                total_amount += log_data["amount"]
    
    print(f"Total amount of verified transactions: {total_amount}")

if __name__ == "__main__":
    main()

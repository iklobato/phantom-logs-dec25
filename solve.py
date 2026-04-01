#!/usr/bin/env python3
"""Solve the Phantom Logs challenge with class-based SOLID design."""

import csv
import json
import os
from typing import Dict, List, Optional, Tuple


class HashValidator:
    """Validates transaction IDs against Base62 hashes."""
    
    CHARSET = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    
    @staticmethod
    def int_to_base62(n: int) -> str:
        """Convert integer to Base62 string."""
        if n == 0:
            return "0"
        result = []
        while n > 0:
            n, rem = divmod(n, 62)
            result.append(chr(HashValidator.CHARSET[rem]))
        return "".join(reversed(result))
    
    @classmethod
    def txn_id_to_base62(cls, txn_id: str) -> str:
        """Convert transaction ID to Base62 via UTF-8 -> Big-Endian Integer."""
        bytes_val = txn_id.encode("utf-8")
        int_val = int.from_bytes(bytes_val, "big")
        return cls.int_to_base62(int_val)
    
    @classmethod
    def is_valid_transaction_hash(cls, txn_id: str, expected_hash: str) -> bool:
        """Check if transaction ID matches expected Base62 hash."""
        return cls.txn_id_to_base62(txn_id) == expected_hash


class FileDecryptor:
    """Handles file reading and XOR decryption."""
    
    def __init__(self, xor_key: str):
        self._xor_key = xor_key
    
    def decrypt_file(self, filepath: str) -> Optional[bytes]:
        """Read and decrypt a file, return None if file doesn't exist or error occurs."""
        if not os.path.exists(filepath):
            return None
        
        try:
            with open(filepath, "rb") as f:
                encrypted_data = f.read()
            return self._xor_decrypt(encrypted_data)
        except OSError:
            return None
    
    def _xor_decrypt(self, data: bytes) -> bytes:
        """XOR decrypt data with repeating key."""
        key_bytes = self._xor_key.encode("utf-8")
        return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))


class TransactionParser:
    """Parses and validates transaction JSON data."""
    
    @staticmethod
    def parse_transaction_data(decrypted_data: bytes) -> Optional[Dict]:
        """Parse decrypted data as JSON, return None if parsing fails."""
        try:
            return json.loads(decrypted_data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None


class TransactionFilter:
    """Filters out phantom transactions."""
    
    PHANTOM_STATUS = "phantom_process"
    
    @staticmethod
    def is_legitimate_transaction(transaction_data: Dict) -> bool:
        """Check if transaction is legitimate (not phantom)."""
        return transaction_data.get("status") != TransactionFilter.PHANTOM_STATUS


class AmountCalculator:
    """Calculates total amount from legitimate transactions."""
    
    @staticmethod
    def extract_amount(transaction_data: Dict) -> float:
        """Extract amount from transaction data."""
        return transaction_data.get("amount", 0.0)
    
    @staticmethod
    def calculate_total(transactions: List[Dict]) -> float:
        """Calculate total amount from list of transactions."""
        return sum(AmountCalculator.extract_amount(tx) for tx in transactions)


class PhantomLogsSolver:
    """Orchestrates the phantom logs solution process."""
    
    def __init__(self, 
                 hash_validator: HashValidator,
                 file_decryptor: FileDecryptor,
                 transaction_parser: TransactionParser,
                 transaction_filter: TransactionFilter,
                 amount_calculator: AmountCalculator,
                 logs_dir: str = "logs",
                 file_extension: str = ".dat"):
        self._hash_validator = hash_validator
        self._file_decryptor = file_decryptor
        self._transaction_parser = transaction_parser
        self._transaction_filter = transaction_filter
        self._amount_calculator = amount_calculator
        self._logs_dir = logs_dir
        self._file_extension = file_extension
    
    def load_valid_transaction_ids(self) -> List[str]:
        """Load and validate transaction IDs from manifest."""
        valid_txn_ids = []
        with open("manifest.csv", "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                txn_id = row["transaction_id"]
                expected_hash = row["verification_hash"]
                if self._hash_validator.is_valid_transaction_hash(txn_id, expected_hash):
                    valid_txn_ids.append(txn_id)
        return valid_txn_ids
    
    def decrypt_and_parse_transaction(self, txn_id: str) -> Optional[Dict]:
        """Decrypt and parse a single transaction file."""
        filepath = os.path.join(self._logs_dir, f"{txn_id}{self._file_extension}")
        decrypted_data = self._file_decryptor.decrypt_file(filepath)
        if decrypted_data is None:
            return None
        return self._transaction_parser.parse_transaction_data(decrypted_data)
    
    def solve(self) -> Tuple[float, int]:
        """Solve the phantom logs challenge.
        
        Returns:
            Tuple of (total_amount, valid_transaction_count)
        """
        valid_txn_ids = self.load_valid_transaction_ids()
        legitimate_transactions = []
        
        for txn_id in valid_txn_ids:
            transaction_data = self.decrypt_and_parse_transaction(txn_id)
            if transaction_data is None:
                continue
                
            if self._transaction_filter.is_legitimate_transaction(transaction_data):
                legitimate_transactions.append(transaction_data)
        
        total_amount = self._amount_calculator.calculate_total(legitimate_transactions)
        return total_amount, len(valid_txn_ids)


def main() -> None:
    """Main execution function."""
    # Create instances following Dependency Inversion Principle
    hash_validator = HashValidator()
    file_decryptor = FileDecryptor("GlaDOS")
    transaction_parser = TransactionParser()
    transaction_filter = TransactionFilter()
    amount_calculator = AmountCalculator()
    
    # Create orchestrator
    solver = PhantomLogsSolver(
        hash_validator=hash_validator,
        file_decryptor=file_decryptor,
        transaction_parser=transaction_parser,
        transaction_filter=transaction_filter,
        amount_calculator=amount_calculator
    )
    
    # Solve and display results
    total_amount, valid_count = solver.solve()
    print(f"Valid transactions: {valid_count}")
    print(f"\nTotal Amount: {total_amount}")


if __name__ == "__main__":
    main()

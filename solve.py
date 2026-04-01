#!/usr/bin/env python3
"""Solve the Phantom Logs challenge with class-based SOLID design and Enums."""

import csv
import json
import os
from enum import Enum
from typing import Dict, List, Optional, Tuple


class TransactionStatus(Enum):
    """Enumeration of possible transaction statuses."""

    PHANTOM_PROCESS = "phantom_process"
    VERIFIED = "verified"


class FileExtension(Enum):
    """Enumeration of supported file extensions."""

    DAT = ".dat"


class Directory(Enum):
    """Enumeration of directory names."""

    LOGS = "logs"


class HashValidator:
    """Validates transaction IDs against Base62 hashes."""

    CHARSET = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    @staticmethod
    def encode_integer_to_base62(number: int) -> str:
        """Convert integer to Base62 string."""
        if number == 0:
            return "0"
        result = []
        while number > 0:
            number, remainder = divmod(number, 62)
            result.append(chr(HashValidator.CHARSET[remainder]))
        return "".join(reversed(result))

    @classmethod
    def encode_transaction_id_to_base62(cls, transaction_id: str) -> str:
        """Convert transaction ID to Base62 via UTF-8 -> Big-Endian Integer."""
        bytes_value = transaction_id.encode("utf-8")
        integer_value = int.from_bytes(bytes_value, "big")
        return cls.encode_integer_to_base62(integer_value)

    @classmethod
    def is_transaction_id_hash_valid(cls, transaction_id: str, expected_hash: str) -> bool:
        """Check if transaction ID matches expected Base62 hash."""
        return cls.encode_transaction_id_to_base62(transaction_id) == expected_hash


class FileDecryptor:
    """Handles file reading and XOR decryption."""

    def __init__(self, xor_key: str):
        self._xor_key = xor_key

    def read_and_decrypt_file(self, file_path: str) -> Optional[bytes]:
        """Read and decrypt a file, return None if file doesn't exist or error occurs."""
        if not os.path.exists(file_path):
            return None

        try:
            with open(file_path, "rb") as file_handle:
                encrypted_data = file_handle.read()
            return self._apply_xor_decryption(encrypted_data)
        except OSError:
            return None

    def _apply_xor_decryption(self, data: bytes) -> bytes:
        """XOR decrypt data with repeating key."""
        key_bytes = self._xor_key.encode("utf-8")
        return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))


class TransactionParser:
    """Parses and validates transaction JSON data."""

    @staticmethod
    def parse_transaction_json(decrypted_data: bytes) -> Optional[Dict]:
        """Parse decrypted data as JSON, return None if parsing fails."""
        try:
            return json.loads(decrypted_data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None


class TransactionFilter:
    """Filters out phantom transactions."""

    @staticmethod
    def is_transaction_valid(transaction_data: Dict) -> bool:
        """Check if transaction is legitimate (not phantom)."""
        status = transaction_data.get("status")
        return status != TransactionStatus.PHANTOM_PROCESS.value


class AmountCalculator:
    """Calculates total amount from legitimate transactions."""

    @staticmethod
    def retrieve_transaction_amount(transaction_data: Dict) -> float:
        """Extract amount from transaction data."""
        return transaction_data.get("amount", 0.0)

    @staticmethod
    def sum_transaction_amounts(transactions: List[Dict]) -> float:
        """Calculate total amount from list of transactions."""
        return sum(AmountCalculator.retrieve_transaction_amount(tx) for tx in transactions)


class PhantomLogsSolver:
    """Orchestrates the phantom logs solution process."""

    def __init__(
        self,
        hash_validator: HashValidator,
        file_decryptor: FileDecryptor,
        transaction_parser: TransactionParser,
        transaction_filter: TransactionFilter,
        amount_calculator: AmountCalculator,
        logs_dir: str = Directory.LOGS.value,
        file_extension: str = FileExtension.DAT.value,
    ):
        self._hash_validator = hash_validator
        self._file_decryptor = file_decryptor
        self._transaction_parser = transaction_parser
        self._transaction_filter = transaction_filter
        self._amount_calculator = amount_calculator
        self._logs_dir = logs_dir
        self._file_extension = file_extension

    def retrieve_validated_transaction_ids(self) -> List[str]:
        """Load and validate transaction IDs from manifest."""
        valid_transaction_ids = []
        with open("manifest.csv", "r") as manifest_file:
            reader = csv.DictReader(manifest_file)
            for row in reader:
                transaction_id = row["transaction_id"]
                expected_hash = row["verification_hash"]
                if self._hash_validator.is_transaction_id_hash_valid(transaction_id, expected_hash):
                    valid_transaction_ids.append(transaction_id)
        return valid_transaction_ids

    def load_and_parse_transaction(self, transaction_id: str) -> Optional[Dict]:
        """Decrypt and parse a single transaction file."""
        file_path = os.path.join(self._logs_dir, f"{transaction_id}{self._file_extension}")
        decrypted_data = self._file_decryptor.read_and_decrypt_file(file_path)
        if decrypted_data is None:
            return None
        return self._transaction_parser.parse_transaction_json(decrypted_data)

    def execute_solution(self) -> Tuple[float, int]:
        """Solve the phantom logs challenge.

        Returns:
            Tuple of (total_amount, valid_transaction_count)
        """
        validated_transaction_ids = self.retrieve_validated_transaction_ids()
        legitimate_transactions = []

        for transaction_id in validated_transaction_ids:
            transaction_data = self.load_and_parse_transaction(transaction_id)
            if transaction_data is None:
                continue

            if self._transaction_filter.is_transaction_valid(transaction_data):
                legitimate_transactions.append(transaction_data)

        total_amount = self._amount_calculator.sum_transaction_amounts(legitimate_transactions)
        return total_amount, len(validated_transaction_ids)


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
        amount_calculator=amount_calculator,
    )

    # Solve and display results
    total_amount, validated_count = solver.execute_solution()
    print(f"Valid transactions: {validated_count}")
    print(f"\nTotal Amount: {total_amount}")


if __name__ == "__main__":
    main()

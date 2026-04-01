# Case: The Phantom Logs

## Scenario
We are auditing a compromised payment gateway. A full set of transaction logs (`logs.tar.gz`) has been recovered alongside a master manifest (`manifest.csv`).

However, the system was flooded with "phantom" transactions during the incident. We need to separate the real data from the noise.

## Artifacts
1.  **`logs.tar.gz`**: Compressed archive containing encrypted transaction files. Filenames correspond to Transaction IDs.
2.  **`manifest.csv`**: A list of all recorded events, including a verification hash for each.
3.  **`server_room.png`**: A reference photo from the facility.

## Objective
Calculate the **Total Amount** of all **verified** transactions.

## Technical Rules

### 1. Integrity Check (Crucial)
The `logs.tar.gz` archive contains both valid and corrupted files. You must extract and filter them using the manifest.

A transaction is **VALID** only if:
1.  The `verification_hash` in the manifest matches the **Base62** encoding of the Transaction ID.

**Base62 Specification:**
- Logic: `Transaction ID (String)` -> `UTF-8 Bytes` -> `Big-Endian Integer` -> `Base62 String`.
- Standard: We use the character set `0-9`, `A-Z`, `a-z` (Reference: https://github.com/suminb/base62).
* **Warning:** If the hash does not match, the file is corrupted. Its payload might look like valid JSON, but the data is garbage. **Exclude these from the sum.**

### 2. Decryption
The log files contain JSON payloads. To avoid transmitting plaintext, the system uses a simple **XOR Cipher** (repeating key) to encrypt the data.
- **Hint:** The decryption key is hidden in the server room. The sign in the image points the way.
* **Warning:** The corrupted files may have additional garbage information.

## Solution

### Key Discovery
From the EXIF metadata of `server_room.png`:
```
Software: System_Key: GlaDOS
```
The XOR decryption key is **`GlaDOS`**.

### Algorithm
1. Extract `logs.tar.gz`
2. For each transaction in `manifest.csv`:
   - Compute Base62 encoding of Transaction ID (UTF-8 → Big-Endian Integer → Base62)
   - If hash matches `verification_hash` → file is valid
3. XOR decrypt valid files with key `GlaDOS`
4. Parse JSON, extract `amount` field, exclude entries with `status: "phantom_process"`
5. Sum all valid amounts

### Implementation
See `solve.py` for the complete implementation.

## Result
**Total Amount: 50227.93**

- Valid transactions (passed hash verification): 186
- Phantom transactions excluded: 1
- Verified transactions processed: 185
- Final sum: $50,227.93

## Files
- `solve.py`: Python script implementing the solution
- `result.txt`: Contains the final answer
- `logs/`: Extracted transaction log files
- `manifest.csv`: Transaction verification data
- `server_room.png`: Contains the decryption key in EXIF metadata

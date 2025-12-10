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

## Deliverable
- A git repository with your script.
- The final sum.

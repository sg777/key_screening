# Key Screening Attack Implementation

This repository contains the implementation for the *Asymmetric Hardware Fault Attack* described in the paper *Asymmetric Hardware Faults: Exploiting Low Hamming Weight Hashes in OTP-Based Secure Boot* by Sarat Chandra Prasad Gingupalli.

## Structure
- **md5/**: Implementation for MD5-based attack (proof-of-concept for low Hamming weight hashes).
  - `md5_search.py`: Finds ECDSA keys (NIST P-256) producing MD5 hashes with low Hamming weight ($k \leq 53$, i.e., $\geq 75$ zeros).
  - `md5_superhash.py`: Finds superset hashes for a given low Hamming weight MD5 hash (e.g., `825020c00126288101a3b11424208009`, $k=32$).
  - `md5.hashes.txt`: Stores low Hamming weight MD5 hashes (e.g., `825020c00126288101a3b11424208009`, $k=32$, 96 zeros).
  - `md5.superhashes.txt`: Stores superset hashes (e.g., `87d1e8fe6d3e7f8f37b3b3366ea9853f`, $k=78$).
- **sha1/**: Implementation for SHA-1-based attack (theoretical analysis).
  - `sha1_search.py`: Finds ECDSA keys producing SHA-1 hashes with low Hamming weight ($k \leq 68$, i.e., $\geq 92$ zeros).
  - `sha1_superhash.py`: Finds superset hashes for a given low Hamming weight SHA-1 hash.
  - `sha1.hashes.txt`: Stores low Hamming weight SHA-1 hashes.
  - `sha1.superhashes.txt`: Stores superset hashes.
- **sha256/**: Implementation for SHA-256-based attack (primary target).
  - `sha256_search.py`: Finds ECDSA keys producing SHA-256 hashes with low Hamming weight ($k \leq 112$, i.e., $\geq 144$ zeros).
  - `sha256_superhash.py`: Finds superset hashes for a given low Hamming weight SHA-256 hash.
  - `sha256.hashes.txt`: Stores low Hamming weight SHA-256 hashes (e.g., `13080e6066508e80e0228f19082e83e9094509a0b0234804406248c1cd208518`, $k=84$).
  - `sha256.superhashes.txt`: Stores superset hashes.

## Usage
Run `<hash_name>_search.py --zeros <min_zeros>` to generate low Hamming weight hashes, stored in `<hash_name>.hashes.txt`. For example:
```bash
python3 md5_search.py --zeros 75
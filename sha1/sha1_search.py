#!/usr/bin/env python3
"""
Script to generate ECDSA keys (NIST P-256) in parallel and find a specified number of SHA-1 hashes
with at least a given number of zeros (low Hamming weight), demonstrating vulnerabilities in OTP
fuse-based secure boot systems.
"""
import argparse
import hashlib
import multiprocessing as mp
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

def count_zeros(hash_hex: str) -> int:
    """Count the number of 0's in the binary representation of a 160-bit SHA-1 hash."""
    binary = bin(int(hash_hex, 16))[2:].zfill(160)
    return binary.count('0')

def generate_and_check_key(trial_counter: mp.Value, hash_counter: mp.Value, lock: mp.Lock, min_zeros: int, num_hashes: int, stop_event: mp.Event) -> None:
    """Generate an ECDSA key and check if its SHA-1 hash has at least min_zeros zeros."""
    while not stop_event.is_set():
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        pubkey_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        hash_obj = hashlib.sha1(pubkey_der)
        hash_hex = hash_obj.hexdigest()
        zeros = count_zeros(hash_hex)
        ones = 160 - zeros
        
        with lock:
            trial_counter.value += 1
            trial_count = trial_counter.value
        
        if zeros >= min_zeros:
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
                with open('sha1.hashes.txt', 'a') as f:
                    f.write(f"Trial: {trial_count}, Hash: {hash_hex}, Zeros: {zeros}, Ones: {ones}\n")
                    f.write("Private Key:\n")
                    f.write(privkey_pem)
                    f.write("Public Key:\n")
                    f.write(pubkey_pem)
                    f.write("\n" + "-"*80 + "\n")
                print(f"Trial {trial_count}: Found hash {hash_hex} with {zeros} zeros, {ones} ones")
                hash_counter.value += 1
                if hash_counter.value >= num_hashes:
                    stop_event.set()  # Signal stop when num_hashes is reached

def main():
    """Run key generation in parallel to find num_hashes SHA-1 hashes with at least min_zeros zeros."""
    parser = argparse.ArgumentParser(description="Search for ECDSA keys with SHA-1 hashes having a specified number of zeros.")
    parser.add_argument('--zeros', type=int, required=True, help="Minimum number of zeros in the SHA-1 hash")
    parser.add_argument('--num-hashes', type=int, default=64, help="Number of hashes to find (default: 64)")
    args = parser.parse_args()
    min_zeros = args.zeros
    num_hashes = args.num_hashes
    
    num_processes = mp.cpu_count()  # Use all available CPU cores
    trial_counter = mp.Value('i', 0)  # Shared trial counter
    hash_counter = mp.Value('i', 0)  # Shared hash counter
    lock = mp.Lock()  # Lock for thread-safe counter and file access
    stop_event = mp.Event()  # Event to signal when num_hashes is reached
    
    print(f"Generating ECDSA keys (NIST P-256) in parallel ({num_processes} processes) to find {num_hashes} SHA-1 hashes with at least {min_zeros} zeros...")
    processes = [
        mp.Process(target=generate_and_check_key, args=(trial_counter, hash_counter, lock, min_zeros, num_hashes, stop_event))
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
        print(f"\nStopped by user after {trial_counter.value} trials, found {hash_counter.value} hashes.")

if __name__ == "__main__":
    main()
import time
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

def generate_key_and_hash():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    pubkey_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    hash_obj = hashlib.sha1(pubkey_der)
    hash_hex = hash_obj.hexdigest()
    return hash_hex

def simulate_comparison(hash_hex):
    # Simulate a superset check (dummy operation, e.g., convert to bin and check)
    binary = bin(int(hash_hex, 16))[2:].zfill(160)
    return all(binary[i] == '1' for i in range(42))  # Dummy check

def measure_operations(func, duration=60):
    start_time = time.time()
    count = 0
    while time.time() - start_time < duration:
        func()
        count += 1
    return count

def main():
    print("Measuring key generation + SHA-1 hash for 1 minute...")
    key_gen_count = measure_operations(generate_key_and_hash)
    print(f"Key gens + hashes per minute: {key_gen_count}")

    # Generate a sample hash for comparison simulation
    sample_hash = generate_key_and_hash()
    def comparison_wrapper():
        simulate_comparison(sample_hash)

    print("\nMeasuring SHA-1 comparisons for 1 minute...")
    comparison_count = measure_operations(comparison_wrapper)
    print(f"Comparisons per minute: {comparison_count}")

    ratio = comparison_count / key_gen_count if key_gen_count > 0 else 0
    print(f"\nRatio (comparisons / key gens): {ratio:.2f}")

if __name__ == "__main__":
    main()

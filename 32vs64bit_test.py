import rsa
import time

def generate_rsa_key(bits: int):
    start_time = time.time()
    pubkey, privkey = rsa.newkeys(bits)
    end_time = time.time()
    return end_time - start_time

if __name__ == "__main__":
    bits = 2048  # Size of the RSA key
    duration = generate_rsa_key(bits)
    print(f"Time taken to generate a {bits}-bit RSA key: {duration:.4f} seconds")
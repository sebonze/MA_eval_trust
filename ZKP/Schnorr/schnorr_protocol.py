from hashlib import sha384
import random
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend

def generate_dh_parameters(key_size=2048):
    # Generate DH parameters which include a large prime number (p) and a generator (g)
    parameters = dh.generate_parameters(generator=2, key_size=key_size, backend=default_backend())
    return parameters

class SchnorrProtocolSHA384:
    def __init__(self, key_size=2048):
        dh_parameters = generate_dh_parameters(key_size)
        self.p = dh_parameters.parameter_numbers().p
        # Correctly calculate q as (p - 1) / 2 for a safe prime p
        self.q = (self.p - 1) // 2
        self.g = dh_parameters.parameter_numbers().g
        self.x = random.randint(1, self.q)  # Private key
        self.y = pow(self.g, self.x, self.p)  # Public key

    def generate_commitment(self):
        self.r = random.randint(1, self.q)
        self.c = pow(self.g, self.r, self.p)
        return self.c

    def generate_challenge(self, c):
        c_bytes = c.to_bytes((c.bit_length() + 7) // 8, 'big')
        e_hash = sha384(c_bytes).digest()
        self.e = int.from_bytes(e_hash, 'big') % self.q
        return self.e

    def generate_response(self, e):
        self.s = (self.r + e * self.x) % self.q
        return self.s

    def verify(self, c, e, s):
        lhs = pow(self.g, s, self.p)
        rhs = (c * pow(self.y, e, self.p)) % self.p
        return lhs == rhs

    def display_message_sizes(self, c, e, s):
        c_size = (c.bit_length() + 7) // 8
        e_size = (e.bit_length() + 7) // 8
        s_size = (s.bit_length() + 7) // 8
        print(f"Size of commitment (c): {c_size} bytes")
        print(f"Size of challenge (e): {e_size} bytes")
        print(f"Size of response (s): {s_size} bytes")

def run_schnorr_protocol_sha384():
    schnorr = SchnorrProtocolSHA384()
    c = schnorr.generate_commitment()
    e = schnorr.generate_challenge(c)
    s = schnorr.generate_response(e)
    verification_result = schnorr.verify(c, e, s)
    schnorr.display_message_sizes(c, e, s)
    return verification_result

if __name__ == "__main__":
    run_schnorr_protocol_sha384()

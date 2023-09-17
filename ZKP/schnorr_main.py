import os
import hashlib
import ecdsa

# Define the elliptic curve used for the Schnorr protocol
curve = ecdsa.SECP256k1


def generate_keys():
    """
    Generate a pair of private and public keys using the defined elliptic curve.

    Returns:
        private_key (ecdsa.SigningKey): The private key.
        public_key (ecdsa.VerifyingKey): The corresponding public key.
    """
    private_key = ecdsa.SigningKey.generate(curve=curve)
    public_key = private_key.get_verifying_key()
    return private_key, public_key


def schnorr_sign(private_key, message):
    """
    Sign a given message using the Schnorr signature scheme.

    Args:
        private_key (ecdsa.SigningKey): The signer's private key.
        message (bytes): The message to be signed.

    Returns:
        tuple: The Schnorr signature (R, s).
    """
    # Generate a random nonce k
    k = ecdsa.util.randrange(curve.order)
    R = k * curve.generator
    R_x = int.from_bytes(R.x().to_bytes(32, 'big'), 'big')

    # Compute the challenge e using the hash of (R, public_key, message)
    e = int(hashlib.sha256(R_x.to_bytes(32, 'big') + private_key.get_verifying_key().to_string() + message).hexdigest(),
            16)

    # Compute the response s
    s = (k - e * private_key.privkey.secret_multiplier) % curve.order
    return (R, s)


def schnorr_verify(public_key, message, signature):
    """
    Verify a Schnorr signature for a given message.

    Args:
        public_key (ecdsa.VerifyingKey): The signer's public key.
        message (bytes): The signed message.
        signature (tuple): The Schnorr signature (R, s) to be verified.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    R, s = signature

    # Compute the challenge e using the hash of (R, public_key, message)
    e = int(hashlib.sha256(R.x().to_bytes(32, 'big') + public_key.to_string() + message).hexdigest(), 16)

    # Verify the signature using the computed challenge
    expected_R = s * curve.generator + e * ecdsa.ellipticcurve.Point(curve.curve, public_key.pubkey.point.x(),
                                                                     public_key.pubkey.point.y(), curve.order)
    return expected_R == R


def schnorr_protocol_example():
    """
    Demonstrate the Schnorr signature scheme by generating keys, signing a message, and verifying the signature.
    """
    private_key, public_key = generate_keys()
    message = b"test hallo 123123"
    signature = schnorr_sign(private_key, message)
    valid = schnorr_verify(public_key, message, signature)
    print(f"Signature is {'valid' if valid else 'invalid'}")


schnorr_protocol_example()



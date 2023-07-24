import os
import hashlib
import ecdsa

# Select curve
curve = ecdsa.SECP256k1


def generate_keys():
    private_key = ecdsa.SigningKey.generate(curve=curve)
    public_key = private_key.get_verifying_key()
    return private_key, public_key


def schnorr_sign(private_key, message):
    # Generate a random k
    k = ecdsa.util.randrange(curve.order)
    R = k * curve.generator
    R_x = int.from_bytes(R.x().to_bytes(32, 'big'), 'big')

    # Calculate e = H(R || public_key || message)
    e = int(hashlib.sha256(R_x.to_bytes(32, 'big') + private_key.get_verifying_key().to_string() + message).hexdigest(),
            16)

    # Calculate s = k - e*private_key
    s = (k - e * private_key.privkey.secret_multiplier) % curve.order
    return (R, s)


def schnorr_verify(public_key, message, signature):
    R, s = signature

    # Calculate e = H(R || public_key || message)
    e = int(hashlib.sha256(R.x().to_bytes(32, 'big') + public_key.to_string() + message).hexdigest(), 16)

    # Check if R = sG + e*public_key
    expected_R = s * curve.generator + e * ecdsa.ellipticcurve.Point(curve.curve, public_key.pubkey.point.x(),
                                                                     public_key.pubkey.point.y(), curve.order)
    return expected_R == R


def schnorr_protocol_example():
    private_key, public_key = generate_keys()
    message = b"Some generic content"
    signature = schnorr_sign(private_key, message)
    valid = schnorr_verify(public_key, message, signature)
    print(f"Signature is {'valid' if valid else 'invalid'}")


schnorr_protocol_example()
from typing import Tuple, Optional
import hashlib

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

Point = Tuple[int, int]


def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = hashlib.sha384(tag.encode()).digest()
    return hashlib.sha384(tag_hash + tag_hash + msg).digest()


def is_infinity(P: Optional[Point]) -> bool:
    return P is None


def x(P: Point) -> int:
    return P[0]


def y(P: Point) -> int:
    return P[1]


def point_add(P1: Optional[Point], P2: Optional[Point]) -> Optional[Point]:
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    if (x(P1) == x(P2)) and (y(P1) != y(P2)):
        return None
    if P1 == P2:
        lam = (3 * x(P1) * x(P1) * pow(2 * y(P1), p - 2, p)) % p
    else:
        lam = ((y(P2) - y(P1)) * pow(x(P2) - x(P1), p - 2, p)) % p
    x3 = (lam * lam - x(P1) - x(P2)) % p
    return (x3, (lam * (x(P1) - x3) - y(P1)) % p)


def point_mul(P: Optional[Point], n: int) -> Optional[Point]:
    R = None
    for i in range(256):
        if (n >> i) & 1:
            R = point_add(R, P)
        P = point_add(P, P)
    return R


def bytes_from_int(x: int) -> bytes:
    return x.to_bytes(32, byteorder="big")


def bytes_from_point(P: Point) -> bytes:
    return bytes_from_int(x(P))


def xor_bytes(b0: bytes, b1: bytes) -> bytes:
    return bytes(x ^ y for (x, y) in zip(b0, b1))


def lift_x_square_y(b: bytes) -> Optional[Point]:
    x = int_from_bytes(b)
    if x >= p:
        return None
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if pow(y, 2, p) != y_sq:
        return None
    return (x, y)


def lift_x_even_y(b: bytes) -> Optional[Point]:
    P = lift_x_square_y(b)
    if P is None:
        return None
    else:
        return (x(P), y(P) if y(P) % 2 == 0 else p - y(P))


def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")


def hash_sha384(b: bytes) -> bytes:
    return hashlib.sha384(b).digest()


def is_square(x: int) -> bool:
    return int(pow(x, (p - 1) // 2, p)) == 1


def has_square_y(P: Optional[Point]) -> bool:
    infinity = is_infinity(P)
    if infinity: return False
    assert P is not None
    return is_square(y(P))


def has_even_y(P: Point) -> bool:
    return y(P) % 2 == 0


def pubkey_gen(seckey: bytes) -> bytes:
    d0 = int_from_bytes(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    P = point_mul(G, d0)
    assert P is not None
    return bytes_from_point(P)


def schnorr_sign(msg: bytes, seckey: bytes, aux_rand: bytes) -> bytes:
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')
    d0 = int_from_bytes(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    if len(aux_rand) != 32:
        raise ValueError('aux_rand must be 32 bytes instead of %i.' % len(aux_rand))
    P = point_mul(G, d0)
    assert P is not None
    d = d0 if has_even_y(P) else n - d0
    t = xor_bytes(bytes_from_int(d), tagged_hash("BIP340/aux", aux_rand))
    k0 = int_from_bytes(tagged_hash("BIP340/nonce", t + bytes_from_point(P) + msg)) % n
    if k0 == 0:
        raise RuntimeError('Failure. This happens only with negligible probability.')
    R = point_mul(G, k0)
    assert R is not None
    k = n - k0 if not has_square_y(R) else k0
    e = int_from_bytes(tagged_hash("BIP340/challenge", bytes_from_point(R) + bytes_from_point(P) + msg)) % n
    sig = bytes_from_point(R) + bytes_from_int((k + e * d) % n)
    if not schnorr_verify(msg, bytes_from_point(P), sig):
        raise RuntimeError('The created signature does not pass verification.')
    return sig


def schnorr_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')
    if len(pubkey) != 32:
        raise ValueError('The public key must be a 32-byte array.')
    if len(sig) != 64:
        raise ValueError('The signature must be a 64-byte array.')
    P = lift_x_even_y(pubkey)
    r = int_from_bytes(sig[0:32])
    s = int_from_bytes(sig[32:64])
    if (P is None) or (r >= p) or (s >= n):
        return False
    e = int_from_bytes(tagged_hash("BIP340/challenge", sig[0:32] + pubkey + msg)) % n
    R = point_add(point_mul(G, s), point_mul(P, n - e))
    if (R is None) or (not has_square_y(R)) or (x(R) != r):
        return False
    return True


if __name__ == "__main__":
    seckey1_hex = "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"
    seckey2_hex = "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEE"
    pubkey_hex = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
    pubkey2_hex = pubkey_gen(bytes.fromhex(seckey2_hex))
    aux_rand_hex = "0000000000000000000000000000000000000000000000000000000000000001"
    msg_hex = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
    sig_hex = "0E12B8C520948A776753A96F21ABD7FDC2D7D0C0DDC90851BE17B04E75EF86A47EF0DA46C4DC4D0D1BCB8668C2CE16C54C7C23A6716EDE303AF86774917CF928"

    msg = bytes.fromhex(msg_hex)
    sig = bytes.fromhex(sig_hex)
    seckey = bytes.fromhex(seckey1_hex)
    pubkey = bytes.fromhex(pubkey_hex)
    aux_rand = bytes.fromhex(aux_rand_hex)

    sig_actual = schnorr_sign(msg, seckey, aux_rand)

    if sig == sig_actual:
        # print(' * Passed signing test.')
        pass
    else:
        print(' * Failed signing test.')
        print('   Expected signature:', sig.hex().upper())
        print('   Actual signature:', sig_actual.hex().upper())

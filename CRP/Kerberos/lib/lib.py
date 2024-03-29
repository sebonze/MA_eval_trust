import os.path
from math import gcd
from math import ceil, sqrt
from random import getrandbits
from random import randint
import itertools
import functools
import base64
from Crypto.Cipher import AES
import hashlib
import os
from ast import literal_eval


def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('{}, {} modular inverse does not exist'.format(a, m))
    else:
        return x % m


def crt(X, P):
    z = 0
    pi = functools.reduce(lambda a, b: a * b, P)
    for x_i, p_i in zip(X, P):
        p = pi / p_i
        z += x_i * modinv(p, p_i) * p
    return z % pi


def sieve(n):
    A = [True] * (n + 1)
    A[0] = False
    A[1] = False
    for i in range(2, int(sqrt(n) + 1)):
        if A[i]:
            for j in map(lambda x: i * i + i * x, range(n)):
                if j > n:
                    break
                A[j] = False
    P = []
    C = []
    for i in range(len(A)):
        if A[i]:
            P.append(i)
        else:
            C.append(i)
    return [P, C]


sieve_cache = sieve(1000)


def sieve_cache_test(n):
    for i in sieve_cache[0]:
        if n % i == 0 and n != i:
            return False
    return True


def fermat_test(n, tests):
    if n == 2:
        return True
    if n == 0 or n == 1 or n % 2 == 0:
        return False
    for d in range(tests):
        a = randint(1, n - 1)
        div = gcd(a, n)
        if div > 1:
            return False
        if pow(a, n - 1, n) != 1:
            return False
    return True


def miller_rabin_test(n, k):
    if n == 1:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False

    m = n - 1
    t = 0
    # Binary search would have better worst case, but I think this will
    # ultimately be faster bc we check for divisibility via sieve
    while True:
        try:
            q, r = divmod(m, 2)
            if r == 1:
                break
            t += 1
            m = q
        except:
            # print("{} {} {} {} {}".format(q, r, t, m, n))
            pass

    # x = a^d mod n
    # n-1 = 2^r * d
    def _possible_prime(a):
        x = pow(a, m, n)
        if x == 1 or x == n - 1:
            return True
        for i in range(t):
            x = pow(x, 2, n)
            if x == 1:
                return False
            if x == n - 1:
                return True
        return False

    for i in range(k):
        a = randint(2, n - 1)
        if not _possible_prime(a):
            return False
    return True


def isPrime(n):
    a = 100
    return sieve_cache_test(n) and fermat_test(n, a) and miller_rabin_test(n, a)


def makePrime(bits=128):
    while True:
        r = getrandbits(bits)
        if isPrime(r):
            return r


def primeFactor(n):
    primes = [2, 3]
    primefacs = []
    exp = []
    for i in range(5, n):
        if isPrime(primes, i):
            primes.append(i)
    for p in primes:
        e = 0
        while (n % p == 0):
            n = n // p
            e += 1
        if e != 0:
            primefacs.append(p)
            exp.append(e)
    return (primefacs, exp)


# Baby step giant step algorithm
def dl3(g, h, p):
    m = int(ceil(sqrt(p)))
    lis = {}
    for j in range(m):
        idx = pow(g, j, p)
        if not idx in lis:
            lis[idx] = j
    # Really should probably be a hashmap
    minv = modinv(g, p)
    inv = pow(minv, m, p)
    value = h
    for i in range(0, m):
        if value in lis:
            return (i * m + lis[value]) % p
        value = value * inv % p
    return value


def dl2(g, h, p, e, q):
    ppow = pow(p, e - 1, q)
    lgpow = pow(g, ppow, q)
    hpow = pow(h, ppow, q)
    X = dl3(lgpow, hpow, q)
    for i in range(1, e):
        gpow = pow(modinv(g, q), X, q)
        ppow = pow(p, e - i - 1, q)
        hpow = pow(h * gpow, ppow, q)
        X = X + dl3(lgpow, hpow, q) * pow(p, i, q)
    return X


def discreteLog(g, h, q):
    N = q - 1
    F = primeFactor(N)
    C = []
    P = []
    for i in range(0, len(F[0])):
        p = F[0][i]
        e = F[1][i]
        exp = N / pow(p, e, q)
        g0 = pow(g, exp, q)
        h0 = pow(h, exp, q)
        C.append(dl2(g0, h0, p, e, q))
        P.append(pow(p, e))
    return crt(C, P)


# pollard p-1 algorithm
def factor(n):
    a = 2
    for j in itertools.count(1):
        if j > n:
            return -1
        a = pow(a, j, n)
        d = gcd(a - 1, n)
        if 1 < d and d < n:
            return d


# x^e = c mod n
def rsa_crack(e, c, n):
    p = factor(n)
    q = n // p
    d = modinv(e, (p - 1) * (q - 1))
    m = pow(c, d, n)
    return m


def div(p1, m, p):
    result = [0] * len(p1)
    rest = list(p1)
    for i in range(len(p1) - 1, -1, -1):
        high = len(m) - 1
        if i - high < 0:
            break
        r = rest[i] / m[high]
        result[i - high] = r % p
        # l = [0]*len(p1)
        for j in range(len(m)):
            # l[j+i-high]=r*m[j]
            rest[j + i - high] -= (r * m[j])
            rest[j + i - high] %= p
    return rest


# removes trailing zeros
def trim(p):
    while not p[-1]:
        p.pop()
        if len(p) == 0:
            return p
    return p


def reducer(p1, m, p):
    result = p1
    trim(result)
    trim(m)
    if len(result) == 0 or len(m) == 0:
        return result
    while len(result) > len(m) - 1:
        result = div(result, m, p)
        trim(result)
    return result


def mul(p1, p2, m, p):
    result = [0] * len(p1) * len(p2)
    for i in range(len(p1)):
        for j in range(len(p2)):
            result[i + j] += (p1[i] * p2[j])
            result[i + j] %= p
    return reducer(result, m, p)


def add(p1, p2, m, p):
    result = [0] * len(p1)
    for i in range(len(p1)):
        result[i] += (p1[i] + p2[i])
        result[i] %= p
    return reducer(result, m, p)


def sub(p1, p2, m, p):
    result = []
    for i in range(len(p1)):
        result += (p1[i] - p2[i]) % p
    return reducer(result, m, p)


# e is a encryption function
def encrypt_blockchain(M, e, iv=5):
    M = map(int, M)
    C = [iv]
    for idx in range(len(M)):
        C.append(e(M[idx] ^ C[idx]))
    return C


# d is a decryption function
def decrypt_blockchain(C, d, iv=5):
    C = map(int, C)
    M = []
    for idx in range(1, len(C)):
        M.append(d(C[idx]) ^ C[idx - 1])
    return M


BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


def one_way_hash_old(value):
    # Stop using md5. Need to find a cryptographically secure one-way hah
    # that outputs 32-byte quantities, or use different symmetric-key encryption
    # to take in variable-length keys
    md = hashlib.md5()
    md.update(value.encode('utf8'))
    value_digest = md.digest()
    result = base64.b64encode(value_digest)
    return result.decode('utf8')


def one_way_hash(value):
    try:
        return base64.b64encode(hashlib.sha384(value.encode('utf8')).digest())
    except:
        return base64.b64encode(hashlib.sha384(value).digest())


def encrypt(txt, key):
    txt = str(txt)

    # try:
    #    key = key.decode("utf8")
    # except:
    #    key = str(key)

    if key[0] == "b" and key[1] == "'" and key[len(key) - 1] == key[1]:
        key = key[2:66]

    key = one_way_hash(key)
    # key = str(key)
    txt = pad(txt).encode("utf8")
    # key = pad(key)
    iv = os.urandom(16)[0:16]
    cipher = AES.new(key[:32], AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(txt))


def decrypt(enc, key):
    try:
        if chr(enc[0]) == "b" and chr(enc[1]) == "'" and chr(enc[len(enc) - 1]) == ")" and chr(
                enc[len(enc) - 2]) == "'":
            enc = enc[2:90]
    except:
        # print("debug 1")
        pass

    try:
        if chr(enc[0]) == "(" and chr(enc[1]) == "b" and chr(enc[len(enc) - 1]) == ")" and chr(
                enc[len(enc) - 2]) == ",":
            enc = enc[3:47]
    except:
        # print("debug 7")
        pass

    try:
        if enc[0] == "(" and enc[1] == "b" and enc[len(enc) - 1] == "," and enc[len(enc) - 2] == '\'':
            enc = enc[3:155]
    except:
        # print("debug 2")
        pass

    try:
        key = key.decode("utf8")
    except:
        key = str(key)
    # try:
    #    if key[0] == "b" and key[1] == '\'' and key[len(key)-1] == '\'':
    #        key = key[2:38]
    # except:
    #    print("debug 6")
    key = one_way_hash(key)
    # key = str(key)
    # key = pad(key)
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(key[:32], AES.MODE_CBC, iv)
    dec = cipher.decrypt(enc[16:])
    if unpad(dec) == b'':
        # print("debug 4")
        return dec
    return unpad(dec)


def encrypt_tuple(txt, key):
    encr = encrypt(str(txt), key)
    return encr


def decrypt_tuple(txt, key):
    decr = decrypt(txt, key)
    try:
        return literal_eval(decr.decode())
    except:
        # print("debug 3")
        pass

    try:
        return literal_eval(decr)
    except:
        # print("debug 5")
        pass
    return decr

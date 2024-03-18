
import sys

from cryptography import x509

from datetime import datetime, timedelta
import os
import time


from cryptography.x509 import load_pem_x509_certificate, ocsp

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


from Crypto.Hash import CMAC
from Crypto.Cipher import AES
import datetime
import random
import uuid


from .pki_util import generate_private_key, generate_ca_certificate, load_ca_private_key_and_cert, issue_certificate, \
    validate_certificate, revoke_certificate, is_certificate_revoked, get_size


def pki_routine(c_init=100):
    msg_hex = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
    msg = bytes.fromhex(msg_hex)
    pki_prep_t = []
    pki_sign_t = []
    pki_verify_t = []

    # Directory setup
    os.makedirs("tmp_cert", exist_ok=True)

    for c in range(c_init):
        start_time = time.perf_counter_ns()
        # Generate CA private key and save it
        ca_private_key, ca_private_key_pem = generate_private_key(password="mysecurepassword")

        with open("tmp_cert/ca_private_key.pem", "wb") as f:
            f.write(ca_private_key_pem)

        # Generate CA certificate and save it
        ca_cert_pem = generate_ca_certificate(ca_private_key)
        with open("tmp_cert/ca_certificate.pem", "wb") as f:
            f.write(ca_cert_pem)

        pki_prep_t.append(time.perf_counter_ns() - start_time)
        print(str(sys.getsizeof(ca_private_key) + sys.getsizeof(ca_private_key_pem) + sys.getsizeof(
            ca_cert_pem)) + ' bytes PKI')
        print(str(sys.getsizeof(ca_private_key_pem) + sys.getsizeof(msg)) + ' bytes PKI new min')

    # Load CA private key and certificate
    ca_private_key, ca_certificate = load_ca_private_key_and_cert()
    entity_name = "entity1"

    for c in range(c_init):
        start_time = time.perf_counter_ns()

        # Issue a certificate and save it

        entity_private_key, entity_certificate_pem = issue_certificate(entity_name, ca_private_key, ca_certificate)
        with open(f"tmp_cert/{entity_name}_certificate.pem", "wb") as f:
            f.write(entity_certificate_pem)

        pki_sign_t.append(time.perf_counter_ns() - start_time)
        print(str(sys.getsizeof(entity_private_key) + sys.getsizeof(entity_certificate_pem)) + ' bytes PKI')

    # Load the issued certificate
    with open(f"tmp_cert/{entity_name}_certificate.pem", "rb") as f:
        entity_certificate = x509.load_pem_x509_certificate(f.read())
    print(str(sys.getsizeof(entity_certificate)) + ' bytes PKI')
    for c in range(c_init):
        start_time = time.perf_counter_ns()

        # Validate the issued certificate
        is_valid = validate_certificate(entity_certificate, ca_certificate)

        pki_verify_t.append(time.perf_counter_ns() - start_time)
        print(str(sys.getsizeof(entity_certificate) + sys.getsizeof(ca_certificate)) + ' bytes PKI')
    # Revoke the certificate and save CRL
    crl_pem = revoke_certificate(entity_certificate, ca_private_key, ca_certificate)
    with open("tmp_cert/crl.pem", "wb") as f:
        f.write(crl_pem)

    # Load CRL
    with open("tmp_cert/crl.pem", "rb") as f:
        crl = x509.load_pem_x509_crl(f.read())

    # Check revocation status
    is_revoked = is_certificate_revoked(entity_certificate, crl)
    # print("Certificate is revoked:", is_revoked)

    return [pki_prep_t, pki_sign_t, pki_verify_t]


# -------------------------------------------------------------------------------------------------

def build_OCSPresponse(id):

    f = open("tmp_cert/entity1_certificate.pem", "rb")
    cert = f.read()
    f.close()
    cert = load_pem_x509_certificate(cert)

    # open issuer cert
    f = open("tmp_cert/ca_certificate.pem", 'rb')
    issuer_cert = f.read()
    f.close()
    responder_cert = load_pem_x509_certificate(issuer_cert)
    f = open("tmp_cert/ca_private_key.pem", 'rb')
    issuer_priv_key = f.read()
    f.close()
    responder_key = serialization.load_pem_private_key(issuer_priv_key, b'mysecurepassword')

    builder = ocsp.OCSPResponseBuilder()
    builder = builder.add_response(
        cert=cert, issuer=responder_cert, algorithm=hashes.SHA256(),
        cert_status=ocsp.OCSPCertStatus.GOOD,
        this_update=datetime.datetime.now(),
        next_update=datetime.datetime.now(),
        revocation_time=None, revocation_reason=None
    ).responder_id(
        ocsp.OCSPResponderEncoding.HASH, responder_cert
    )

    response = builder.sign(responder_key, hashes.SHA384())
    serialized_response = response.public_bytes(serialization.Encoding.DER)

    return serialized_response
def generate_mac(key, message):
    cobj = CMAC.new(key, ciphermod=AES)
    cobj.update(message.encode())
    return cobj.digest()


def verify_MAC(key, msg, MACtag, mac_len=16):
    cobj = CMAC.new(key, ciphermod=AES, mac_len=mac_len)
    cobj.update(msg)

    try:
        cobj.verify(MACtag)
        return True
    except ValueError:
        return False


def generate_nonce():
    seed = uuid.uuid4().hex + uuid.uuid1().hex
    nonce = ''
    while len(nonce) < 12:
        nonce += random.choice(seed)
    return bytes(nonce, 'utf-8')


def sign_message(private_key, message):
    return private_key.sign(message.encode(), ec.ECDSA(hashes.SHA384()))


# Protocol implementation starts here
# UA = 28 bit, SAC = 12 bit identifiers, P_AS sidn ECDH pub key, N = 64 bit nonce, sigma = ECDSA signature, MAC = 128bit MAC tag
class LDACSAuthenticationProtocol:
    def __init__(self):
        self.private_key_GS = generate_private_key()
        self.private_key_AS = generate_private_key()
        self.kM = os.urandom(16)  # Shared MAC key for demonstration purposes
        self.P_GS = self.private_key_GS[1]
        self.P_AS = self.private_key_AS[1]
        self.N_GS = generate_nonce()
        self.N_AS = generate_nonce()
        # Real values for simulation/testing
        self.UA_GS = random.getrandbits(28)
        self.UA_AS = random.getrandbits(28)
        self.SAC_GS = random.getrandbits(12)
        self.SAC_AS = random.getrandbits(12)

        self.sigma_AS = None
        self.t_AS = None
        self.sigma_GS = None
        self.t_GS = None

    def step1(self):
        # GS to AS: Send P_GS and N_GS
        return {"P_GS": self.P_GS, "N_GS": self.N_GS}

    def step2(self, P_GS, N_GS):
        # AS to GS: Respond with P_AS, N_AS, sigma_AS (signature), and t_AS (MAC)
        message = f"{self.P_AS}{P_GS}{self.UA_GS}{self.SAC_GS}{self.N_AS}"
        sigma_AS = sign_message(self.private_key_AS[0], message)
        t_AS = generate_mac(self.kM, message)
        return {"P_AS": self.P_AS, "N_AS": self.N_AS, "sigma_AS": sigma_AS, "t_AS": t_AS}

    def step3(self, P_AS, N_AS, sigma_AS, t_AS):
        # GS to AS: Send OCSP_Cert_GS , Cert_GS , sigma_GS (signature), and t_GS (MAC)
        message = f"{self.P_GS}{P_AS}{self.UA_AS}{self.SAC_AS}{self.N_GS}"
        sigma_GS = sign_message(self.private_key_GS[0], message)
        t_GS = generate_mac(self.kM, message)
        OCSP_Cert_GS = build_OCSPresponse(self.UA_GS)
        Cert_GS = load_pem_x509_certificate(generate_ca_certificate(self.private_key_GS[0]))
        return {"OCSP_Cert_GS": OCSP_Cert_GS, "Cert_GS": Cert_GS, "sigma_GS": sigma_GS, "t_GS": t_GS}


def display_message_sizes(s1, s2, s3):
    s1_size = get_size(s1)
    s2_size = get_size(s2)
    s3_size = get_size(s3)
    print(f"Size of step 1 (c): {s1_size} bytes")
    print(f"Size of step 2 (e): {s2_size} bytes")
    print(f"Size of step 3 (s): {s3_size} bytes")


def run_pki_protocol_sha384(c_init):
    pki_prep_t = []
    pki_s2_t = []
    pki_s3_t = []

    for c in range(c_init):
        start_time = time.perf_counter_ns()
        pki = LDACSAuthenticationProtocol()
        s1 = pki.step1()
        pki_prep_t.append(time.perf_counter_ns() - start_time)

    for c in range(c_init):
        start_time = time.perf_counter_ns()
        s2 = pki.step2(pki.P_GS, pki.N_GS)
        pki_s2_t.append(time.perf_counter_ns() - start_time)

    for c in range(c_init):
        start_time = time.perf_counter_ns()
        s3 = pki.step3(pki.P_AS, pki.N_AS, pki.sigma_AS, pki.t_AS)
        pki_s3_t.append(time.perf_counter_ns() - start_time)

    display_message_sizes(s1, s2, s3)
    print("PKI protocol completed.")

    return [pki_prep_t, pki_s2_t, pki_s3_t]


# Main routine
if __name__ == "__main__":
    run_pki_protocol_sha384(10)


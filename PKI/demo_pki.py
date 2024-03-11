import hashlib
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature
from datetime import datetime, timedelta
import os
import time

from cryptography.exceptions import InvalidSignature
from cryptography.x509 import load_pem_x509_certificate, ocsp
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import algorithms

from Crypto.Hash import CMAC
from Crypto.Cipher import AES
import datetime
import random
import uuid
import binascii
import sys


# Function to generate a private key
def generate_private_key(password=None):
    key = ec.generate_private_key(ec.SECP256K1())
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode())
    else:
        encryption = serialization.NoEncryption()
    return key, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)


def sha384(b: bytes) -> bytes:
    return hashlib.sha384(b).digest()


# Function to generate a self-signed CA certificate
def generate_ca_certificate(private_key):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"DE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"BAVARIA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"DEISENHOFEN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ASD DLR"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"TEST Root CA"),
    ])

    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=10 * 365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(private_key, hashes.SHA256())

    return ca_cert.public_bytes(serialization.Encoding.PEM)


# Load CA private key and certificate
def load_ca_private_key_and_cert():
    with open("tmp_cert/ca_private_key.pem", "rb") as key_file:
        ca_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=b'mysecurepassword'
        )

    with open("tmp_cert/ca_certificate.pem", "rb") as cert_file:
        ca_certificate = x509.load_pem_x509_certificate(cert_file.read())

    return ca_private_key, ca_certificate


# Function to issue a certificate
def issue_certificate(subject_name, ca_private_key, ca_certificate):
    private_key = ec.generate_private_key(ec.SECP256K1())

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"DE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"BAVARIA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"DEISENHOFEN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ASD DLR"),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_certificate.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).sign(ca_private_key, hashes.SHA256())

    return private_key, cert.public_bytes(serialization.Encoding.PEM)


# Function to validate a certificate
def validate_certificate(certificate, ca_certificate):
    try:
        ca_public_key = ca_certificate.public_key()
        ca_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        return False


# Function to revoke a certificate
def revoke_certificate(certificate, ca_private_key, ca_certificate):
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_certificate.subject)
    builder = builder.last_update(datetime.utcnow())
    builder = builder.next_update(datetime.utcnow() + timedelta(days=30))
    builder = builder.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(
        certificate.serial_number
    ).revocation_date(
        datetime.utcnow()
    ).build())

    crl = builder.sign(
        private_key=ca_private_key,
        algorithm=hashes.SHA256()
    )
    return crl.public_bytes(serialization.Encoding.PEM)


# Function to check revocation status
def is_certificate_revoked(certificate, crl):
    for revoked_cert in crl:
        if revoked_cert.serial_number == certificate.serial_number:
            return True
    return False


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
        self.UA_GS = 'GroundStationIdentifier'
        self.UA_AS = 'AircraftStationIdentifier'
        self.SAC_GS = 'GS_ServiceAccessCredential'
        self.SAC_AS = 'AS_ServiceAccessCredential'

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
        # GS to AS: Send OCSP_Cert_GS (dummy), Cert_GS (dummy), sigma_GS (signature), and t_GS (MAC)
        message = f"{self.P_GS}{P_AS}{self.UA_AS}{self.SAC_AS}{self.N_GS}"
        sigma_GS = sign_message(self.private_key_GS[0], message)
        t_GS = generate_mac(self.kM, message)
        OCSP_Cert_GS = "OCSP_CERT_DUMMY"
        Cert_GS = "CERT_GS_DUMMY"
        return {"OCSP_Cert_GS": OCSP_Cert_GS, "Cert_GS": Cert_GS, "sigma_GS": sigma_GS, "t_GS": t_GS}


def display_message_sizes(s1, s2, s3):
    s1_size = sys.getsizeof(s1)
    s2_size = sys.getsizeof(s2)
    s3_size = sys.getsizeof(s3)
    print(f"Size of step 1 (c): {s1_size} bytes")
    print(f"Size of step 2 (e): {s2_size} bytes")
    print(f"Size of step 3 (s): {s3_size} bytes")


def run_pki_protocol_sha384(c_init=1):
    pki_prep_t = []
    pki_s2_t = []
    pki_s3_t = []

    start_time = time.perf_counter_ns()
    pki = LDACSAuthenticationProtocol()
    s1 = pki.step1()
    pki_prep_t.append(time.perf_counter_ns() - start_time)

    start_time = time.perf_counter_ns()
    s2 = pki.step2(pki.P_GS, pki.N_GS)
    pki_s2_t.append(time.perf_counter_ns() - start_time)

    start_time = time.perf_counter_ns()
    s3 = pki.step3(pki.P_AS, pki.N_AS, pki.sigma_AS, pki.t_AS)
    pki_s3_t.append(time.perf_counter_ns() - start_time)

    display_message_sizes(s1, s2, s3)
    print("PKI protocol completed.")

    return [pki_prep_t, pki_s2_t, pki_s3_t]


# Main routine
if __name__ == "__main__":
    run_pki_protocol_sha384()


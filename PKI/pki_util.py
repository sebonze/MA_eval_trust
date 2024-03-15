import hashlib
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import datetime
import sys

def get_size(obj, seen=None):
    """Recursively finds size of objects"""
    size = sys.getsizeof(obj)
    if seen is None:
        seen = set()
    obj_id = id(obj)
    if obj_id in seen:
        return 0
    # Important mark as seen *before* entering recursion to gracefully handle
    # self-referential objects
    seen.add(obj_id)
    if isinstance(obj, dict):
        size += sum([get_size(v, seen) for v in obj.values()])
        size += sum([get_size(k, seen) for k in obj.keys()])
    elif hasattr(obj, '__dict__'):
        size += get_size(obj.__dict__, seen)
    elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes, bytearray)):
        size += sum([get_size(i, seen) for i in obj])
    return size

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
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + timedelta(days=10 * 365)
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

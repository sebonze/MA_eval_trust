from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature
from datetime import datetime, timedelta
import os


# Function to generate a private key
def generate_private_key(password=None):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode())
    else:
        encryption = serialization.NoEncryption()
    return key, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)


# Function to generate a self-signed CA certificate
def generate_ca_certificate(private_key):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"MyCompany Root CA"),
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
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
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
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
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

def pki_routine():
    # Directory setup
    os.makedirs("tmp_cert", exist_ok=True)

    # Generate CA private key and save it
    ca_private_key, ca_private_key_pem = generate_private_key(password="mysecurepassword")
    with open("tmp_cert/ca_private_key.pem", "wb") as f:
        f.write(ca_private_key_pem)

    # Generate CA certificate and save it
    ca_cert_pem = generate_ca_certificate(ca_private_key)
    with open("tmp_cert/ca_certificate.pem", "wb") as f:
        f.write(ca_cert_pem)

    # Load CA private key and certificate
    ca_private_key, ca_certificate = load_ca_private_key_and_cert()

    # Issue a certificate and save it
    entity_name = "entity1"
    entity_private_key, entity_certificate_pem = issue_certificate(entity_name, ca_private_key, ca_certificate)
    with open(f"tmp_cert/{entity_name}_certificate.pem", "wb") as f:
        f.write(entity_certificate_pem)

    # Load the issued certificate
    with open(f"tmp_cert/{entity_name}_certificate.pem", "rb") as f:
        entity_certificate = x509.load_pem_x509_certificate(f.read())

    # Validate the issued certificate
    is_valid = validate_certificate(entity_certificate, ca_certificate)
    #print("Certificate is valid:", is_valid)

    # Revoke the certificate and save CRL
    crl_pem = revoke_certificate(entity_certificate, ca_private_key, ca_certificate)
    with open("tmp_cert/crl.pem", "wb") as f:
        f.write(crl_pem)

    # Load CRL
    with open("tmp_cert/crl.pem", "rb") as f:
        crl = x509.load_pem_x509_crl(f.read())

    # Check revocation status
    is_revoked = is_certificate_revoked(entity_certificate, crl)
    #print("Certificate is revoked:", is_revoked)
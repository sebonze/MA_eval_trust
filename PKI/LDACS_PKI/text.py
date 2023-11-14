import parameters
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

f = open("./parameters/LDACS-GS_sl1.pem", 'rb')
cert = f.read()
f.close()
cert = load_pem_x509_certificate(cert)
# open issuer cert
f = open("./parameters/LDACS-sub-CA.pem", 'rb')
issuer_cert = f.read()
f.close()
responder_cert = load_pem_x509_certificate(issuer_cert)
f = open("./parameters/LDACS-sub-CA-private-key.pem", 'rb')
issuer_priv_key = f.read()
f.close()
responder_key = serialization.load_pem_private_key(issuer_priv_key, None)
# open OCSP builder
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
if parameters.SECURITY_LEVEL == 0:
    response = builder.sign(responder_key, hashes.SHA256())
elif parameters.SECURITY_LEVEL == 1:
    response = builder.sign(responder_key, hashes.SHA384())
# now we need to serialize this response
serialized_response = response.public_bytes(serialization.Encoding.DER)

print(serialized_response)
print(len(serialized_response))
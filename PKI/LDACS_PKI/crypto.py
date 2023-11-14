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

# crypto module - !!!DO NOT USE in operational environment!!!
# Copyright DLR e.V. by Nils Mäurer 2022
# Please note only Security Level 1 and 2 are implemented

class make_details:
    def __init__(self, private_own_ec_key, public_other_ec_key, nonce_gs, nonce_as, ua_gs, ua_as, sac_gs, sac_as, scgs, EPLDACS, CCLDACS, algo, kM, kKEK):
        self.private_own_ec_key = private_own_ec_key
        self.public_other_ec_key = public_other_ec_key
        self.nonce_gs = nonce_gs
        self.nonce_as = nonce_as
        self.ua_gs = ua_gs
        self.ua_as = ua_as
        self.sac_gs = sac_gs
        self.sac_as = sac_as
        self.scgs = scgs
        self.EPLDACS = EPLDACS
        self.CCLDACS = CCLDACS
        self.algo = algo
        self.kM = kM
        self.kKEK = kKEK

# --- helper
def bytelify(data):
    if not isinstance(data, str):
        data = str(data)
    return bytes(data, 'utf-8')

def generate_ec_key_pairs():
    if parameters.SECURITY_LEVEL == 0:
        private_key = ec.generate_private_key(ec.SECP256K1())
        public_key = private_key.public_key()
    elif parameters.SECURITY_LEVEL == 1:
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
    return private_key, public_key

def generate_nonce():
    seed = uuid.uuid4().hex + uuid.uuid1().hex
    nonce = ''
    if parameters.SECURITY_LEVEL == 0:
        while len(nonce) < 12:
            nonce += random.choice(seed)
    elif parameters.SECURITY_LEVEL == 1:
        while len(nonce) < 16:
            nonce += random.choice(seed)
    """
    elif parameters.SECURITY_LEVEL == 2:
        while len(nonce) < 16:
            nonce += random.choice(seed)
    elif parameters.SECURITY_LEVEL == 3:
        while len(nonce) < 32:
            nonce += random.choice(seed)
    """
    return bytes(nonce, 'utf-8')

def generate_Kset():
    seed = uuid.uuid4().hex + uuid.uuid1().hex
    all_key = ''
    if parameters.SECURITY_LEVEL == 0:
        size = 48
        while len(all_key) < size:
            all_key += random.choice(seed)
        all_key = bytes(all_key, 'utf-8')
        kBC = all_key[:16]
        kCC = all_key[16:32]
        kvoice = all_key[32:]
    elif parameters.SECURITY_LEVEL == 1:
        size = 96
        while len(all_key) < size:
            all_key += random.choice(seed)
        all_key = bytes(all_key, 'utf-8')
        kBC = all_key[:32]
        kCC = all_key[32:64]
        kvoice = all_key[64:]
    
    return kBC, kCC, kvoice
    
def derive_keys(idA, idB, nonceA, nonceB, shared_key):
    salt = nonceA + nonceB
    info = b"Keys for " + nonceA + b" and " + nonceB
    if parameters.SECURITY_LEVEL == 0:
        # 4 times 16 byte
        size = 64
        all_key = HKDF(algorithm=hashes.SHA256(), length=size, salt=salt, info=info).derive(shared_key)
        kAS_GS = all_key[:16]
        kM = all_key[16:32]
        kDC = all_key[32:48]
        kKEK = all_key[48:]
    elif parameters.SECURITY_LEVEL == 1:
        # 4 times 32 byte
        size = 128
        all_key = HKDF(algorithm=hashes.SHA256(), length=size, salt=salt, info=info).derive(shared_key)
        kAS_GS = all_key[:32]
        kM = all_key[32:64]
        kDC = all_key[64:96]
        kKEK = all_key[96:]

    return kAS_GS, kM, kDC, kKEK

def sign_message(msg, id):
    if parameters.SECURITY_LEVEL == 0:
        if id == "AS":
            f = open("./parameters/LDACS-AS-private-key_sl1.pem", 'rb')
        else:
            f = open("./parameters/LDACS-GS-private-key_sl1.pem", 'rb')
        keydata = f.read()
        f.close()
        private_key = serialization.load_pem_private_key(keydata, password=None)
        signature = private_key.sign(msg, ec.ECDSA(hashes.SHA256()))
    elif parameters.SECURITY_LEVEL == 1:
        if id == "AS":
            f = open("./parameters/LDACS-AS-private-key_sl2.pem", 'rb')
        else:
            f = open("./parameters/LDACS-GS-private-key_sl2.pem", 'rb')
        keydata = f.read()
        f.close()
        private_key = serialization.load_pem_private_key(keydata, password=None)
        signature = private_key.sign(msg, ec.ECDSA(hashes.SHA384()))
    else:
        return -1
    return signature

def verify_message(msg, sig, id):
    if parameters.SECURITY_LEVEL == 0:
        if id == "AS":
            f = open("./parameters/LDACS-AS_sl1.pem", 'rb')
        else:
            f = open("./parameters/LDACS-GS_sl1.pem", 'rb')
        cert = f.read()
        f.close()
        cert = load_pem_x509_certificate(cert)
        public_key = cert.public_key()
        try:
            public_key.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False
    elif parameters.SECURITY_LEVEL == 1:
        if id == "AS":
            f = open("./parameters/LDACS-AS_sl2.pem", 'rb')
        else:
            f = open("./parameters/LDACS-GS_sl2.pem", 'rb')
        cert = f.read()
        f.close()
        cert = load_pem_x509_certificate(cert)
        public_key = cert.public_key()
        try:
            public_key.verify(sig, msg, ec.ECDSA(hashes.SHA384()))
            return True
        except InvalidSignature:
            return False
    else:
        return False

def build_OCSPresponse(id):
    """
        Function to generate an OCSP response for the certificate of 'id' hence AS or GS.
        Please note that issuer and responder are the same in our case for simplifaction.
    """
    if parameters.SECURITY_LEVEL == 0:
        if id == "AS":
            f = open("./parameters/LDACS-AS_sl1.pem", 'rb')
        else:
            f = open("./parameters/LDACS-GS_sl1.pem", 'rb')
    elif parameters.SECURITY_LEVEL == 1:
        if id == "AS":
            f = open("./parameters/LDACS-AS_sl2.pem", 'rb')
        else:
            f = open("./parameters/LDACS-GS_sl2.pem", 'rb')

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
    return serialized_response

def verify_OCSPResponse(serialized_response):
    ocsp_resp = ocsp.load_der_ocsp_response(serialized_response)
    f = open("./parameters/LDACS-sub-CA.pem", 'rb')
    responder_cert = f.read()
    f.close()
    responder_cert = load_pem_x509_certificate(responder_cert)
    public_key = responder_cert.public_key()
    # "tbs_response_bytes": This data may be used to validate the signature on the OCSP response.
    try:
        if parameters.SECURITY_LEVEL == 0:
            public_key.verify(ocsp_resp.signature, ocsp_resp.tbs_response_bytes, ec.ECDSA(hashes.SHA256()))
        elif parameters.SECURITY_LEVEL == 1:
            public_key.verify(ocsp_resp.signature, ocsp_resp.tbs_response_bytes, ec.ECDSA(hashes.SHA384()))
        # check whether the certificate is actually still valid (status is GOOD)
        if str(ocsp_resp.certificate_status) == 'OCSPCertStatus.GOOD':
            return True
        else:
            return False
    except InvalidSignature:
        return False

# --- generate_MAC, verify_MAC, encrypt_data, decrypt_data use pyCryptodome due to flexibility in the implementation
def generate_MAC(key, msg, mac_len=16):
    cobj = CMAC.new(key, ciphermod=AES, mac_len=mac_len)
    cobj.update(msg)
    MACtag = cobj.digest()
    return MACtag

def verify_MAC(key, msg, MACtag, mac_len=16):
    cobj = CMAC.new(key, ciphermod=AES, mac_len=mac_len)
    cobj.update(msg)

    try:
        cobj.verify(MACtag)
        return True
    except ValueError:
        return False

def encrypt_data(key, msg):
    cipher = AES.new(key, AES.MODE_CCM)
    ciphertext, MACtag = cipher.encrypt_and_digest(msg)
    nonce = cipher.nonce
    return nonce, ciphertext, MACtag

def decrypt_data(key, msg, MACtag, nonce):
    try:
        cipher = AES.new(key, AES.MODE_CCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(msg, MACtag)
        return plaintext
    except (ValueError, KeyError):
        return b'-1'
    
def build_shke():
    private_gs_ec_key, public_gs_ec_key = generate_ec_key_pairs()
    nonce_gs = generate_nonce()
    # we need a serialized key for transmission!
    serialized_gs_ec_public_key = public_gs_ec_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )

    shke = serialized_gs_ec_public_key + nonce_gs
    # private key can remain in ECHazmatFormat since we (GS) store it
    # store private_gs_ec_key, nonce_gs and send shke
    return private_gs_ec_key, nonce_gs, shke

def select_algo_from_EPLDACS(EPLDACS):
    # EPLDACS is 16 byte with 8 pairs of 2 byte
    choice = random.randint(0,7)
    algo = EPLDACS[choice*2:choice*2+2]
    return algo

def build_chke(shke, ua_as, ua_gs, sac_gs, EPLDACS, scgs):
    private_as_ec_key, public_as_ec_key = generate_ec_key_pairs()
    nonce_as = generate_nonce()
    serialized_public_gs_ec_key = b''
    nonce_gs = b''
    if parameters.SECURITY_LEVEL == 0:
        serialized_public_gs_ec_key = shke[:-12]
        nonce_gs = shke[-12:]
        # now regenerate gs public key as ellipticCurve hazmat format again
        deserialized_public_gs_ec_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), serialized_public_gs_ec_key)
    elif parameters.SECURITY_LEVEL == 1: # or parameters.SECURITY_LEVEL == 2:
        serialized_public_gs_ec_key = shke[:-16]
        nonce_gs = shke[-16:]
        # now regenerate gs public key as ellipticCurve hazmat format again
        deserialized_public_gs_ec_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), serialized_public_gs_ec_key)
    """
    elif parameters.SECURITY_LEVEL == 3:
        public_gs_ec_key = shke[:-32]
        nonce_gs = shke[-32:]
        deserialized_public_gs_ec_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP521K1(), serialized_public_gs_ec_key)
    """
    # now generate keys
    shared_key = private_as_ec_key.exchange(ec.ECDH(), deserialized_public_gs_ec_key)
    kAS_GS, kM, kDC, kKEK = derive_keys(ua_as, ua_gs, nonce_as, nonce_gs, shared_key)
    # serialize own public key
    serialized_public_as_ec_key = public_as_ec_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )
    if parameters.SECURITY_ENCRYPT:
        algo = b'01'
    else:
        algo = b'00'
    # generate overall message
    # print("kM:", kM)
    # print("m_AS:", serialized_public_as_ec_key, serialized_public_gs_ec_key, ua_gs, sac_gs, scgs, algo, nonce_as)
    m_AS = serialized_public_as_ec_key + serialized_public_gs_ec_key + ua_gs + sac_gs + scgs + algo + nonce_as
    # generate MAC tag
    tag_m_AS = generate_MAC(kM, m_AS)
    # print("tag_m_AS:", tag_m_AS)
    # generate signature
    sign_AS = sign_message(m_AS, "AS")
    # print("m_AS", m_AS)
    # build chke
    # print("AS CHKE", algo, serialized_public_as_ec_key, nonce_as, tag_m_AS, sign_AS)
    # please note that we build tag then sign even though diss uses it other way round.
    # we do this since tag length is fixed, signature ot necessarily due to encoding
    chke = algo + serialized_public_as_ec_key + nonce_as + tag_m_AS + sign_AS
    # store kAS_GS, kM, kDC, kKEK, deserialized_public_gs_ec_key and send chke
    return private_as_ec_key, deserialized_public_gs_ec_key, nonce_gs, kAS_GS, kM, kDC, kKEK, chke

# KAM-7 uses first signature then MAC
def build_skef(chke, private_gs_ec_key, nonce_gs, ua_as, ua_gs, sac_gs, sac_as, scgs, kBC, kCC, kvoice, EPLDACS, CCLDACS):
    serialized_public_as_ec_key = b''
    nonce_as = b''
    # recreate algo field
    algo = chke[0:2]
    # please note that we build tag then sign even though diss uses it other way round.
    # we do this since tag length is fixed, signature ot necessarily due to encoding
    if parameters.SECURITY_LEVEL == 0:
        serialized_public_as_ec_key = chke[2:35]
        nonce_as = chke[35:47]
        tag_m_AS = chke[47:63]
        sign_AS = chke[63:]
        # now regenerate gs public key as ellipticCurve hazmat format again
        deserialized_public_as_ec_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), serialized_public_as_ec_key)
    elif parameters.SECURITY_LEVEL == 1: # or parameters.SECURITY_LEVEL == 2:
        serialized_public_as_ec_key = chke[2:51]
        nonce_as = chke[51:67]
        tag_m_AS = chke[67:83]
        sign_AS = chke[83:]
        # now regenerate gs public key as ellipticCurve hazmat format again
        deserialized_public_as_ec_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), serialized_public_as_ec_key)
    # print("GS CHKE", algo, serialized_public_as_ec_key, nonce_as, tag_m_AS, sign_AS)
    # generate keys
    shared_key = private_gs_ec_key.exchange(ec.ECDH(), deserialized_public_as_ec_key)
    kAS_GS, kM, kDC, kKEK = derive_keys(ua_as, ua_gs, nonce_as, nonce_gs, shared_key)
    # get OCSP response for AS certificate
    OCSPresponse_AS = build_OCSPresponse("AS")
    # verify validity of OCSP response
    # print("verify validity of OCSP response")
    if not verify_OCSPResponse(OCSPresponse_AS):
        return -1, -1, -1
    # recreate and serialize own public key
    deserialized_public_gs_ec_key = private_gs_ec_key.public_key()
    serialized_public_gs_ec_key = deserialized_public_gs_ec_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )
    # prepare m_AS'
    m_AS_v = serialized_public_as_ec_key + serialized_public_gs_ec_key + ua_gs + sac_gs + scgs + algo + nonce_as
    # print("m_AS_v", m_AS_v)
    # verify AS signature
    # print("verify AS signature")
    if not verify_message(m_AS_v, sign_AS, 'AS'):
        # print("Wrong signature.")
        return -1, -1, -1
    # verify AS MAC tag
    #print("verify AS MAC tag")
    if not verify_MAC(kM, m_AS_v, tag_m_AS):
        # print("Wrong MAC")
        return -1, -1, -1

    # AS successfully authenticated to GS
    kset = kBC + kCC + kvoice
    c_nonce, c_kset, tag_c_kset = encrypt_data(kKEK, kset)

    # prepare m_GS
    # print("GS m_GS:", serialized_public_gs_ec_key, serialized_public_as_ec_key, ua_as, sac_as, EPLDACS, CCLDACS, nonce_gs, c_nonce, c_kset, tag_c_kset)
    m_GS = serialized_public_gs_ec_key + serialized_public_as_ec_key + ua_as + sac_as + EPLDACS + CCLDACS + nonce_gs + c_nonce + c_kset + tag_c_kset
    # generate MAC tag
    tag_m_GS = generate_MAC(kM, m_GS)
    # generate signature
    sign_GS = sign_message(m_GS, "GS")
    # since we have the issue here that the signature can be 71 or 72 byte long for sl1 we add a length field JUST at the beginning here
    len_sign_GS = bytes(str(len(sign_GS)), 'utf-8')

    # build skef
    OCSPresponse_GS = build_OCSPresponse("GS")
    len_OCSPresponse_GS = bytes(str(len(OCSPresponse_GS)), 'utf-8')
    # please note that we build tag then sign even though diss uses it other way round.
    # we do this since tag length is fixed, signature ot necessarily due to encoding
    skef = c_nonce + c_kset + tag_c_kset + tag_m_GS + len_sign_GS + sign_GS + len_OCSPresponse_GS + OCSPresponse_GS
    # scgs is in bytes here --> convert to int
    scgs = int(scgs)
    if not scgs:
        if parameters.SECURITY_LEVEL == 0:
            f = open("./parameters/LDACS-GS_sl1.pem", 'rb')
        elif parameters.SECURITY_LEVEL == 1:
            f = open("./parameters/LDACS-GS_sl2.pem", 'rb')
        gs_cert = f.read()
        f.close()
        len_gs_cert = bytes(str(len(gs_cert)), 'utf-8')
        skef += len_gs_cert + gs_cert
    # store kAS_GS, kDC and send skef
    # if not scgs:
    #     print("GS SKEF:", c_nonce, c_kset, tag_c_kset, tag_m_GS, len_sign_GS, sign_GS, len_OCSPresponse_GS, OCSPresponse_GS, len_gs_cert , gs_cert)
    # else:
    #     print("GS SKEF:", c_nonce, c_kset, tag_c_kset, tag_m_GS, len_sign_GS, sign_GS, len_OCSPresponse_GS, OCSPresponse_GS)
    return kAS_GS, kDC, skef

def process_skef(skef, public_as_ec_key, public_gs_ec_key, ua_as, sac_as, EPLDACS, CCLDACS, nonce_gs, scgs, kM, kKEK):
    # please note that we build tag then sign even though diss uses it other way round.
    # we do this since tag length is fixed, signature ot necessarily due to encoding
    # c_nonce is 11 byte long
    c_nonce = skef[0:11]
    if parameters.SECURITY_LEVEL == 0:
        # three keys à 16 byte aka 48 byte
        c_kset = skef[11:59]
        tag_c_kset = skef[59:75]
        tag_m_GS = skef[75:91]
        # len_sign_GS is 2 byte
        len_sign_GS = int(skef[91:93])
        end_index_sign_GS = 93 + len_sign_GS
        sign_GS = skef[93:end_index_sign_GS]
        # len of OCSP response is 3 byte
        len_OCSPresponse_GS = int(skef[end_index_sign_GS:end_index_sign_GS + 3])
        begin_index_OCSPresponse = end_index_sign_GS + 3
        end_index_OCSPresponse = begin_index_OCSPresponse + len_OCSPresponse_GS
        OCSPresponse_GS = skef[begin_index_OCSPresponse:end_index_OCSPresponse]
        if not scgs:
            # len of gs_cert is 3 byte
            len_gs_cert = int(sked[end_index_OCSPresponse:end_index_OCSPresponse + 3])
            begin_index_gs_cert = end_index_OCSPresponse + 3
            end_index_gs_cert = begin_index_gs_cert + len_gs_cert
            gs_cert = skef[begin_index_gs_cert:end_index_gs_cert]
    elif parameters.SECURITY_LEVEL == 1:
        # three keys à 32 byte aka 96 byte
        c_kset = skef[11:107]
        tag_c_kset = skef[107:123]
        tag_m_GS = skef[123:139]
        # signature length > 100 byte
        len_sign_GS = int(skef[139:142])
        end_index_sign_GS = 142 + len_sign_GS
        sign_GS = skef[142:end_index_sign_GS]
        # len of OCSP response is 3 byte
        len_OCSPresponse_GS = int(skef[end_index_sign_GS:end_index_sign_GS + 3])
        begin_index_OCSPresponse = end_index_sign_GS + 3
        end_index_OCSPresponse = begin_index_OCSPresponse + len_OCSPresponse_GS
        OCSPresponse_GS = skef[begin_index_OCSPresponse:end_index_OCSPresponse]
        if not scgs:
            # len of gs_cert is 3? byte
            len_gs_cert = int(sked[end_index_OCSPresponse:end_index_OCSPresponse + 3])
            begin_index_gs_cert = end_index_OCSPresponse + 3
            end_index_gs_cert = begin_index_gs_cert + len_gs_cert
            gs_cert = skef[begin_index_gs_cert:end_index_gs_cert]

    # check if OCSPResponse is for the the GS certificate
    if not scgs:
        ocsp_resp = ocsp.load_der_ocsp_response(OCSPresponse_GS)
        gs_cert = load_pem_x509_certificate(gs_cert)
        # if they do not match then the OCSP response is intended for ANOTHER certificate and hence cen NEVER be valid!
        if not ocsp_resp.serial_number == gs_cert.serial_number:
            return -1, -1, -1

    # verify OCSPresponse
    if not verify_OCSPResponse(OCSPresponse_GS):
        return -1, -1, -1
    
    serialized_public_gs_ec_key = public_gs_ec_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )
    serialized_public_as_ec_key = public_as_ec_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )

    # print("AS SKEF:", c_nonce, c_kset, tag_c_kset, tag_m_GS, len_sign_GS, sign_GS, OCSPresponse_GS)
    # build m_GS'
    m_GS_v = serialized_public_gs_ec_key + serialized_public_as_ec_key + ua_as + sac_as + EPLDACS + CCLDACS + nonce_gs + c_nonce + c_kset + tag_c_kset
    # verify GS signature
    # print("verify GS signature")
    if not verify_message(m_GS_v, sign_GS, 'GS'):
        return -1, -1, -1
    # verify GS MAC tag
    # print("AS m_GS:", serialized_public_gs_ec_key, serialized_public_as_ec_key, ua_as, sac_as, EPLDACS, CCLDACS, nonce_gs, c_nonce, c_kset, tag_c_kset)
    # print("verify GS MAC tag")
    if not verify_MAC(kM, m_GS_v, tag_m_GS):
        return -1, -1, -1

    kset = decrypt_data(kKEK, c_kset, tag_c_kset, c_nonce)
    if kset == b'-1':
        return -1, -1, -1

    if parameters.SECURITY_LEVEL == 0:
        kBC, kCC, kvoice = kset[0:16], kset[16:32], kset[32:48]
    elif parameters.SECURITY_LEVEL == 1:
        kBC, kCC, kvoice = kset[0:32], kset[32:64], kset[64:96]
    return kBC, kCC, kvoice  

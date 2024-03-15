import sys
import time

from ZKP.Schnorr.schnorr_protocol import run_schnorr_protocol_sha384
from ZKP.Schnorr.schnorr_test import pubkey_gen
from ZKP.Schnorr.schnorr_test import schnorr_sign
from ZKP.Schnorr.schnorr_test import schnorr_verify

def schnor_signature_routine():
    schnorr_prep_t = []
    schnorr_sign_t = []
    schnorr_verify_t = []

    sec_key1_hex = ""
    pubkey_hex = ""
    aux_rand_hex = ""
    msg_hex = ""
    msg = b''
    sec_key = b''
    pubkey = b''
    aux_rand = b''

    sig_actual = None

    for c in range():

        sec_key1_hex = ""
        pubkey_hex = ""
        aux_rand_hex = ""
        msg_hex = ""
        msg = b''
        sec_key = b''
        pubkey = b''
        aux_rand = b''

        start_time = time.perf_counter_ns()

        sec_key1_hex = "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"
        pubkey_hex = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
        aux_rand_hex = "0000000000000000000000000000000000000000000000000000000000000001"
        msg_hex = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
        msg = bytes.fromhex(msg_hex)
        sec_key = bytes.fromhex(sec_key1_hex)
        pubkey = bytes.fromhex(pubkey_hex)
        aux_rand = bytes.fromhex(aux_rand_hex)

        schnorr_prep_t.append(time.perf_counter_ns() - start_time)




    for c in range():
        start_time = time.perf_counter_ns()

        sig_actual = schnorr_sign(msg, sec_key, aux_rand)

        schnorr_sign_t.append(time.perf_counter_ns() - start_time)
        print(str(sys.getsizeof(msg) + sys.getsizeof(sec_key) + sys.getsizeof(aux_rand)) + ' bytes SCHNORR')

    for c in range():
        start_time = time.perf_counter_ns()

        assert schnorr_verify(msg, pubkey, sig_actual)

        schnorr_verify_t.append(time.perf_counter_ns() - start_time)
        print(str(sys.getsizeof(msg) + sys.getsizeof(pubkey) + sys.getsizeof(sig_actual)) + ' bytes SCHNORR')


def schnorr_performance_routine(c_init=100):
    return run_schnorr_protocol_sha384(c_init)




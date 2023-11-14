import os
import hashlib
import ecdsa
import time
from ZKP.Schnorr import schnorr_test
from ZKP.Schnorr.schnorr_test import pubkey_gen
from ZKP.Schnorr.schnorr_test import schnorr_sign
from ZKP.Schnorr.schnorr_test import schnorr_verify

def schnorr_performance_routine():

    start_time = time.perf_counter_ns()

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

    print(f" {time.perf_counter_ns()- start_time} ")

    print("-------- Schnorr preparation done --------")

    #Return the value (in fractional seconds) of a performance counter,
    # i.e. a clock with the highest available resolution to measure a short duration.
    start_time = time.perf_counter_ns()
    sig_actual = schnorr_sign(msg, seckey, aux_rand)
    print(f" {time.perf_counter_ns()- start_time} ")

    start_time = time.perf_counter_ns()
    assert schnorr_verify(msg, pubkey, sig_actual)
    print(f" {time.perf_counter_ns()- start_time} ")

    print("-------- Schnorr Authorization & Client Request done --------")

if __name__ == "__main__":
    schnorr_performance_routine()
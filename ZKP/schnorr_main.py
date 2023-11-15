
import sys
import time
from ZKP.Schnorr.schnorr_test import pubkey_gen
from ZKP.Schnorr.schnorr_test import schnorr_sign
from ZKP.Schnorr.schnorr_test import schnorr_verify
import statistics


def schnorr_performance_routine(c_init=1):

    schnorr_data = []
    sig_actual = None

    start_time = time.perf_counter_ns()

    sec_key1_hex = "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"
    pubkey_hex = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
    aux_rand_hex = "0000000000000000000000000000000000000000000000000000000000000001"
    msg_hex = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
    msg = bytes.fromhex(msg_hex)
    sec_key = bytes.fromhex(sec_key1_hex)
    pubkey = bytes.fromhex(pubkey_hex)
    aux_rand = bytes.fromhex(aux_rand_hex)

    schnorr_time_prep = time.perf_counter_ns() - start_time

    for c in range(c_init):
        start_time = time.perf_counter_ns()

        sig_actual = schnorr_sign(msg, sec_key, aux_rand)

        assert schnorr_verify(msg, pubkey, sig_actual)

        schnorr_data.append(time.perf_counter_ns() - start_time)

    print(sys.getsizeof(sig_actual))
    print(sys.getsizeof(msg))
    print(sys.getsizeof(sec_key))
    print(sys.getsizeof(aux_rand))

    return min(schnorr_data), max(schnorr_data), statistics.mean(schnorr_data), schnorr_time_prep




if __name__ == "__main__":
    schnorr_performance_routine()

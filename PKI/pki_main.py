import os
import subprocess
import time
import PKI.demo_pki as demo_pki
import statistics

def pki_performance_routine(c_init=1):
    pki_data = []

    for c in range(c_init):
        start_time = time.perf_counter_ns()
        demo_pki.pki_routine()
        pki_data.append(time.perf_counter_ns() - start_time)

    return min(pki_data), max(pki_data), statistics.mean(pki_data)


if __name__ == "__main__":
    pki_performance_routine()
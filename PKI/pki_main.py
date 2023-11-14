import os
import subprocess
import time
import PKI.demo_pki as demo_pki

def pki_performance_routine():
    print("-------- PKI preparation done --------")
    # Return the value (in fractional seconds) of a performance counter,
    # i.e. a clock with the highest available resolution to measure a short duration.
    start_time = time.perf_counter_ns()

    demo_pki.pki_routine()

    print(f" {time.perf_counter_ns()- start_time} ")

    print("-------- PKI Authorization & Client Request done --------")

if __name__ == "__main__":
    pki_performance_routine()
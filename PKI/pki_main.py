import os
import subprocess
import time


if __name__ == "__main__":

    print("-------- PKI preparation done --------")
    # Return the value (in fractional seconds) of a performance counter,
    # i.e. a clock with the highest available resolution to measure a short duration.
    start_time = time.perf_counter_ns()

    end_time = time.perf_counter_ns()
    cycles = end_time - start_time
    print(f"PKI took {cycles} seconds.")

    print("-------- PKI Authorization & Client Request done --------")
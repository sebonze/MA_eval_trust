import time
import schnorr_main
import pki_main
import kerberos_main

def prepare_trust_solutions():
    """
    This function prepares all Trust Solutions to run.
    You can add any initialization or setup code here.
    """
    # Placeholder for preparation code
    pass

def measure_cycles(func):
    """
    Decorator to measure and print the number of processing cycles a function takes.
    """
    def wrapper(*args, **kwargs):
        start_time = time.process_time()
        result = func(*args, **kwargs)
        end_time = time.process_time()
        cycles = end_time - start_time
        print(f"{func.__name__} took {cycles} processing cycles.")
        return result
    return wrapper

@measure_cycles
def call_schnorr():
    # Placeholder for schnorr_main callable function
    schnorr_main.callable_function()

@measure_cycles
def call_pki():
    # Placeholder for pki_main callable function
    pki_main.callable_function()

@measure_cycles
def call_kerberos():
    # Placeholder for kerberos_main callable function
    kerberos_main.callable_function()

if __name__ == "__main__":
    prepare_trust_solutions()
    call_schnorr()
    call_pki()
    call_kerberos()






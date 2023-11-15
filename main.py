import time

from prettytable import PrettyTable

import ZKP.schnorr_main
import PKI.pki_main
import CRP.kerberos_main
from CRP import kerberos_main
from PKI import pki_main
from ZKP import schnorr_main


def prepare_trust_solutions():
    """
    This function prepares all Trust Solutions to run.
    You can add any initialization or setup code here.
    """
    # Placeholder for preparation code
    pass


schnorr_crypto_info = "SECP256K1, SHA-384"
schnorr_min = 0
schnorr_max = 0
schnorr_mean = 0
schnorr_bytes = 0

pki_crypto_info = "ECDSA P-384, SHA-384"
pki_min = 0
pki_max = 0
pki_mean = 0
pki_bytes = 0

kerberos_crypto_info = "AES 256 CBC, SHA-384"
kerberos_min = 0
kerberos_max = 0
kerberos_mean = 0
kerberos_bytes = 0

def print_data():
    """
    This function prints the data collected from the Trust Solutions.
    """

    # Initialize table
    table = PrettyTable()

    # Add columns
    table.field_names = ["Trust Solution", "Cipher & Hash", "Min Time", "Max Time", "Mean Time", "Size (Byte)", "Latency *", "Number of Routines"]

    # Add row with the provided data
    # every trust solution offers similar internal operations: preparation (key generation & certificate gen), register / authentication, authorization, verification
    # time to de- and encrypt and the total overall time
    table.add_row(["Schnorr total", schnorr_crypto_info, schnorr_min, schnorr_max, schnorr_mean, "N/A", "N/A",100])
    table.add_row(["    Schnorr Prep", schnorr_crypto_info, schnorr_time_prep, schnorr_time_prep, schnorr_time_prep, "N/A", "N/A", 100])
    table.add_row(["PKI total", pki_crypto_info, pki_min, pki_max, pki_mean, "N/A", "N/A",100])
    table.add_row(["Kerberos total", kerberos_crypto_info, kerberos_min, kerberos_max, kerberos_mean, "N/A", "N/A",100])

    # Print table
    print(table)


if __name__ == "__main__":
    prepare_trust_solutions()
    kerberos_min, kerberos_max, kerberos_mean = kerberos_main.kerberos_performance_routine()
    schnorr_min, schnorr_max, schnorr_mean, schnorr_time_prep = schnorr_main.schnorr_performance_routine()
    pki_min, pki_max, pki_mean = pki_main.pki_performance_routine()


    print_data()

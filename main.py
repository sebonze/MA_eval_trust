from prettytable import PrettyTable
from CRP import kerberos_main
from PKI import pki_main
from ZKP import schnorr_main
import statistics

schnorr_crypto_info = "SECP256K1, SHA-384"
schnorr_data = None
schnorr_bytes = 0

pki_crypto_info = "SECP256K1, SHA-384"
pki_data = None
pki_bytes = 0

kerberos_crypto_info = "AES 256 CBC, SHA-384"
kerberos_data = None
kerberos_bytes = 0

def print_data():
    """
    This function prints the data collected from the Trust Solutions.
    """

    # Initialize table
    table = PrettyTable()

    # Add columns
    table.field_names = ["Trust Solution", "Cipher & Hash", "Min Time", "Max Time", "Mean Time", "Size (Byte)", "Latency *", "Number of Routines"]

    # Add row with the provided data every trust solution offers similar internal operations: preparation (key
    # generation & certificate gen), register / authentication, authorization, verification time to de- and encrypt
    # and the total overall time

    st_min = min(schnorr_data[0])+min(schnorr_data[1])+min(schnorr_data[2])
    st_max =  max(schnorr_data[0])+max(schnorr_data[1])+max(schnorr_data[2])
    st_mean = statistics.mean(schnorr_data[0])+statistics.mean(schnorr_data[1])+statistics.mean(schnorr_data[2])

    pt_min = min(pki_data[0])+min(pki_data[1])+min(pki_data[2])
    pt_max =  max(pki_data[0])+max(pki_data[1])+max(pki_data[2])
    pt_mean = statistics.mean(pki_data[0])+statistics.mean(pki_data[1])+statistics.mean(pki_data[2])

    kt_min = min(kerberos_data[0])+min(kerberos_data[1])+min(kerberos_data[2])
    kt_max =  max(kerberos_data[0])+max(kerberos_data[1])+max(kerberos_data[2])
    kt_mean = statistics.mean(kerberos_data[0])+statistics.mean(kerberos_data[1])+statistics.mean(kerberos_data[2])

    table.add_row(["Schnorr Prep", schnorr_crypto_info, min(schnorr_data[0]), max(schnorr_data[0]), statistics.mean(schnorr_data[0]), "256", "N/A", 100])
    table.add_row(["Schnorr Sign", schnorr_crypto_info, min(schnorr_data[1]), max(schnorr_data[1]), statistics.mean(schnorr_data[1]), "48", "N/A", 100])
    table.add_row(["Schnorr Verify", schnorr_crypto_info, min(schnorr_data[2]), max(schnorr_data[2]), statistics.mean(schnorr_data[2]), "256", "N/A", 100])
    table.add_row(["Schnorr Total", schnorr_crypto_info, st_min, st_max, st_mean, "560", "N/A", 100])

    table.add_row(["-----", "-----", "-----", "-----", "-----", "-----", "-----", "-----"])

    table.add_row(["PKI Prep", pki_crypto_info, min(pki_data[0]), max(pki_data[0]), statistics.mean(pki_data[0]), "605", "N/A", 100])
    table.add_row(["PKI Sign", pki_crypto_info, min(pki_data[1]), max(pki_data[1]), statistics.mean(pki_data[1]), "868", "N/A", 100])
    table.add_row(["PKI Verify", pki_crypto_info, min(pki_data[2]), max(pki_data[2]), statistics.mean(pki_data[2]), "1511", "N/A", 100])
    table.add_row(["PKI Total", pki_crypto_info, pt_min, pt_max, pt_mean, "2984", "N/A", 100])

    table.add_row(["-----", "-----", "-----", "-----", "-----", "-----", "-----", "-----"])

    table.add_row(["Kerberos Prep", kerberos_crypto_info, min(kerberos_data[0]), max(kerberos_data[0]), statistics.mean(kerberos_data[0]), "56", "N/A", 100])
    table.add_row(["Kerberos Sign", kerberos_crypto_info, min(kerberos_data[1]), max(kerberos_data[1]), statistics.mean(kerberos_data[1]), "56", "N/A", 100])
    table.add_row(["Kerberos Verify", kerberos_crypto_info, min(kerberos_data[2]), max(kerberos_data[2]), statistics.mean(kerberos_data[2]), "56", "N/A", 100])
    table.add_row(["Kerberos Total", kerberos_crypto_info, kt_min, kt_max, kt_mean, "168", "N/A", 100])


    # Print table
    print(table)


if __name__ == "__main__":

    kerberos_data = kerberos_main.kerberos_performance_routine()
    schnorr_data = schnorr_main.schnorr_performance_routine()
    pki_data = pki_main.pki_performance_routine()
    print_data()

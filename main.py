import time
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

def call_schnorr():
    # Placeholder for schnorr_main callable function
    schnorr_main.schnorr_performance_routine()

def call_pki():
    # Placeholder for pki_main callable function
    #pki_main.main()
    pass

def call_kerberos():
    # Placeholder for kerberos_main callable function
    kerberos_main.kerberos_performance_routine()

if __name__ == "__main__":
    prepare_trust_solutions()
    call_kerberos()
    call_schnorr()
    call_pki()







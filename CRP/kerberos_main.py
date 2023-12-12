from multiprocessing import Process
import os
import CRP.Kerberos.server.key_distribution as db
import CRP.Kerberos.server.server as server
from CRP.Kerberos.server.server_authentication import AuthenticationServer
from CRP.Kerberos.server.server_tgs import TGSServer
from CRP.Kerberos.server.service_server_basic import SSServerBasic
from CRP.Kerberos.server.service_server_bad import SSServerBad
from CRP.Kerberos.client.client import KerberosClient


def AS():
    server.start(AuthenticationServer, db.AS_NAME, 'localhost', 8080)


def TGS():
    server.start(TGSServer, db.TGS_NAME, 'localhost', 8081)


def SSBasic():
    server.start(SSServerBasic, 'Basic', 'localhost', 8082)


def SSBad():
    server.start(SSServerBad, 'Bad', 'localhost', 8083)


PROCS = []


def start_all():
    k_servers = [AS,
                 TGS,
                 SSBasic,
                 SSBad]

    for k_server in k_servers:
        proc = Process(target=k_server)
        proc.start()
        PROCS.append(proc)

    # for proc in procs:
    #    proc.join()


def kerberos_performance_routine(c_init=100):
    kerberos_prep_t = []
    kerberos_sign_t = []
    kerberos_verify_t = []

    start_all()

    USER = 'username'
    PASS = 'password'

    FOLDER = os.path.dirname(os.path.realpath(__file__))
    DATA = FOLDER + "/Kerberos/server/database/user_{}.data".format(USER)

    if os.path.isfile(DATA):
        os.remove(DATA)

    client = KerberosClient(USER, PASS)
    client.register()

    TGS_key, TGT = client.authenticate()

    CTS_good, CTS_key_good = client.authorize(TGT, TGS_key, 'Basic')
    assert client.service_request(CTS_good, CTS_key_good, 'http://localhost:8082/client')

    for proc in PROCS:
        proc.kill()

    # get data from time logs
    # Open the file and read lines
    with open("prep.data", 'r') as file:
        for line in file:
            # Convert each line to an integer and append to the array
            kerberos_prep_t.append(int(line.strip()))

    with open("sign.data", 'r') as file:
        for line in file:
            # Convert each line to an integer and append to the array
            kerberos_sign_t.append(int(line.strip()))

    with open("verify.data", 'r') as file:
        for line in file:
            # Convert each line to an integer and append to the array
            kerberos_verify_t.append(int(line.strip()))

    return [kerberos_prep_t, kerberos_sign_t, kerberos_verify_t]


if __name__ == "__main__":
    kerberos_performance_routine()

from multiprocessing import Process
import time
import os
import CRP.Kerberos.lib.lib as lib
import CRP.Kerberos.server.key_distribution as db
import CRP.Kerberos.server.server as server
from CRP.Kerberos.server.authentication_server import AuthenticationServer
from CRP.Kerberos.server.tgs_server import TGSServer
from CRP.Kerberos.server.service_server_basic import SSServerBasic
from CRP.Kerberos.server.service_server_bad import SSServerBad
from CRP.Kerberos.client.client import KerberosClient

SERVER = 'localhost'
STARTED = 0


def AS():
    print("start AS")
    server.start(AuthenticationServer, db.AS_NAME, SERVER, 8080)


def TGS():
    print("start TGS")
    server.start(TGSServer, db.TGS_NAME, SERVER, 8081)


def SSBasic():
    print("start Basic")
    server.start(SSServerBasic, 'Basic', SERVER, 8082)


def SSBad():
    print("start Bad")
    server.start(SSServerBad, 'Bad', SERVER, 8083)


def test_client():
    time.sleep(5)
    USER = 'username'
    PASS = 'password'
    BAD_PASS = 'bad'
    FOLDER = os.path.dirname(os.path.realpath(__file__))
    DATA = FOLDER + "/../server/database/user_{}.data".format(USER)
    # if os.path.isfile(DATA):
    # os.remove(DATA)
    client = KerberosClient(USER, PASS)
    client.register()

    assert db.retrieve_user(USER) == lib.one_way_hash(PASS)
    assert db.retrieve_user(USER) != lib.one_way_hash(BAD_PASS)

    TGS_key, TGT = client.authenticate()
    assert len(TGS_key) != 0

    CTS_good, CTS_key_good = client.authorize(TGT, TGS_key, 'Basic')
    assert client.service_request(CTS_good, CTS_key_good, 'http://localhost:8082/client')

    CTS_bad, CTS_key_bad = client.authorize(TGT, TGS_key, 'Bad')
    assert not client.service_request(CTS_bad, CTS_key_bad, 'http://localhost:8083/client')

    print("<====== Tests passed ======>")
    print("Type Ctrl-C to stop servers")


def start_all():

        fns = [AS,
               TGS,
               SSBasic,
               SSBad,
               test_client]

        procs = []
        for fn in fns:
            proc = Process(target=fn)
            proc.start()
            procs.append(proc)

        for proc in procs:
            proc.join()



if __name__ == '__main__':
    start_all()

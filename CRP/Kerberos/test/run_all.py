from multiprocessing import Process
import time
import os
import threading

import CRP.Kerberos.server.key_distribution as db
import CRP.Kerberos.server.server as server
from CRP.Kerberos.server.authentication_server import AuthenticationServer
from CRP.Kerberos.server.tgs_server import TGSServer
from CRP.Kerberos.server.service_server_basic import SSServerBasic
from CRP.Kerberos.server.service_server_bad import SSServerBad
from CRP.Kerberos.client.client import KerberosClient
import CRP.Kerberos.lib.lib as lib

SERVER = 'localhost'
STARTED = 0


def AS():
    server.start(AuthenticationServer, db.AS_NAME, SERVER, 8080)


def TGS():
    server.start(TGSServer, db.TGS_NAME, SERVER, 8081)


def SSBasic():
    server.start(SSServerBasic, 'Basic', SERVER, 8082)


def start_all():
    fns = [AS,
           TGS,
           SSBasic]

    procs = []
    for fn in fns:
        proc = Process(target=fn)
        proc.start()
        procs.append(proc)

    for proc in procs:
        proc.join()


if __name__ == '__main__':
    # start_all()
    t1 = threading.Thread(target=AS)
    t2 = threading.Thread(target=TGS)
    t3 = threading.Thread(target=SSBasic)

    t1.start()
    t2.start()
    t3.start()

from multiprocessing import Process
import time
import os

import sys
sys.path.insert(0, '../lib')
sys.path.insert(0, '../client')
sys.path.insert(0, '../server')

import key_distribution as db
import server
from authentication_server import AuthenticationServer
from tgs_server import TGSServer
from service_server_basic import SSServerBasic
from service_server_bad import SSServerBad
from client import KerberosClient
import lib

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
    start_all()

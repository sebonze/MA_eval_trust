#!/usr/bin/python
from time import time
from ast import literal_eval
import uuid
import server
import cgi

import sys
sys.path.insert(0, '../lib')
import lib

SERVER = 'localhost'
PORT_NUMBER = 8083
TIMEOUT = 60*60 #An hour
NAME = 'Bad'

class SSServerBad(server.ResponseServer):
    def response(self, CTS_encrypted, authenticator_encrypted, addr):
        CTS = lib.decrypt_tuple(CTS_encrypted, self.private_key)
        username, CTS_addr, expiration, SS_session_key = CTS
        # unpack client-to-server ticket

        ID, timestamp = lib.decrypt_tuple(authenticator_encrypted, SS_session_key)
        # unpack authenticator

        confirmation = lib.encrypt('0', SS_session_key)
        # send faulty timestamp

        return (confirmation, )

    def resolve(self, CTS_encrypted, message, addr):
        return 'You should never connect to me!'

if __name__ == '__main__':
    server.start(SSServerBad, NAME, SERVER, PORT_NUMBER)


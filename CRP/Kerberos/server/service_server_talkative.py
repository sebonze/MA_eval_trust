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
PORT_NUMBER = 8084
TIMEOUT = 60*60 #An hour
NAME = 'Talk'

class SSServerBasic(server.ResponseServer):
    def response(self, CTS_encrypted, authenticator_encrypted, addr):
        CTS = lib.decrypt_tuple(CTS_encrypted, self.private_key)
        username, CTS_addr, expiration, SS_session_key = CTS
        # unpack client-to-server ticket

        ID, timestamp = lib.decrypt_tuple(authenticator_encrypted, SS_session_key)
        # unpack authenticator

        confirmation = lib.encrypt(timestamp, SS_session_key)
        # send the user's timestamp back to them as a confirmation of login

        return (confirmation, )

    def resolve(self, CTS_encrypted, message, addr):
        CTS = literal_eval(lib.decrypt(CTS_encrypted, self.private_key))
        if CTS[1] != addr:
            return 'IP does not match ticket'
        if CTS[2] < time():
            return 'Session expired, please re-authenticate'
        return self.process_msg(message, CTS[0])

    def process_msg(self, message, user):
        return 'received {} from {}'.format(message, user)

if __name__ == '__main__':
    server.start(SSServerBasic, NAME, SERVER, PORT_NUMBER)


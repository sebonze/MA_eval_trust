#!/usr/bin/python
from time import time
from ast import literal_eval
import CRP.Kerberos.server.server as server
import os
import CRP.Kerberos.lib.lib as lib

FOLDER = os.path.dirname(os.path.realpath(__file__))
SERVER = 'localhost'
PORT_NUMBER = 8082
TIMEOUT = 60 * 60  # An hour
NAME = 'Basic'


class SSServerBasic(server.ResponseServer):
    def response(self, CTS_encrypted, authenticator_encrypted, addr):
        CTS = lib.decrypt_tuple(CTS_encrypted, self.private_key)
        username, CTS_addr, expiration, SS_session_key = CTS
        # unpack client-to-server ticket

        ID, timestamp = lib.decrypt_tuple(authenticator_encrypted, SS_session_key)
        # unpack authenticator

        confirmation = lib.encrypt(timestamp, SS_session_key.encode('utf-8'))
        # send the user's timestamp back to them as a confirmation of login

        return confirmation.decode('utf-8')

    def resolve(self, CTS_encrypted, message, addr):
        CTS = literal_eval(lib.decrypt(CTS_encrypted, self.private_key))
        if CTS[1] != addr:
            return 'IP does not match ticket'
        if CTS[2] < time():
            return 'Session expired, please re-authenticate'
        return self.process_msg(message, CTS[0])

    def process_msg(self, message, user):
        print('received {} from {}'.format(message, user))
        with open('{}/response.txt'.format(FOLDER)) as reader:
            return reader.read()


if __name__ == '__main__':
    server.start(SSServerBasic, NAME, SERVER, PORT_NUMBER)

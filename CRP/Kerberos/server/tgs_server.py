#!/usr/bin/python
from time import time
from ast import literal_eval
import key_distribution as db
import uuid
import server
import cgi

import sys
sys.path.insert(0, '../lib')
import lib

SERVER = 'localhost'
PORT_NUMBER = 8081
TIMEOUT = 60*60 #An hour

class TGSServer(server.ResponseServer):
    def response(self, TGT_ID, authenticator_encrypted, addr):
        TGT, service_id = literal_eval(TGT_ID)
        # Unencrypted TGT and service id come as string'd double

        TGT_decrypted = lib.decrypt_tuple(TGT, self.private_key)
        TGT_username, TGT_addr, expiration, TGS_session_key = TGT_decrypted
        # Unpack TGT

        username, time = lib.decrypt_tuple(authenticator_encrypted, TGS_session_key)
        # Encrypted username and time.

        assert username == TGT_username
        assert addr == TGT_addr
        # Make sure they are who they say they are. I think we could omit this.

        SS_session_key = str(uuid.uuid1())
        # Session key for the service server

        CTS = (username, addr, expiration, SS_session_key)
        service_server_key = db.retrieve_server(service_id)
        CTS_encrypted = lib.encrypt_tuple(CTS, service_server_key)
        # Client-to-server ticket

        SS_session_key_encrypted = lib.encrypt(SS_session_key, TGS_session_key)
        return (CTS_encrypted, SS_session_key_encrypted)

if __name__ == '__main__':
    server.start(TGSServer, db.TGS_NAME, SERVER, PORT_NUMBER)

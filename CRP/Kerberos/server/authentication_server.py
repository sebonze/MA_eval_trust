#!/usr/bin/python
from time import time
import key_distribution as db
import uuid
import server
import cgi

import sys
sys.path.insert(0, '../lib')
import lib

SERVER = 'localhost'
PORT_NUMBER = 8080
TIMEOUT = 60*60 #An hour

class AuthenticationServer(server.ResponseServer):
    def response(self, username, _, addr):
        secret = db.retrieve_user(username)
        TGS_session_key = str(uuid.uuid1())

        TGS_encrypted = lib.encrypt(TGS_session_key, secret)

        expiration = time() + TIMEOUT
        TGT = (username, addr, expiration, TGS_session_key)
        TGS_server_key = db.retrieve_server(db.TGS_NAME)
        TGT_encrypted = lib.encrypt_tuple(TGT, TGS_server_key)

        return (TGS_encrypted, TGT_encrypted)


    #Handler for the GET requests
    def do_POST(self):
        # Parse the form data posted
        form = cgi.FieldStorage(
            fp=self.rfile, 
            headers=self.headers,
            environ={'REQUEST_METHOD':'POST',
                     'CONTENT_TYPE':self.headers['Content-Type'],
                     })

        # Begin the response
        self.send_response(200)
        self.end_headers()
        username = form['username'].value
        password = form['password'].value
        result = db.configure_user(username, password)
        self.wfile.write('Response: {}'.format(result))
        return

if __name__ == '__main__':
    server.start(AuthenticationServer, db.AS_NAME, SERVER, PORT_NUMBER)

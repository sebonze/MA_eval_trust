#!/usr/bin/python
import time
import CRP.Kerberos.server.key_distribution as db
import uuid
import CRP.Kerberos.server.server as server
import cgi
import CRP.Kerberos.lib.lib as lib

SERVER = 'localhost'
PORT_NUMBER = 8080
TIMEOUT = 60 * 60  # An hour


class AuthenticationServer(server.ResponseServer):
    def response(self, username, _, addr):
        start_time = time.perf_counter_ns()

        secret = db.retrieve_user(username)
        TGS_session_key = str(uuid.uuid1())

        TGS_encrypted = lib.encrypt(TGS_session_key, secret)

        expiration = time.time() + TIMEOUT
        TGT = (username, addr, expiration, TGS_session_key)
        TGS_server_key = db.retrieve_server(db.TGS_NAME)
        TGT_encrypted = lib.encrypt_tuple(TGT, TGS_server_key)

        with open("sign.data", "a") as myfile:
            myfile.write(str(time.perf_counter_ns() - start_time) + "\n")

        return TGS_encrypted, TGT_encrypted

    # Handler for the GET requests
    def do_POST(self):
        start_time = time.perf_counter_ns()

        # Parse the form data posted
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD': 'POST',
                     'CONTENT_TYPE': self.headers['Content-Type'],
                     })

        # Begin the response
        self.send_response(200, message=None)
        # self.send_header('Content-type', 'text/html')
        self.end_headers()
        username = form['username'].value
        password = form['password'].value
        result = db.configure_user(username, password)
        self.wfile.write('Response: {}'.format(result).encode("utf8"))

        with open("prep.data", "a") as myfile:
            myfile.write(str(time.perf_counter_ns() - start_time) + "\n")
        return


if __name__ == '__main__':
    server.start(AuthenticationServer, db.AS_NAME, SERVER, PORT_NUMBER)

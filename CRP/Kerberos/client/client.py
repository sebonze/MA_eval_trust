import requests
import sys

sys.path.append('CRP/Kerberos/lib')
import CRP.Kerberos.lib.lib as lib
import urllib
import getpass
from time import time

URL_AS = 'http://localhost:8080/client'
URL_TGS = 'http://localhost:8081/client'
URL_SS = 'http://localhost:8082/client'
PORTS = {
    'Basic': '8082',
    'Bad': '8083',
    'Talk': '8084'
}


def send(args, url):
    mapped = dict((i, args[i]) for i in range(len(args)))
    encoded = urllib.parse.urlencode(mapped)
    return requests.get(url + '?' + encoded).content


class KerberosClient():
    def __init__(self, user, passwd):
        self.user = user
        self.passwd = passwd

    def register(self):
        args = {'username': self.user, 'password': self.passwd}
        return requests.post(URL_AS, data=args)

    def authenticate(self):
        auth_send = send((self.user, '_'), URL_AS).split()
        #dirty fix
        TGS_key_encoded = auth_send[0][3:91]
        TGT = auth_send[1][2:154]
        #TGS_key_encoded, TGT = send((self.user, '_'), URL_AS).split()

        secret = lib.one_way_hash(self.passwd)
        TGS_key = lib.decrypt(TGS_key_encoded, secret)

        return TGS_key, TGT

    def authorize(self, TGT, TGS_key, service_id):
        unencrypted = str((TGT.decode(), service_id))
        encrypted = lib.encrypt_tuple((self.user, time()), TGS_key)

        tgs_response = send((unencrypted, encrypted), URL_TGS)
        CTS, CTS_key_encrypted = tgs_response.split()
        CTS_key = lib.decrypt(CTS_key_encrypted, TGS_key)

        return CTS, CTS_key

    def service_request(self, CTS, CTS_key, url):
        authenticator = (self.user, str(time()))
        authenticator_encrypted = lib.encrypt(str(authenticator), CTS_key)

        timestamp_encrypted = send((CTS, authenticator_encrypted), url).split()[0]
        timestamp = lib.decrypt(timestamp_encrypted, CTS_key)

        return timestamp.decode('utf-8') == authenticator[1]

    def run(self):
        print("Starting authentication")
        print("Requesting TGS Session Key and  Ticket-granting-ticket from Authentication Server...")
        TGS_key, TGT = self.authenticate()
        sys.stdout.write('Specify machine to connect to (Basic, Bad, Talk):')
        machine = input()
        PORT = PORTS[machine]
        print("Requesting Client-To-Server ticket and session key from Ticket Granting Server...")
        CTS, CTS_key = self.authorize(TGT, TGS_key, machine)
        print("Connecting to service server \'{}\' (http://localhost:{})".format(machine, PORT))
        if self.service_request(CTS, CTS_key, 'http://localhost:{}/client'.format(PORT)):
            while machine == 'Talk':
                sys.stdout.write('>')
                print(send((CTS, input()), 'http://localhost:{}/'.format(PORT)))
            print(send((CTS, 'Hello world!'), 'http://localhost:{}/'.format(PORT)))
        else:
            print('Authentication failed, server not trusted')
        print("Connection closed")


if __name__ == '__main__':
    sys.stdout.write('Username: ')
    user = input()
    passwd = getpass.getpass()
    client = KerberosClient(user, passwd)
    client.run()

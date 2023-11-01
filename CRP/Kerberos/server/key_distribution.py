import os
from base64 import b64encode

import sys
sys.path.insert(0, '../lib')
import lib

FOLDER = os.path.dirname(os.path.realpath(__file__)) + "/database"
AS_NAME = "AS"
TGS_NAME = "TGS"
SS_NAME = "SS"

def save(ID, value):
    f = open("{}/{}.data".format(FOLDER, ID), 'w+')
    print("saving {}:{}".format(ID, value))
    f.write(str(value))
    f.close()

def retrieve(ID):
    f = open("{}/{}.data".format(FOLDER, ID))
    data = f.read()
    f.close()
    return data

def configure_server(ID):
    ID = "server_{}".format(ID)
    random_bytes = os.urandom(16)
    key = b64encode(random_bytes).decode('utf-8')
    save(ID, key)

def configure_user(ID, passwd):
    key = lib.one_way_hash(passwd)
    ID = "user_{}".format(ID)
    
    if os.path.isfile("{}/{}.data".format(FOLDER, ID)):
        return "User {} already exists".format(ID)

    save(ID, key)
    return "Register {}".format(ID)

def retrieve_user(ID):
    return str(retrieve("user_{}".format(ID)))

def retrieve_server(ID):
    return str(retrieve("server_{}".format(ID)))

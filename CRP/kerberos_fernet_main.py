from cryptography.fernet import Fernet
import time

# Key Distribution Center (KDC)
class KDC:
    def __init__(self):
        self.tgs_key = Fernet.generate_key()  # Key for Ticket Granting Service (TGS)
        self.clients = {}  # Store client passwords

    def register_client(self, client_name, client_password):
        self.clients[client_name] = Fernet(client_password)

    def get_tgs_ticket(self, client_name, client_password):
        if client_name in self.clients:
            client_cipher = Fernet(client_password)
            ticket = client_cipher.encrypt(self.tgs_key)
            return ticket
        else:
            raise ValueError("Client not registered.")

# Ticket Granting Service (TGS)
class TGS:
    def __init__(self, kdc):
        self.kdc = kdc
        self.service_keys = {}

    def register_service(self, service_name):
        self.service_keys[service_name] = Fernet.generate_key()

    def get_service_ticket(self, service_name, ticket):
        tgs_cipher = Fernet(self.kdc.tgs_key)
        client_password = tgs_cipher.decrypt(ticket)
        client_cipher = Fernet(client_password)
        service_key = self.service_keys[service_name]
        service_ticket = client_cipher.encrypt(service_key)
        return service_ticket

# Service (e.g., a file server)
class Service:
    def __init__(self, service_name, tgs):
        self.service_name = service_name
        self.tgs = tgs
        self.key = self.tgs.service_keys[service_name]

    def access_service(self, service_ticket, client_password):
        client_cipher = Fernet(client_password)
        service_key = client_cipher.decrypt(service_ticket)
        if service_key == self.key:
            return "Access granted!"
        else:
            return "Access denied!"

if __name__ == "__main__":
    kdc = KDC()
    tgs = TGS(kdc)
    service_name = "file_server"
    tgs.register_service(service_name)
    service = Service(service_name, tgs)

    client_name = "Alice"
    client_password = Fernet.generate_key()
    kdc.register_client(client_name, client_password)

    tgs_ticket = kdc.get_tgs_ticket(client_name, client_password)
    service_ticket = tgs.get_service_ticket(service_name, tgs_ticket)

    response = service.access_service(service_ticket, client_password)
    print(response)
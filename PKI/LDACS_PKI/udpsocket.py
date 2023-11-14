import socket
import time
from base64 import b64encode
from crc import CrcCalculator, Crc32
from datetime import datetime
from filelogger import FileLogger
from queue import Queue
from threading import Thread


class UDPSocket:
    listen: bool
    host: str
    port: int
    s: socket.socket
    logger: FileLogger
    q: Queue

    def __init__(self, listen: bool, host: str, port: int, logger: FileLogger, ipv: int = 4):
        self.listen = listen
        self.host = host
        self.port = port
        self.q = Queue()
        self.logger = logger
        self.logger.info(f"[udpsocket] Creating a UDP socket with host:port {self.host}:{self.port}")
        if ipv == 4:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if self.listen:
                self.s.bind((self.host, self.port))
        elif ipv == 6:
            self.s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            # info = socket.getaddrinfo(str(self.host) + '%' + str(INTERFACE), self.port, socket.AF_INET6,
            #                           socket.SOCK_DGRAM, socket.SOL_UDP)[0][4]
            # self.s.bind(info)
            if self.listen:
                self.s.bind((self.host, self.port))
        else:
            self.logger.info(f"[udpsocket] IP version has an unknown value: {ipv}. Aborting execution.")
            raise ValueError
        self.logger.info(f"[udpsocket] Created a UDP socket with host:port {self.host}:{self.port}")

    def send(self, data: bytes) -> None:
        """
        Sends the data over UDP by using the socket
        :param data: data to be sent over UDP
        :return: Nothing.
        """
        try:
            # b64 = b64encode(data).decode()
            # self.logger.info(f"[udpsocket] Send {b64} to {self.host}:{self.port}")
            self.s.sendto(data, (self.host, self.port))
            self.logger.info(f"[udpsocket] Sent a packet: {data}")
        except socket.error:
            self.logger.error(f"[udpsocket] Failed to send {data} to {self.host}:{self.port}")

    def receive(self) -> None:
        """
        Wait for content to arrive over UDP and store it in `d`
        :return: `d`: the content and the address and port where it came from
        """
        d = self.s.recvfrom(1 << 12)
        self.logger.info(f"[udpsocket] Received message")
        self.q.put((time.time(), d))


    def receiver_thread(self):
        while True:
            self.receive()
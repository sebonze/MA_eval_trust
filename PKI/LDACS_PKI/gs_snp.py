from udpsocket import UDPSocket
import crypto
import parameters
import os
import sys
import random
import time
import datetime
from threading import Thread
from filelogger import FileLogger
from placeholdertext import placeholdertext

import sys
sys.executable


class SNP_GS:
    def __init__(self, UA_AS, UA_GS, SAC_AS, SAC_GS, SCGS, logger):
        self.UA_AS = UA_AS
        self.UA_GS = UA_GS
        self.SAC_AS = SAC_AS
        self.SAC_GS = SAC_GS
        self.SCGS = SCGS
        # crypto:
        self.EPLDACS = b'0001000100010001'
        self.CCLDACS = b'1'
        self.make_details = None
        # keys
        self.kAS_GS = None
        self.kDC = None
        # generate cell wide keys
        self.kBC, self.kCC, self.kvoice = crypto.generate_Kset()
        # set security_mode (MAC only at 0, encrypt at 1)
        self.security_mode = -1
        # start allowing data packes when true
        self.allow_processing_data_packets = False
        # logger
        self.logger = logger
        # socket ops
        if ":" in parameters.GS_HOST:
            self.udp_socket_receiver = UDPSocket(listen = True, host=parameters.OWN_HOST, port=parameters.OWN_PORT, logger=self.logger, ipv=6)
            self.udp_socket_sender = UDPSocket(listen = False, host=parameters.AS_HOST, port=parameters.AS_PORT, logger=self.logger, ipv=6)
        else:
            self.udp_socket_receiver = UDPSocket(listen = True, host=parameters.OWN_HOST, port=parameters.OWN_PORT, logger=self.logger, ipv=4)
            self.udp_socket_sender = UDPSocket(listen = False, host=parameters.AS_HOST, port=parameters.AS_PORT, logger=self.logger, ipv=4)

    def begin_make(self):
        private_gs_ec_key, nonce_gs, shke_payload = crypto.build_shke()
        # initialize this specific MAKE details
        UA_GS = crypto.bytelify(self.UA_GS)
        UA_AS = crypto.bytelify(self.UA_AS)
        SAC_GS = crypto.bytelify(self.SAC_GS)
        SAC_AS = crypto.bytelify(self.SAC_AS)
        SCGS = crypto.bytelify(self.SCGS)
        self.make_details = crypto.make_details(private_own_ec_key=private_gs_ec_key, public_other_ec_key=b'', nonce_gs=nonce_gs
                                            , nonce_as=b'', ua_gs=UA_GS, ua_as=UA_AS, sac_gs=SAC_GS, sac_as=SAC_AS, 
                                            scgs=SCGS, EPLDACS=self.EPLDACS, CCLDACS=self.CCLDACS, algo=b'', kM=b'', kKEK=b'')
        shke = b'000' + shke_payload
        self.udp_socket_sender.send(shke)
        now = time.time()
        self.logger.info(f"[gs_snp] Sent the SHKE message to AS" f" {now} " f" {shke} ")

    def run_sender(self):
        message_counter = 0
        while True:
            try:
                if self.allow_processing_data_packets:
                    header = b'111'
                    packet_id = b'GS' + message_counter.to_bytes(32, sys.byteorder)
                    packet_length = random.randint(125, 1400)
                    data = placeholdertext[:packet_length]
                    payload = data # header + packet_id + data
                    now = time.time()
                    final_payload = payload

                    if self.security_mode == 0:
                        tag = crypto.generate_MAC(self.kAS_GS, payload)
                        self.logger.info(f"[gs_snp] Created MAC at" f" {now} " "for packet" f" {payload} " "with tag" f" {tag} ")
                        final_payload = payload + tag
                    elif self.security_mode == 1:
                        nonce, ciphertext, tag = crypto.encrypt_data(self.kAS_GS, payload)
                        self.logger.info(f"[gs_snp] Encrypted packet" f" {payload} " "at" f" {now} " "with nonce" f" {nonce} " "with tag" f" {tag} " "to ciphertext" f" {ciphertext} ")
                        final_payload = nonce + ciphertext + tag
                    else:
                        pass
                    
                    final_payload = header + packet_id + final_payload
                    self.udp_socket_sender.send(final_payload)
                    time.sleep(2)
                    message_counter += 1
            except KeyboardInterrupt:
                self.logger.info(f"[gs_snp] Listening aborted by user with KeyboardInterrupt")

    def run_receiver(self):
        try:
            # This is the listener thread that puts everything into the q:Queue!
            Thread(target=self.udp_socket_receiver.receiver_thread, daemon=True).start()
            
            while True:
                # Get the next packet from the q:Queue
                try:
                    timestamp, data = self.udp_socket_receiver.q.get(timeout=1)
                    self.logger.info(f"[gs_snp] Just took a packet from the queue at." f" {timestamp} " "Queue size is currently " f" {self.udp_socket_receiver.q.qsize()} ")
                    # first three bytes from a packet are header
                    data = data[0]
                    print("Received data from AS at", timestamp, ":", data)
                    header = data[0:3]
                    # currently at MAKE packet #1
                    if header == b'001':
                        chke = data[3:]
                        # algo is on first position and two bytes long with the second byte either being 0 or 1
                        security_mode = int(chke[0:2])
                        kAS_GS, kDC, skef_payload = crypto.build_skef(chke=chke, private_gs_ec_key=self.make_details.private_own_ec_key, 
                                                nonce_gs=self.make_details.nonce_gs, ua_as=self.make_details.ua_as, ua_gs=self.make_details.ua_gs, 
                                                sac_as=self.make_details.sac_as, sac_gs=self.make_details.sac_gs, scgs=self.make_details.scgs, 
                                                kBC=self.kBC, kCC=self.kCC, kvoice=self.kvoice, 
                                                EPLDACS=self.EPLDACS, CCLDACS=self.CCLDACS)
                        
                        # print("skef_payload", skef_payload)
                        self.kAS_GS = kAS_GS
                        self.kDC = kDC
                        now = time.time()
                        self.logger.info(f"[gs_snp] Just set GS keys at" f" {now} " "with kBC:" f" {self.kBC} " "kCC:" f" {self.kCC} " "kDC:" f" {self.kDC} " "kAS_GS:" f" {self.kAS_GS} " "kvoice:" f" {self.kvoice} ")
                        skef = b'002' + skef_payload
                        self.udp_socket_sender.send(skef)
                        time.sleep(2)
                        now = time.time()
                        self.logger.info(f"[gs_snp] MAKE done. Opening SNP GS now at" f" {now} ")
                        self.security_mode = security_mode
                        self.allow_processing_data_packets = True
                    else:
                        if self.allow_processing_data_packets:
                            # 3 byte header, 2 byte AS/GS, 32 byte packet number
                            payload = data[37:]
                            now = time.time()
                            msg = payload
                            if self.security_mode == 0:
                                msg = payload[:-16]
                                tag = payload[-16:]
                                if crypto.verify_MAC(self.kAS_GS, msg, tag):
                                    now = time.time()
                                    self.logger.info(f"[gs_snp] Verified MAC at" f" {now} " "Packet" f" {msg} " "is ok.")
                                else:
                                    now = time.time()
                                    self.logger.info(f"[gs_snp] Falsified MAC at" f" {now} " "Packet" f" {msg} " "is corrupted.")
                            elif self.security_mode == 1:
                                nonce = payload[:11]
                                msg = payload[11:-16]
                                tag = payload[-16:]
                                plaintext = crypto.decrypt_data(self.kAS_GS, msg, tag, nonce)
                                now = time.time()
                                if plaintext != b'-1':
                                    self.logger.info(f"[gs_snp] Decrypted and verified MAC at" f" {now} " "Packet" f" {msg} " "is ok with plaintext" f" {plaintext} ")
                                else:
                                    self.logger.info(f"[gs_snp] Decryption failed and falsified MAC at" f" {now} " "Packet" f" {msg} " "is corrupted.")
                            # there is no security mode above 1
                            else:
                                pass
                            self.logger.info(f"[gs_snp] Got packet" f" {msg} " "at" f" {now} ")
                    
                except Exception as e:
                    print(e)
                    continue
        except KeyboardInterrupt:
                self.logger.info(f"[gs_snp] Listening aborted by user with KeyboardInterrupt")

            

def __main__():
    log_filename = datetime.datetime.strftime(datetime.datetime.now(), "%Y-%m-%d_%T").replace(':', '_') + '_'
    log_filename += '.log'
    folder = './log'
    if not os.path.exists(folder):
        os.makedirs(folder)
    logger = FileLogger(filename=folder + '/' + log_filename)
    logger.info(f"[main] Started the GS SNP with logfile {log_filename} ")

    snp_gs = SNP_GS(UA_AS=1, UA_GS=1, SAC_AS=1, SAC_GS=1, SCGS=0, logger=logger)

    # start udp receiver
    # This is the listener thread that puts everything into the q:Queue!
    Thread(target=snp_gs.udp_socket_receiver.receiver_thread, daemon=True).start()

    print("Starting GS receiver Thread")
    Thread(target=snp_gs.run_receiver, daemon=True).start()
    time.sleep(1)
    print("GS starting MAKE")
    snp_gs.begin_make()
    print("Starting GS sender Thread")
    Thread(target=snp_gs.run_sender, daemon=False).start()
    time.sleep(1)

    


if __name__ == __main__():
    __main__()




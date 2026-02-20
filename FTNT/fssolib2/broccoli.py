# 
#  Brocolli is (almost) abbreviation of BRidge to Original COLLector from fortInet :) (Fortinet FSSO collector)
#  This is by design Collector "repeater".
#  It is connecting to FSSO agent, which is feeding the Brocolli with user updates. Updates got this way
#  are forwarded to another FAAS collector usual SOAP way. Service is set to "broc".
#  
#

import time
import socket
import select
import pprint
import struct
import logging

import hashlib
import hmac

import argparse


# FSSO protocol implementation
import fssolib.protocol as protocol




class Brocolli:
    
    DUMP_PACKET = 0
    
    def __init__(self,ca_ip,ca_port=8000):
        self.log = None
        self.data = ""
        
        self.my_sync = 0
        self.my_sync_interval = 60
        self.my_sync_sent = 0
        self.rem_sync = 0
        self.rem_sync_recv = 0

        self.banner = "BrokerCollector 1.1"
        self.lcol_ip = ca_ip
        self.lcol_port = ca_port
        
    
    def applyConfig(self):
        
        self.log = logging.getLogger("brocolli")
        ch = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s: %(levelname)8s: %(message)s')
        ch.setFormatter(formatter)
        
        self.log.addHandler(ch)
        self.log.setLevel(logging.INFO)

        

    
    # FIXME: copy-paste from fsaehandler
    # method, which runs through the buffer (self.data) and is giving out unpacked structures
    # coming from FortiGate
    def packets(self):
        offset = 0
        no_packets = 0
        while True:
            # we need at least 6 bytes to parse length of the packet
            if offset + 6 > len(self.data):
                self.log.debug("packets: final bytes left in the buffer: %d" % (len(self.data)-offset,))
                yield offset, None
                break
            # still we can reach end of buffer in the middle of the packet
            pl = protocol.packet_len(self.data[offset:])
            if offset + pl > len(self.data):
                self.log.debug("packets: final bytes left in the buffer: %d" % (len(self.data)-offset,))
                yield offset, None
                break
            # ok, packet is in the buffer completely received
            else:
                packet_data = self.data[offset:offset+pl]
                packet = protocol.unpack(packet_data)
                no_packets += 1
                
                packet_dump = ""
                if Brocolli.DUMP_PACKET:
                    packet_dump = ":\n" + pprint.pformat(packet)
                self.log.debug("packets: debuffered data(#%d), len=%d %s" % (
                                                        no_packets,
                                                        pl,
                                                        packet_dump
                                                        ))
                

                # log bytes still unprocessed (its the next offset run)
                self.log.debug("packets: interim bytes left in the buffer: %d" % (len(self.data)-(offset+pl),))
                # yield this run offset, not next one
                yield offset,packet
                offset += pl
    
    def s_keepalive(self):
        now = time.time()
        
        if now > self.my_sync_sent + self.my_sync_interval:
            self.my_sync += 1
            self.my_sync_sent = now
            sync_item = protocol.pack_primitive(0x1,"int",self.my_sync)
            return protocol.wrap_bytes(0x86,sync_item)
    
    def s_send_all_you_have(self):
        self.my_sync += 1
        sync_item = protocol.pack_primitive(0x1,"int",self.my_sync)
        a_item = protocol.pack_primitive(48,"int",1)
        b_item = protocol.pack_primitive(49,"int",0)
        return protocol.wrap_bytes(131,sync_item+a_item+b_item)
 
       
    
    def run(self):
        self.applyConfig()
        self.log.warning("Based on reverse engineering! :-] ")

        
        while True:

            self.log.info("Starting Brocolli: part of the (in)famous FAAS project")
            s = socket.create_connection((self.lcol_ip, self.lcol_port),10.0)
            self.sock = s
            
            s.setblocking(0)
            
            # here was banner block

            while True:
                # set variable, which later tell us, if we hit socket.error (no data to read)
                NOT_READY = True

                # set to let buffer non-zeroized (waiting for the rest of data)
                WAIT_DATA = False                
                
                try:

                    self.data = self.data + s.recv(1024)
                    if len(self.data) == 0:
                        s.close()
                        self.log.error("Connection to fortinet collector aborted!")
                        break
                    
                    NOT_READY = False


                except socket.error,e:
                    NOT_READY = True
                    
                packet_len = protocol.packet_len(self.data)
                data_len = len(self.data)

                # Check if we shall loop
                if packet_len <= data_len:
                    if data_len:
                        self.log.debug("==> Received enough of bytes (%dB)" % (len(self.data),))
                        
                    WAIT_DATA = False
                else:
                    self.log.debug("==> waiting, incomplete packet (%dB/%dB)" % (len(self.data),packet_len))
                    WAIT_DATA = True                

               # Socket not READY. Lets do something useful
                if NOT_READY:
                    # ideal time to check the keepalives
                    keepalive_packet = self.s_keepalive()

                    # do we need to send keepalive?
                    if keepalive_packet:
                        dmp = ""
                        if Brocolli.DUMP_PACKET:
                            dmp = ":\n" + pprint.pformat(protocol.unpack(keepalive_packet))
                            
                        self.log.info(">> sending keepalive" + dmp)
                        s.sendall(keepalive_packet)
                # socket READY!
                else:
                    # Received data?
                    if len(self.data) > 0:
                        self.log.debug("Packet ready for processing (%sB)" % (len(self.data), ))
                        self.handle_fsae()

                # ok, be little-bit blocking here ....
                # time.sleep(0.15)
                select.select([s,],[],[],1.5)
                continue       




    def handle_fsae(self):
        for offset, packet in self.packets():
            if not packet:
                # if we got None as the packet, end of processible data are reached\
                # still -- that does not simply mean the buffer is actually empty !
                # move to that position
                self.data = self.data[offset:]
                if self.data:
                    self.log.debug("some bytes left in the buffer (%dB)" % (len(self.data)))
                
                break
            else:
                for data in packet:
                    self.handle_data(data)
    
    def handle_data(self,data):
        DATA_ERROR = 0
        try:
            id = data[0]
            len = data[1]
            msg = data[2]
            
            if id ==128:
                self.my_sync += 1
                
                pwd = b'fortinet'
                ch = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                for i,t,v in msg:
                    if i == 18:
                        ch = v
                self.log.info(">> sending challenge")
                if Brocolli.DUMP_PACKET: self.log.debug(pformat.pprint(ch))
                
                h = hmac.HMAC('fortinet')
                
                h.update('FG44FAAS00123456')
                #h.update('Brocolli v1.0.0')
                #h.update(pwd)
                h.update(ch)
                hh = h.digest()
                
                hello_sync = protocol.pack_primitive(0x1,"int",self.my_sync)
                hello_xxxx = protocol.pack_primitive(0x10,"int",0x20)
                #hello_auth = protocol.pack_primitive(0x11,"aut","\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01")
                hello_auth = protocol.pack_primitive(0x11,"aut","Brocolli v1.0.0\x00")
                hello_banner = protocol.pack_primitive(0x13,"aut","FG44FAAS00123456\x00\x00\x00\x00")
                #hello_auth2= protocol.pack_primitive(0x12,"aut","\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
                hello_auth2= protocol.pack_primitive(0x12,"aut",hh)

                hello_packet = protocol.wrap_bytes(0x80, hello_sync + hello_xxxx + hello_auth + hello_banner + hello_auth2)
                
                
                self.log.info(">> sending hello")
                if Brocolli.DUMP_PACKET: self.log.debug(pprint.pformat(protocol.unpack(hello_packet)))
                
                self.sock.sendall(hello_packet + self.s_send_all_you_have() ) 
                
            elif id == 132:
                self.log.info("<< incoming sync data")
                ul = self.handleUsers(msg)
                for u in ul: self.log.info(self.formatUser(u))
                
            elif id == 133:
                self.log.info("<< incoming new logon event")
                ul = self.handleUsers(msg)
                for u in ul: self.log.info(self.formatUser(u))
            elif id == 134:
                self.log.info("<< keepalive received")
                
        except IndexError,e:
            DATA_ERROR = 1
        except KeyError,e:
            DATA_ERROR = 1
        
        if DATA_ERROR:
            self.log.warning("Error in packet processing: \n" + pprint.pformat(data))

    def user_to_dict(self,data):
        d = {}
        for i,t,v in data:
            if i == 81: d["LOGGED_ON"] = v
            elif i == 82: d["IP"] = socket.inet_ntoa(struct.pack("I",socket.ntohl(v)))
            elif i == 83: d["WORKSTATION"] = v
            elif i == 84: d["DOMAIN"] = v
            elif i == 85: d["USERNAME"] = v
            elif i == 86: d["GROUPS"] = v
            elif i == 87: d["LOGON_TIMESTAMP"] = v
            elif i == 88: d["88"] = v
            elif i == 89: d["89"] = v
            else:
                self.log.info("Unknown user attribute '%d','%d','%s' " % (i,t,str(v)))
            
        return d


    def handleUsers(self,data):
        sync = data[0]
        u1 = data[1]
        u2 = data[2]
        container = data[3:]

        users = []

        for c in data:
            if c[0] == 80:
                user = c[2]
                u = self.user_to_dict(user)
                users.append(u)

                if Brocolli.DUMP_PACKET: self.log.debug("USER: \n" + pprint.pformat(u))
                #self.handleSession(self.createSessionKey(u),self.lcol_ip,u)
                
        return users

    def formatUser(self,u):
        
        try: 
            r = ''
            if u['LOGGED_ON']:
                r += 'LOGON '
            else:
                r += 'LOGOFF'

            r += ' IP: %s' % (u['IP'],)
            r += ' User: %s' % (u['USERNAME'],)
            r += ' Groups: %s' % (u['GROUPS'],) 
            r += ' Workstation: %s' % (u['WORKSTATION'],) 
            r += ' Domain: %s' % (u['DOMAIN'],) 
            r += ' CaSysTime: %s' % (u['LOGON_TIMESTAMP'],) 
            
            return r
        except KeyError, e:
            return '# format error: ' + str(u)


def parse_args():
    parser = argparse.ArgumentParser(description='Brocolli 1.0.0: Fake FortiGate connector to Fortinet Collector Agent',
                                     epilog="""Created by Ales Stibal, astibal@gmail.com (c) """)
    parser.add_argument('-ca','--collector', dest='ca',default='127.0.0.1:8000',
                       help='collector IP and port in form IP:PORT (default: 127.0.0.1:8000)')

    args = parser.parse_args()
    return parser,args


def main():
    parser, args = parse_args()
    
    try:
        ip = None
        port = 8000
        
        if ':' in args.ca:
            ip,port = args.ca.split(':')
        else:
            ip = args.ca

        b = Brocolli(ip,port)
        b.run()

            
    except socket.error,e:
        print "Socket error: " + str(e)
        

try:        
    main()
except KeyboardInterrupt, e:
    print "Interrupted!"

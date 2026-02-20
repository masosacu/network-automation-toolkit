#
# ProxyCA -- Proxy for Collector Agent
#          - FSAE/FSSO protocol analyzer
#
#          - Copyright Ales Stibal, astibal@gmail.com (c)
#

import time
import socket
import select
import pprint
import struct
import logging
import sys

from multiprocessing import Process, current_process, freeze_support
import threading

import hashlib
import hmac

import argparse


# FSSO protocol implementation
import fssolib.protocol as protocol


#if sys.platform == 'win32':
#    import multiprocessing.reduction    # make sockets pickable/inheritable


class ProxyCa:
    
    DUMP_PACKET = 1
    
    def __init__(self,ca_ip,ca_port=8000,in_port=9000,debug_level=0):
        self.log = None
        self.data = {}
        self.sock = {}
        
        self.my_sync = 0
        self.my_sync_interval = 60
        self.my_sync_sent = 0
        self.rem_sync = 0
        self.rem_sync_recv = 0

        self.banner = "ProxyCa 0.1.0"
        self.lcol_ip = ca_ip
        self.lcol_port = ca_port
        
        self.in_port = in_port
        self.debug_level = debug_level
        
    
    def applyConfig(self):
        
        self.log = logging.getLogger("proxyca")
        ch = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s: %(process)d: %(levelname)8s: %(message)s')
        ch.setFormatter(formatter)
        
        self.log.addHandler(ch)
        self.log.setLevel(logging.INFO)
        
        if self.debug_level > 0:
            self.log.setLevel(logging.DEBUG)
        if self.debug_level > 1:
            ProxyCa.DUMP_PACKET = 1
        
        

        

    
    # FIXME: copy-paste from fsaehandler
    # method, which runs through the buffer (self.data) and is giving out unpacked structures
    # coming from FortiGate
    def packets(self,socket_name,raw=False):
        offset = 0
        no_packets = 0
        while True:
            # we need at least 6 bytes to parse length of the packet
            if offset + 6 > len(self.data[socket_name]):
                self.log.debug("[%s] packets: final bytes left in the buffer: %d" % (socket_name,len(self.data[socket_name])-offset,))
                yield offset, None
                break
            # still we can reach end of buffer in the middle of the packet
            pl = protocol.packet_len(self.data[socket_name][offset:])
            if offset + pl > len(self.data[socket_name]):
                self.log.debug("[%s] packets: final bytes left in the buffer: %d" % (socket_name,len(self.data[socket_name])-offset,))
                yield offset, None
                break
            # ok, packet is in the buffer completely received
            else:
                packet_data = self.data[socket_name][offset:offset+pl]
                packet = protocol.unpack(packet_data)
                no_packets += 1
                
                packet_dump = ""
                if ProxyCa.DUMP_PACKET:
                    packet_dump = ":\n" + pprint.pformat(packet)
                self.log.debug("[%s] packets: debuffered data(#%d), len=%d %s" % (
                                                        socket_name,
                                                        no_packets,
                                                        pl,
                                                        packet_dump
                                                        ))
                

                # log bytes still unprocessed (its the next offset run)
                self.log.debug("[%s] packets: interim bytes left in the buffer: %d" % (socket_name,len(self.data[socket_name])-(offset+pl),))
                # yield this run offset, not next one
                yield offset,packet
                offset += pl
                        
            self.data[socket_name] = self.data[socket_name][offset:]
            if self.data[socket_name]:
                self.log.debug("[%s] some bytes left in the buffer (%dB)" % (socket_name,len(self.data)))
    
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
        
        
        # while True:
        
        self.log.info("Waiting for the Fortigate to proxy..")
        host = ''
        ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ss.bind((host, self.in_port))
        ss.listen(1)

        plist = []

        try:
            while True:
                conn, addr = ss.accept()
                #p = Process(target=self.proxy,args=(conn,addr[0]))
                p = Process(target=s_proxy,args=(multiprocessing.reduction.reduce_handle(conn.fileno()),addr[0]))
                plist.append(p)
                p.start()

        except KeyboardInterrupt, e:
            print "Interrupted!"

        ss.close() 
        for p in plist:
            p.join()
            
      # end of while  
            

    def proxy(self,conn,addr):
        try:
            self.log.info("Accepting connection from %s" % (addr,))        

            self.data["fgt"] = ""
            self.sock['fgt'] = conn

            self.log.info("Starting CA connection to %s:%s" % (self.lcol_ip, self.lcol_port))
            s = socket.create_connection((self.lcol_ip, self.lcol_port),10.0)
            self.sock['ca'] = s
            self.data['ca'] = ""

            self.sock['fgt'].setblocking(0)
            self.sock['ca'].setblocking(0)


            r_ready, w_ready, x_ready = [],[],[]

            while True:

                if self.sock['fgt'] in r_ready: 
                    if self.read_socket('fgt'):
                        if not self.data['fgt']: 
                            self.sock['ca'].close()
                            break

                        self.log.info(">>> Fortigate:")
                        for o,p in self.packets('fgt'):
                            if not p: break

                            l = pprint.pformat(p,indent=4)
                            for ll in l.split('\n'): self.log.info(ll)
                            self.write_socket('ca',self.packet_bytes('fgt',o))
                            self.log.info("<<<")
                            self.handle_data(p[0])

                if self.sock['ca'] in r_ready: 
                    if self.read_socket('ca'):
                        if not self.data['ca']: 
                            self.sock['fgt'].close()
                            break

                        self.log.info(">>> Collector:")
                        for o,p in self.packets('ca'):
                            if not p: break

                            l = pprint.pformat(p,indent=4)
                            for ll in l.split('\n'): self.log.info(ll)
                            self.write_socket('fgt',self.packet_bytes('ca',o))
                            self.log.info("<<<")
                            self.handle_data(p[0])

                r_ready, w_ready, x_ready = select.select(self.sock.values(),[],[])
        except KeyboardInterrupt, e:
            self.log.warning("Interrupted!")


    def packet_bytes(self,socket_name,offset):
        d = self.data[socket_name]
        l = protocol.packet_len(d[offset:])
        return d[offset:l]


    def read_socket(self,socket_name):
        i = socket_name
        try:
            self.data[i] = self.data[i] + self.sock[socket_name].recv(1024)
            if len(self.data[i]) == 0:
                self.sock[socket_name].close()
                self.log.error("[%s] connection aborted!" % (i,))
                self.data[i] = None
                return True

        except socket.error,e:
            pass

        packet_len = protocol.packet_len(self.data[i])
        data_len = len(self.data[i])

        if data_len >= packet_len:
            self.log.debug("[%s] ==> Received enough of bytes (%dB)" % (i,len(self.data[i]),))
            self.log.debug("[%s] ... Packet ready for processing (%sB)" % (i,len(self.data[i]), ))
            return True

        else:
            self.log.debug("[%s] ==> waiting, incomplete packet (%dB/%dB)" % (i,len(self.data[i]),packet_len))

        return False


    def write_socket(self,socket_name,data):
        i = socket_name
        self.sock[i].sendall(data)


    def handle_data(self,data):
        DATA_ERROR = 0
        try:
            id = data[0]
            len = data[1]
            msg = data[2]
            
            if id ==128:

                self.log.info("sync message")
                
            elif id == 132:
                self.log.info("logon sync")
                ul = self.handleUsers(msg)
                for u in ul: self.log.info(self.formatUser(u))
                
            elif id == 133:
                self.log.info("new event")
                ul = self.handleUsers(msg)
                for u in ul: self.log.info(self.formatUser(u))
            elif id == 134:
                self.log.info("keepalive message")
                
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
            elif i == 93: d["PORT_RANGE_SIZE"] = v
            elif i == 92:
                if 'PORT_RANGES' not in d.keys():
                    d["PORT_RANGES"] = []
                
                b = struct.pack('L', long(v))
                b1 = struct.unpack('H',b[0:2])
                b2 = struct.unpack('H',b[2:4])
                d["PORT_RANGES"].append((b2[0],b1[0]))
                    
            else:
                self.log.info("Unknown user attribute '%d','%d','%s'" % (i,t,str(v)))
            
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

                if ProxyCa.DUMP_PACKET: self.log.debug("USER: \n" + pprint.pformat(u))
                
        return users

    def formatUser(self,u):
        
        try: 
            r = ''
            if u['LOGGED_ON']:
                r += 'LOGON '
            else:
                r += 'LOGOFF'

            r += ' IP:%s' % (u['IP'],)
            r += ' User:%s' % (u['USERNAME'],)
            r += ' Groups:%s' % (u['GROUPS'],) 
            r += ' Workstation:%s' % (u['WORKSTATION'],) 
            r += ' Domain:%s' % (u['DOMAIN'],) 
            r += ' CaSysTime:%s' % (u['LOGON_TIMESTAMP'],) 
            
            if 'PORT_RANGE_SIZE' in u.keys():
                r += ' Ranges:%d' % (u['PORT_RANGE_SIZE'],)
                
            if 'PORT_RANGES' in u.keys():
                r += ' Range list:%s' % (str(u['PORT_RANGES']),)
            
            return r
        except KeyError, e:
            return '# format error: ' + str(u)


def parse_args():
    parser = argparse.ArgumentParser(description='ProxyCa 0.1.0: Proxy for CA <-> Fortigate communication analysis',
                                     epilog="""Created by Ales Stibal, astibal@gmail.com (c) """)
    parser.add_argument('-ca','--collector', dest='ca',default='127.0.0.1:8000',
                       help='collector IP and port in form IP:PORT (default: 127.0.0.1:8000)')
    parser.add_argument('-l','--listen-port', dest='in_port',default='9000',
                       help='port, where Fortigates will be connecting')
                       
    parser.add_argument('-d','--debug', dest='debuglevel',default=0,
                       help='set verbosity to debug')

    args = parser.parse_args()
    return parser,args


def s_proxy(conn,addr,ip,port,in_port):
    try:
        #ss = multiprocessing.reduction.rebuild_handle(conn)
        #sss= socket.fromfd(ss,socket.AF_INET,socket.SOCK_STREAM)
        print "Accepting connection from %s" % (addr,)
        c = ProxyCa(ip,port,int(in_port))
        c.applyConfig()
        c.proxy(conn,addr)
    except KeyboardInterrupt,e:
        print "Ctrl-C pressed: interrupted!"        



def global_run(ip,port,in_port):
    print "Based on reverse engineering! :-] "
    
    
    # while True:
    
    print "Waiting for the Fortigate to proxy.."
    host = ''
    ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ss.bind((host, int(in_port)))
    ss.listen(1)

    plist = []

    try:
        while True:
            conn, addr = ss.accept()
            p = threading.Thread(target=s_proxy,args=(conn,addr[0],ip,port,in_port))
            p.daemon = True
            plist.append(p)
            p.start()

    except KeyboardInterrupt, e:
        print "Interrupted!"

    ss.close() 
    for p in plist:
        if p.is_alive():
            pass

    sys.exit()
        
  # end of while  


def main():
    parser, args = parse_args()
    
    try:
        ip = None
        port = 9000
        in_port = 9000
        
        if ':' in args.ca:
            ip,port = args.ca.split(':')
        else:
            ip = args.ca

        if args.in_port:
            in_port = args.in_port

        global_run(ip,port,in_port)
            
    except socket.error,e:
        print "Socket error: " + str(e)
        

if __name__ == '__main__':
    freeze_support()
    main()


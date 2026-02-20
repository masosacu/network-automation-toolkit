# -*- coding: utf-8 -*-
import socket
import struct
import tools
import time

import SocketServer

class Ftnt_CollectorHandler(SocketServer.BaseRequestHandler):

    def handle(self):
        data = self.request[0]
        sock = self.request[1]
        #print "%s wrote:" % self.client_address[0]
        

        header_fmt='>HLL'
        length,timstamp,ip = struct.unpack(header_fmt,data[0:10])
        data_offset = struct.calcsize(header_fmt)
        data_length = struct.unpack('>H',data[data_offset:data_offset+2])[0]
        data = struct.unpack((">%ds" % data_length),data[data_offset+2:data_offset+2+data_length])

        if ip == 0xffffffff:
            print "Received keepalive from %s: %s/%s" % (time.ctime(timstamp),self.client_address[0],data[0])

        else:
            ip_str = socket.inet_ntoa(struct.pack('>L',ip))
            print "Received logon from %s: %s/%s" % (time.ctime(timstamp),ip_str,data[0])

if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 8002

    server = SocketServer.UDPServer((HOST, PORT), Ftnt_CollectorHandler)
    server.serve_forever()
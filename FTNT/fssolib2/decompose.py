import SocketServer
import pprint
import argparse

import fssolib.protocol as protocol
import fssolib.tools as tools

class Decomposer(SocketServer.BaseRequestHandler):

    def handle(self):
        self.data = self.request.recv(10240)
        
        #print repr(self.data)
        # return 
        
        for i in range(0,500):
            try:
                d = protocol.unpack(self.data[i:])
                
                print " ====== Raw data at the begining ======" 
                print tools.hexdump(self.data[0:i])
                print " ====== Protocol data at byte index %d ======" % (i,)
                pprint.pprint(d)
                print " ====== "
                break
            except KeyError:
                pass
            except protocol.error:
                pass


def parse_args():
    parser = argparse.ArgumentParser(description="""Decopose is fsso data structure parser""",
                                     epilog="""Created by Ales Stibal, astibal@gmail.com (c) """)
    parser.add_argument('-l','--listen-port', dest='in_port',default='9999',
                       help='feed me here with data containing fsso structures ')


    args = parser.parse_args()
    return parser,args

if __name__ == "__main__":
    
    print "Feed me with fsso structures (with netcat)! You can start with LogonCache.dat ;)"
    
    parser, args = parse_args()
    in_port = 9999

    if args.in_port:
        in_port = int(args.in_port)    
    
    HOST, PORT = "localhost", in_port

    server = SocketServer.TCPServer((HOST, PORT), Decomposer,bind_and_activate=False)
    server.allow_reuse_address = True
    server.server_bind()
    server.server_activate()
    server.serve_forever()

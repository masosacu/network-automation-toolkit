import time
import argparse

import fssolib.fsaehandler as fsaehandler
import fssolib.generator as generator
import fssolib.fgtauthlist as fgtal

FNM=None

class FSSOAuthListUserHandler(fsaehandler.FSAE_Handler):
    
    def setup(self):
        global FNM
        
        fsaehandler.FSAE_Handler.setup(self)
        
        self.users = []
        self.all_users = []
        self.tick = time.time();
        self.auth_list = fgtal.FgtAuthList(FNM);
        self.cont = True
        self.end_reached = False
        self.interval = 5
        self.roundno = 0
    
    def on_connected(self):
        pass
    
    def on_idle(self):
        
        t = time.time()
        
        if t >= self.tick + self.interval and self.cont:
        
            self.tick = t
            if self.end_reached:
                self.log.info("-- end of the list --")
                return
            
            self.roundno += 1
            
            # self.users = [] ### do stuff here!
            self.users = list(self.auth_list.logons_diff()[0].values())
            
            
            if len(self.users) > 1000:
                #self.users = self.users[500:520]
                #self.cont = False
                pass
            
            if self.roundno > 0:
                self.interval = 0.03
            
            try:
                self.auth_list.next()
                self.log.info("round %d update size %d" % (self.roundno, len(self.users),))
            except StopIteration:
                self.log.warning("end of list reached")
                self.end_reached = True
                self.interval = 60
            
            
    def get_users(self,all=False):
        return self.users
    
    def on_push_post(self):
        self.users  = []
        # this erases current users


def parse_args():
    parser = argparse.ArgumentParser(description="""fssoreplay, tool to resend users from 'diag debug auth list'""",
                                     epilog="""Created by Ales Stibal, astibal@gmail.com (c) """)
    parser.add_argument('-l','--listen-port', dest='in_port',default='8000',
                       help='port, where Fortigates will be connecting')

    parser.add_argument('-f','--file', dest='fnm',default=None,
                       help="file containing 'diag debug auth fsso list' output from Fortigate")
                       
    parser.add_argument('-d','--debug', dest='debuglevel',default=0,
                       help='set verbosity to debug')

    args = parser.parse_args()
    return parser,args


def main():
    global FNM
    parser, args = parse_args()
    in_port = 8000

    if args.in_port:
        in_port = int(args.in_port)
        
    if args.fnm:
        FNM = args.fnm
    else:
        print "WARNING: no file specified. No FSSO users will be sent."
        time.sleep(2)

    try:        
        fsaehandler.runServer(('0.0.0.0',in_port),FSSOAuthListUserHandler)
    except KeyboardInterrupt:
        print "Bailing."
        
        
if __name__ == '__main__':
    main()
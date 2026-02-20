import time
import struct
import socket

class RandomUsers:
    
    def __init__(self,log):
        
        self.ip_start = struct.unpack('>I',socket.inet_aton("10.0.0.1"))[0] 
        
        self.tick = time.time()
        self.ip_incr = self.ip_start
        self.port_range_max = 1024
        self.users = []
        self.all_users = []
        self.log = log
        self.group_filter = ["cn=somegroup,dc=somedomain",]

    def set_group_filter(self,grpf):
        self.group_filter = grpf

    def generate(self,count=1,port_ranges=False):
        
        if(len(self.all_users) < 100000):
            self.log.info("generating new users")
            self.users = self.generate_new_users_(count,port_ranges)
            self.all_users.extend(self.users)
        else:
            self.log.info("logging all users")
            for u in self.all_users:
                u['LOGGED_ON'] = 0
            
            # send all users
            self.users = self.all_users
            
            # reset state to continue from begining
            self.all_users = []
            self.ip_incr = self.ip_start
            self.port_range_max = 1024
            self.tick = time.time()
            
        return self.users
            
    
    def generate_new_users_(self,count=1,port_ranges=False):

        ret = []
        counter = 0
        while True:
            u = {}
            u['LOGGED_ON'] = 1
            u['LOGON_TIMESTAMP'] = self.tick
            u['IP'] = socket.inet_ntoa(struct.pack('>I',self.ip_incr))
            u['USERNAME'] = "user%d-%X" % (self.tick,self.ip_incr)
            u['WORKSTATION'] = "WKS%d-%X" % (self.tick,self.ip_incr)
            u['DOMAIN'] = "DOMB"
            u['USER_DN'] = self.group_filter[0]

            
            if port_ranges:
                u['PORT_RANGES'] = []
                
                ### port range 1
                port_max = self.port_range_max + 200 - 1
                u['PORT_RANGES'].append((self.port_range_max,port_max,))
                self.port_range_max = port_max + 1

                ### port range 2
                port_max = self.port_range_max + 200 - 1
                u['PORT_RANGES'].append((self.port_range_max,port_max,))
                self.port_range_max = port_max + 1

                u['PORT_RANGE_SIZE'] = len(u['PORT_RANGES'])
            
            self.ip_incr += 1
            
            ret.append(u)
            
            counter += 1
            if counter >= count:
                break
        
        return ret
    
    
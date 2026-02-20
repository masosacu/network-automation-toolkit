import pprint
# -*- coding: utf-8 -*-

import protocol
import tools
import exceptions

import time
import struct
import socket

# set up the logging features
import sys
import logging
import logging.handlers


class error(Exception):
    pass

class exchange():
  
    SERVER_KEEPALIVE=10
    CLIENT_KEEPALIVE=60
  
    def __init__(self, version, sync_start,logging_level=logging.INFO):
      self.version = version
      self.sync_start = sync_start
      self.sync = self.sync_start
      self.sync_sent = 0
      self.set_logger(logging_level=logging_level)
      self.ldap_filter = []

    # Set instance logging to @logger. If ommited, create default stdout logger instead.
    # Unless @forclass set to False, rewrite class default logger too.
    def set_logger(self,logger=None,forclass=True,logging_level=logging.INFO):
        if not logger:
            newlog = logging.getLogger("fsae_parser")
            formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(formatter)
            newlog.addHandler(handler)
            newlog.setLevel(logging_level)

            self.log = newlog
        else:
            self.log = logger

        if forclass:
            exchange.log = self.log

    # sorry for spaghetti code, seemed to me useful to have a logical alias
    def get_logger(self):
        return self.get_instance_logger()

    def get_instance_logger(self):
        return self.log

    def get_default_logger(self):
        return exchange.log

    def s_hello_packet(self):
      self.sync+=1
      sync = protocol.pack_primitive(0x1,"int",self.sync)
      xxxx = protocol.pack_primitive(0x10,"int",2)
      banner = protocol.pack_primitive(0x11,"str","FSAE server %s" % (self.version))
      chall = protocol.pack_primitive(0x12,"aut","\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
      ser_id = protocol.pack_primitive(0x13,"aut","FSAE_SERVER_10001")
      
      hello_p = protocol.wrap_bytes(0x80,sync + xxxx + banner + chall + ser_id)
      
      return hello_p
      
    def r_hello_packet(self,data):
      
      self.log.debug("received HELLO data")
      reply = protocol.unpack(data)

      
      reply_code = reply[0][0]
      reply_datatype = reply[0][1]
      reply_data = reply[0][2]
      
      fgt_name = None
      fgt_sync = 0
      
      if reply_code != 0x80:
        return False, None, None
      
      for item in reply_data:
        if item[0] == 0x13:
            if item[1] == protocol.T2B["aut"]:
              fgt_name = item[2]
        elif item[0] == 0x1:
            if item[1] == protocol.T2B["int"]:
              fgt_sync = item[2]
      
      # initialize sync between client and server
      self.fgt_name = fgt_name
      self.c_sync_start = fgt_sync
      self.c_sync = self.c_sync_start
      self.c_sync_seen = time.time()
      
      
      return  True, fgt_name, fgt_sync
      
    def s_auth_accept(self, status):
      sync = protocol.pack_primitive(0x1,"int",self.c_sync)
      s = protocol.pack_primitive(0x90,"int",status)

      packet = protocol.wrap_bytes(0x87, sync + s )
      self.log.debug("sending auth packet:")
      self.log.debug("\n" + tools.hexdump(packet))
      
      return packet
      
    def s_keepalive(self):
      now = time.time()
      delta = now - self.sync_sent

      if delta > self.SERVER_KEEPALIVE:
        
          if delta > 2*self.SERVER_KEEPALIVE and self.sync_sent != 0:
            self.log.warning("sent delayed keepalive")
        
          self.sync += 1
          self.sync_sent = now

          sync_item = protocol.pack_primitive(0x1,"int",self.sync)
          return protocol.wrap_bytes(0x86,sync_item)

      return None
    
    # set client sync according received value. 
    # return delta (number of missed syncs+1) ... thus returning 1 means all is ok
    # 
    def set_c_sync(self,value):
      delta = value - self.c_sync
      if delta != 1:
          self.log.warning("keepalive id mismatch (normal after NYI)")

      self.c_sync = value
      self.c_sync_seen = time.time()
      self.log.debug("... keepalive: server=%d, client=%s" % (self.sync, self.c_sync))

      return delta
    
    def r_keepalive(self,data):
      try:
        reply = data[0]

        self.log.debug("... keepalive: %s" % (reply,))
        if reply[0] != 0x86:
          self.log.error("... this is not a keepalive packet!")

        code,type,value = reply[2][0]
        # is it really keepalive?
        if code == 0x1 and type == 3:
            if value - self.c_sync_seen > 2*self.CLIENT_KEEPALIVE:

                #FIXME: keepalives are sent frequently. If delayed, at least log it. 
                # it is questionable how to act, if restart session or let it live as it is.
                
                self.warning("delayed keepalive!")
            else:
                #FIXME: if > 1 there were missed requests
                self.set_c_sync(value)
                return True

        # if you got here, it is not keepalive packet
        return False
        
      except IndexError,e:
        self.log.error("Keepalive: exception caught: %s" % (str(e),))
        raise error("FSAE","keepalive error")
      except struct.error,e:
        self.log.error("Keepalive: exception caught: %s" % (str(e),))
        raise error("FSAE","keepalive error")

    def r_sendall(self, data):
        try:
            d = tools.make_dict(data)

            #self.log.debug("REQUEST: %s" % (str(d)))
            #self.log.debug(pprint.pformat(d))

            # little 'addressing' hell follows..., small hit: after HEX keys use [0]
            sync = d[0x83][0]['value'][0x1][0]['value']
            unk1 = d[0x83][0]['value'][0x30][0]['value']
            unk2 = d[0x83][0]['value'][0x31][0]['value']
            
            self.log.debug("Sendall request sync=%d,unk1=%d,unk2=%d" % (sync,unk1,unk2))
            self.set_c_sync(sync)

            return True, sync

        except IndexError, e:
            self.log.error("Packet parse error: %s" % (str(e),))
            return False, 0
        except KeyError, e:
            self.log.error("Packet parse error: %s" % (str(e),))
            return False, 0
        except struct.error,e:
            self.log.error("Packet parse error: %s" % (str(e),))
            return False, 0


    def user_to_bytes(self,d):
        u_51 = 0
        u_58 = 0
        if d['LOGGED_ON'] > 0:
            u_51 = 1
            u_58 = 0
        else:
            u_51 = 0
            u_58 = 1

        UN1 = protocol.pack_primitive(0x51, 'int', u_51)
        UN2 = protocol.pack_primitive(0x58, 'int', u_58)
        
        
        UN3 = protocol.pack_primitive(0x59, 'int', 1)
        if "PORT_RANGE_SIZE" in d.keys():
            UN3 = protocol.pack_primitive(0x59, 'int', 16)
        
        IP = protocol.pack_primitive(0x52, 'ip', d['IP'])
        LOGON_TIMESTAMP = protocol.pack_primitive(0x57, 'int', int(d['LOGON_TIMESTAMP']))
        WORKSTATION = protocol.pack_primitive(0x53, 'str', d['WORKSTATION'])
        DOMAIN = protocol.pack_primitive(0x54, 'str', d['DOMAIN'])
        USERNAME = protocol.pack_primitive(0x55, 'str', d['USERNAME'])
        USER_DN = protocol.pack_primitive(0x56, 'str', self.ldap_do_filter(d['USER_DN']))
        
        to_wrap_bytes = UN1 + UN2 + UN3 + IP + LOGON_TIMESTAMP + WORKSTATION + DOMAIN + USERNAME + USER_DN;
        
        
        ### !!! READ 
        ### this has to be fixed. PORT_RANGE_SIZE is actually SESSION_ID. 
        ### Users on the same IP have to have different SESSION_ID. 
        ### Here we simply guess (but it works quite well) but there
        ### should be SESSION_ID in the dict added later
        PORT_RANGE_SIZE = None
        if "PORT_RANGE_SIZE" in d.keys():
            #PORT_RANGE_SIZE = protocol.pack_primitive(93,'int',int(d["PORT_RANGE_SIZE"]))
            # quick hack to test
            wks_l = d['WORKSTATION'].split("!")
            if len(wks_l) > 1:
                session_id = int(wks_l[-1],16)
                PORT_RANGE_SIZE = protocol.pack_primitive(93,'int',session_id)

        PORT_RANGES = None
        if "PORT_RANGES" in d.keys():
            PORT_RANGES = ""
            for r in d["PORT_RANGES"]:
                b1 = r[1]
                b2 = r[0]
                b = struct.pack('HH',b1,b2)
                c = struct.unpack('I',b)[0]
                
                PORT_RANGES += protocol.pack_primitive(92,'int',int(c))

        if PORT_RANGE_SIZE and PORT_RANGES:
            to_wrap_bytes += PORT_RANGE_SIZE + PORT_RANGES

        return protocol.wrap_bytes(0x50, to_wrap_bytes)

    def ldap_do_filter(self,dn):
        
        if not dn:
            return ''
        
        self.log.debug("ldap_do_filter: groups unfiltered: " + dn);
        
        d = dn.split('+')
        #self.log.debug("ldap_do_filter: split: " + str(d));
        
        ret = []
        
        if not self.ldap_filter:
            return dn
        
        upper_dn = []
        for group in d:
            upper_dn.append(group.upper())
        
        for r in self.ldap_filter:
            if r.upper() in upper_dn:
                ret.append(r.upper())
        
        
        to_return = '+'.join(ret)
        self.log.debug("ldap_do_filter: group about to send: " + to_return);
    
        return to_return

    # when in bulk-mode, FSAE is able to accept all users in one update, so we returning *one* packet
    # non-bulk mode cant be used to send more users at once, so we must return *list* of packets to send
    def s_send_users(self,request_id,users,bulk=False):
        sync = protocol.pack_primitive(0x1,"int",request_id)



        users_bytes = ''

        if bulk:
            # if requestid is zero, we assume we should send ours sync
            if request_id == 0:
                self.sync+=1

            sync = protocol.pack_primitive(0x1,"int",self.sync)
            un1 = protocol.pack_primitive(0x60,"int",1)
            un2 = protocol.pack_primitive(0x61,"int",0)

            for user in users:
                try:
                    users_bytes+=self.user_to_bytes(user)
                except KeyError,e:
                    self.log.error("Error sending user=%s : %s" % (str(user),str(e)))
                    continue
                    
            return protocol.wrap_bytes(0x84,sync+un1+un2+users_bytes)
        else:
            un1 = protocol.pack_primitive(0x70,"int",0)
            packets = []
            for user in users:
                try:
                    # if requestid is zero, we assume we should send ours sync
                    if request_id == 0:
                        self.sync+=1
                    packets.append(protocol.wrap_bytes(0x85,sync+un1+self.user_to_bytes(user)))

                except KeyError,e:
                    self.log.error("Error sending user=%s : %s" % (str(user),str(e)))
            return packets


    def r_ldap_filter(self,packet):
        d = packet[0]
        id = d[0]
        type = d[1]
        container = d[2]
        
        keepalive_tuple = container[0]
        ldap_tuple = container[1]
        
        self.set_c_sync(keepalive_tuple[2])
        
        users_containers = container[2:]
        if len(users_containers):
            self.ldap_filter = []
            for user in users_containers:
                u1,u2,u = user
                dn = u[0][2]

                self.ldap_filter.append(dn)
                self.log.debug("LDAP new filter entry: " + dn)
        else:
            self.log.debug("LDAP emptying filter")
            self.ldap_filter = []

        
        
        
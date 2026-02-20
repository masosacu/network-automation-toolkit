# -*- coding: utf-8 -*-
import time
import socket
import select
import sys
import pprint
import traceback 

import SocketServer


import protocol
import fsae
import tools


PACKET_DEBUG=0


class FSAE_Handler(SocketServer.BaseRequestHandler):

    STATE_S_HELLO_WAIT = 1
    STATE_S_HELLO_SENT = 2
    STATE_C_HELLO_WAIT = 3
    STATE_C_HELLO_RCVD = 4
    STATE_S_ACCEPT_WAIT = 5
    STATE_S_ACCEPT_SENT = 6
    STATE_ESTABLISHED = 10
    STATE_GF_PUSHED = 11
    STATE_GF_ACCEPTED = 12
    STATE_C_WANTS_USERS = 13
    STATE_C_GOT_USERS = 14
    
    # last message from handshake is served
    STATE_C_IDLE = STATE_C_GOT_USERS

    # multiplexing firewalls
    # status is ass. array, where key connection ID (is the firewall IP:PORT)
    status = {}
    log = None

    def setup(self):
        self.com = fsae.exchange("1.1",100000)
        self.select_timeout = 0.02
        self.log = self.com.get_logger()
        FSAE_Handler.log = self.com.get_default_logger()

        #FIXME: this is not the right default value ;-)
        self.authenticated = True

    
    # FIXME: deliberately stolen from exchange class
    # Set instance logging to @logger. If ommited, create default stdout logger instead.
    # Unless @forclass set to False, rewrite class default logger too.
    def set_logger(self,logger=None,forclass=True):
        if not logger:
            newlog = logging.getLogger("fsae_handler")
            formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(formatter)
            newlog.addHandler(handler)
            newlog.setLevel(logging.INFO)

            self.log = newlog
        else:
            self.log = logger

        if forclass:
            FSAE_Handler.log = self.log

        self.com.set_logger(logger, forclass)

    # sorry for spaghetti code, seemed to me useful to have a logical alias
    def get_logger(self):
        return self.get_instance_logger()

    def get_instance_logger(self):
        return self.log

    # static function to return class logger
    def get_default_logger():
        return FSAE_Handler.log




    def auth_firewall_ip(self,firewall_ip):
        return True


    def handle(self):
      
        # self.request is the TCP socket connected to the client
        #elf.data = self.request.recv(1024)
        #rint tools.hexdump(self.data)

        if not self.auth_firewall_ip(self.client_address[0]):
            return False

        con_id = "%s:%d" % (self.client_address[0],self.client_address[1])
        if con_id not in FSAE_Handler.status.keys():
            self.log.info("New association request from: %s" % (con_id))
            FSAE_Handler.status[con_id] = self.STATE_S_HELLO_WAIT
        
        self.log.debug("FortiGate@%s: state=%d" % (con_id,FSAE_Handler.status[con_id]))
        #int tools.hexdump(self.data)
        
        # insert your favorite state machine
        # socket state note: we are using blocking state until entering main loop. 
        while True:
            try:
                # socket is open, we are ready to send banner and other payload
                if FSAE_Handler.status[con_id] == self.STATE_S_HELLO_WAIT:
                    self.log.debug("Sending banner and greetings...")
                    self.request.sendall(self.com.s_hello_packet())

                    # set state
                    FSAE_Handler.status[con_id] = self.STATE_S_HELLO_SENT
                    FSAE_Handler.status[con_id] = self.STATE_C_HELLO_WAIT 

                # we didn't receive client hello packet yet...
                elif FSAE_Handler.status[con_id] == self.STATE_C_HELLO_WAIT:
                    self.data = self.request.recv(1024)
                    
                    self.log.debug("Received client HELLO data:")
                    self.log.debug(tools.hexdump(self.data))
                    FSAE_Handler.status[con_id] = self.STATE_C_HELLO_RCVD
                    
                    
                    ret, fgt_sn, fgt_sync =  self.com.r_hello_packet(self.data)
                    fgt_sn = fgt_sn.strip()
                    
                    self.log.debug("Received HELLO from %s" % (fgt_sn,))
                    #FIXME: add your ACL logic here
                    if True:
                        self.log.info("Device %s authenticated, initializating..." % (fgt_sn,))
                        self.authenticated = True
                        FSAE_Handler.status[con_id] = self.STATE_S_ACCEPT_WAIT
                    else:
                        raise Exception("Device access has been denied by config rule")
                      
                elif FSAE_Handler.status[con_id] == self.STATE_S_ACCEPT_WAIT:
                    self.request.sendall(self.com.s_auth_accept(1))
                    FSAE_Handler.status[con_id] = self.STATE_S_ACCEPT_SENT
                
                elif FSAE_Handler.status[con_id] == self.STATE_S_ACCEPT_SENT:
                    FSAE_Handler.status[con_id] = self.STATE_ESTABLISHED
                    self.log.info("Connection with %s has been fully established" % (fgt_sn,))
                    #FIXME: start here keepalive thread
                    
                elif FSAE_Handler.status[con_id] == self.STATE_ESTABLISHED:
                    time.sleep(0.1)
                    # having something write/read?
                    self.log.debug("Entering state-machine established loop, unblocking socket")

                    # set variable, which later tell us, if we hit socket.error (no data to read)
                    NOT_READY = True
                    
                    # set to let buffer non-zeroized (waiting for the rest of data)
                    WAIT_DATA = False

                    # we have not to be blocking: we should do more stuff, that only receive
                    self.request.setblocking(0)
                    
                    self.on_connected()
                    
                    while True:
             
                        try:
                            # WAS: quick spot into the socket ;)
                            # IS: we cannot assume all data would come at once, make inner select loop
                            select.select([self.request,],[],[],self.select_timeout)
                            self.data += self.request.recv(1024)
                            
                            NOT_READY = False

                        except socket.error,e:
                            # we don't want to be using in-exception code too much, exit from here, it's anti-pattern
                            NOT_READY = True

                        packet_len = protocol.packet_len(self.data)
                        data_len = len(self.data)

                        if data_len == 0:
                            self.on_idle()

                        # Check if we shall loop
                        if packet_len <= data_len:
                            if data_len != 0:
                                self.log.debug("Received enough of data (%dB)" % (len(self.data),))
                            else:
                                pass
                                #self.log.debug("Idle call")
                                
                            WAIT_DATA = False
                        else:
                            self.log.debug(".... for more data (%dB/%dB)" % (len(self.data),packet_len))
                            WAIT_DATA = True
                            
                            
                        # Socket not READY. Lets do something useful
                        if NOT_READY:
                            # ideal time to check the keepalives
                            keepalive_packet = self.com.s_keepalive()
                            
                            # do we need to send keepalive?
                            if keepalive_packet:
                                self.log.debug("Sending keepalive")
                                self.request.sendall(keepalive_packet)

                            # get updated users from DB
                            users_to_send = self.get_users(all=False)
                            
                            if users_to_send:
                                self.on_push_pre()
                                self.log.debug("Logon users changes: %d" % len(users_to_send))
                                
                                counter = 0
                                for user in users_to_send:
                                    counter += 1
                                    if user['LOGGED_ON'] == 1:
                                        #self.log.info("LOGON user[%d]: %s:%s on %s" % (counter,user['USERNAME'],user['USER_DN'],user['IP']))
                                        self.log.debug("LOGON  user[%d]: %s" % (counter,str(user)))
                                    else:
                                        #self.log.info("LOGOFF user[%d]: %s:%s on %s" % (counter,user['USERNAME'],user['USER_DN'],user['IP']))
                                        self.log.debug("LOGOFF user[%d]: %s" % (counter,str(user)))

                                counter = 0
                                for user_bytes in self.com.s_send_users(0,users_to_send,bulk=False):
                                    counter += 1
                                    self.log.debug("LOGIN/LOGOFF: Sending updates[%d]" % (counter,))
                                    self.writesocket(user_bytes)
                                
                                #self.log.debug("LOGIN/LOGOFF: Sending BULK update")
                                #tosend = self.com.s_send_users(0,users_to_send,bulk=True)
                                #self.writesocket(tosend)
                                
                                self.on_push_post()

                            select.select([self.request,],[],[],self.select_timeout)
                            if WAIT_DATA:
                                continue

                        # socket READY!
                        #else:
                        if not WAIT_DATA:
                            # Received data?
                            if len(self.data) > 0:
                                self.log.debug("Firewall request in state-machine established loop (%sB):" % (len(self.data), ))
                                self.handle_fsae(con_id)
                                
                            # READY and len==0? That indicates end of the life of the socket. Bye.
                            #else:
                            elif not NOT_READY:
                                self.log.warning("Network connection to the firewall device died. Ending the session.")
                                return

                        # set conditions to break ESTABLISHED loop
                        if False:
                            self.log.debug("Restoring socket blocking state")
                            self.request.setblocking(1)
                            break
                            
                    ### END OF ESTABLISHED LOOP

                # wait! we should not be here. Reset state and shutdown FSM
                else:
                    self.log.critical("unknown state or not yet implemented, exiting state-machine loop.")
                    self.request.setblocking(1)
                    del FSAE_Handler.status[con_id]
                    break

            except Exception, e:
                if str(e) == "stop":
                    self.log.info("Instructing to stop.")
                    return
                else:
                    self.log.error("General error: %s" % (str(e)))
                    self.log.debug(str(traceback.format_exc()))
                    self.log.debug("Data dump:")
                    self.log.debug("\n" + tools.hexdump(self.data))
                    self.log.info("Firewall session will be restarted.")
                    time.sleep(5)
                    
                    break

    def on_connected(self):
        pass

    def on_group_filter_change(self):
        pass

    def on_push_pre(self):
        pass
    
    def on_push_post(self):
        pass

    def on_idle(self):
        pass

    # This method is intended to be overided
    def get_users(self, all=False):
        return []




    # process all incomming data. Data can contain
    def handle_fsae(self,con_id):
        global PACKET_DEBUG
        if PACKET_DEBUG > 0:
            self.log.debug("Received data dump:\n %s" % (tools.hexdump(self.data),))
            try:
                self.log.info("Received data decomposition:\n %d:\n %s" % 
                    (protocol.packet_len(self.data),pprint.pformat(protocol.unpack(self.data)),)
                )
            except Exception, e:
                self.log.debug("Error decomposing data: " + str(e))
        ####
        
        for offset, packet in self.packets():
            if not packet:
                # if we got None as the packet, end of processible data are reached\
                # still -- that does not simply mean the buffer is actually empty !
                self.data = self.data[offset:]
                break
            else:
                if not self.handlePacket(packet,con_id):
                    id = protocol.packet_id(self.data[offset:])
                    plen = protocol.packet_len(self.data[offset:])
                    self.log.warning("Not implemented yet: packet_id=0x%x" % id)
                    self.log.debug("Packet dump:\n++++++++++ \n%s\n++++++++++" % (tools.hexdump(self.data[offset:offset+plen]),))

                    try:
                        self.log.debug("Decomposition attempt:\n++++++++++\n" + str(protocol.unpack(self.data[offset:offset+plen])) + "\n++++++++++")
                    except Exception, e:
                        self.log.debug("Decomposition attempt:\n failed: " + str(e))          
        

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
                self.log.debug("packets: debuffered data(#%d), len=%d:\n%s:" % (
                                                        no_packets,
                                                        pl,
                                                        pprint.pformat(packet)
                                                        ))
                

                # log bytes still unprocessed (its the next offset run)
                self.log.debug("packets: interim bytes left in the buffer: %d" % (len(self.data)-(offset+pl),))
                # yield this run offset, not next one
                yield offset,packet
                offset += pl

    def handlePacket(self,packet,con_id):
        id,type,body = packet[0]

        if id == 131:   # 0x83 = Send all logons
            self.log.info("FortiGate: requested to send all users we have")
            proceed,request_id =  self.com.r_sendall(packet)
            if proceed:
                FSAE_Handler.status[con_id] = self.STATE_C_WANTS_USERS
                self.on_push_pre()
                tosend = self.com.s_send_users(request_id,self.get_users(all=True),bulk=True)
                #self.writesocket(tosend)
                self.request.sendall(tosend)
                self.on_push_post()
                FSAE_Handler.status[con_id] = self.STATE_C_GOT_USERS

        elif id == 130:  #0x82 = ldap filter
           
           self.log.info("FortiGate: requested LDAP filtering")

           if self.com.sync - self.com.sync_start > 1:
               FSAE_Handler.status[con_id] = self.STATE_GF_PUSHED
               self.log.info("FortiGate: Filter changed: send all we have")
               self.com.r_ldap_filter(packet)
               self.on_group_filter_change()

               self.on_push_pre()
               tosend = self.com.s_send_users(self.com.sync,self.get_users(all=True),bulk=True)
               self.writesocket(tosend)
               self.on_push_post()
               self.log.info("FortiGate: Filter changed: applied to firewall")
               FSAE_Handler.status[con_id] = self.STATE_GF_ACCEPTED
           else:
               FSAE_Handler.status[con_id] = self.STATE_GF_PUSHED
               self.com.r_ldap_filter(packet)
               self.on_group_filter_change()
               self.log.info("FortiGate: Initial LDAP filter setup")
               FSAE_Handler.status[con_id] = self.STATE_GF_ACCEPTED


        elif id == 134:   # 0x86 = keepalive
           self.log.info("FortiGate: keepalive received")
           self.com.r_keepalive(packet)
        else:
            self.log.info("FortiGate: unimpledmented message id=%d" % (id,))
            return False

        return True

    def writesocket(self,data):
        sent = 0
        bufftop = 0
        while sent < len(data):
            
            try:
                s = self.request.send(data[sent:])
            except socket.error:
                self.log.info("socket full, waiting")
                rx,tx,ex = select.select([],[self.request,],[],1)
                continue
            
            if s >= 0:
                sent += s
                self.log.debug("Sent %d out of %d bytes" % (sent,len(data)))
            else:
                self.log.debug("Sent %d out of %d bytes" % (sent,len(data)))



class ForkedTCPServer(SocketServer.ForkingMixIn, SocketServer.TCPServer):
    pass

def runServer(host_port, handlerClass):
    server = ForkedTCPServer(host_port, handlerClass,bind_and_activate=False)
    server.allow_reuse_address = True
    server.server_bind()
    server.server_activate()
    server.serve_forever()




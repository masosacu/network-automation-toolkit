import fssolib.fsaehandler as fsaehandler
import fssolib.generator as generator
import time


class FSSORandomUserHandler(fsaehandler.FSAE_Handler):
    
    def setup(self):
        fsaehandler.FSAE_Handler.setup(self)
        
        self.users = []
        self.all_users = []
        self.tick = time.time();
        self.randoms = generator.RandomUsers(self.log)
    
    def on_group_filter_change(self):
        if len(self.com.ldap_filter) > 0:
            self.randoms.set_group_filter(self.com.ldap_filter)
    
    
    def on_idle(self):
        #self.log.debug("FSSORandomUserHandler: on_idle")
        t = time.time()
        if t > self.tick + 5:
            self.tick = t
            self.users = self.randoms.generate()
            
            
    def get_users(self,all=False):
        return self.users
        

    
    def on_push_post(self):
        self.users  = []

fsaehandler.runServer(('0.0.0.0',8000),FSSORandomUserHandler)

import re
import time
import pprint

""" returns tuple ot two lists:
     first:  items in 'b' which are not in 'a'   (logon in this module usage)
     second: items in 'a' which are mpt in 'b' (logoffs...)
"""
def dict_key_diff(a,b):

    added = {}
    removed = {}
    
    for a_k in a.keys():
        if a_k not in b.keys():
            removed[a_k] = a[a_k]

    for b_k in b.keys():
        if b_k not in a.keys():
            added[b_k] = b[b_k]
            
    return added,removed
            
    


class FgtAuthList:
    
    def __init__(self,fnm):
        self.fnm = fnm
        self.fd = None
        self.re_fsso_list_entry = r"IP: (?P<IP>\d+\.\d+\.\d+\.\d+)  User: (?P<username>[\d\w=, \/.]+)  Groups: (?P<groups>[\d\w=, \/_+-.]+)  Workstation: (?P<workstation>[\d\w.!_-]+)?"
        self.reC_fsso_list_entry = re.compile(self.re_fsso_list_entry)
        self.logoffs_logons = {},{}
        self.logons_ = {}
        self.list_generator = None
        
        if self.fnm:
            if self.fnm.endswith(".gz"):
                import gzip
                self.fd = gzip.open(self.fnm,'r')
                
            else:
                self.fd = open(self.fnm,'r')
        
    def __del__(self):
        if self.fd:
            self.fd.close()
    
    def logons_diff(self):
        return self.logoffs_logons
    
    def logons_current(self):
        return self.logons_
        

    def next(self):
        if self.list_generator == None:
            self.list_generator = self.get_list_of_logons()
            
        self.list_generator.next()
        
    

    """ Generator yielding list of lines in each 'diagnose debug auth fsso list execution' """
    def get_list(self):
        state_start_detected = False
        state_stop_detected = False
        auth_list = []
        
        if self.fd:
            for line in self.fd:
                if not state_start_detected and line.strip().find("----FSSO logons----") >= 0:
                    state_start_detected = True
                    auth_list = []
                    continue
                if not state_stop_detected and line.strip().find("----end of FSSO logons----") >= 0:
                    state_stop_detected = True
                    
                if(state_start_detected):
                    l = line.strip()
                    #if( l.find("IP:") >= 0):
                    m = self.reC_fsso_list_entry.search(l)
                    if(m):
                        auth_list.append(l)
                    else:
                        if l.find("IP") > 0:
                            print "Non-matching (with IP): " + l
                        else:
                            #print " ---- Non-matching (garbage): " + l
                            pass
                
                if(state_stop_detected):
                    state_start_detected = False
                    state_stop_detected = False
                    yield auth_list

    def guess_domain(self,grp_list):
        
        grp1 = grp_list.split("+")[0]
        
        if grp1.find("/") > 0:
            # standard mode
            return grp1.split("/")[0].upper()
        
        else:
            
            # FIXME: if there is escaped comma in the list, result will be incorrect.
            #        find \, and replace it with something else.
            # Will not implements this now, since it's unlikely first group will contain this.
            
            # advanced mode
            l = grp1.split(",")
            ret = ""
            for ll in l:
                if ll.find("dc=") >= 0:
                    # we've found dc component
                    ret += ll.split("=")[1] + "."
                    
            if len(ret) > 0:
                # remove trailing .
                ret = ret[0:-1]
                
            if len(ret) == 0:
                # well. return something at least
                ret = "DOMA"
                
            return ret.upper()
                
                    
             
            
                
    """ Generator yielding dictionary, where key is the fsso logon list line, value is dictionary with logon structure for fssolib """
    def get_list_of_logons(self):
        
        prev_logon_dict = {}
        
        for auth_list in self.get_list():
            ret = {}
            for auth_list_line in auth_list:
                m = self.reC_fsso_list_entry.search(auth_list_line)
                if(m):
                    vals = m.groupdict()
                    u = {}
                    u['LOGGED_ON'] = 1
                    u['LOGON_TIMESTAMP'] = time.time()
                    u['IP'] = vals["IP"]
                    u['USERNAME'] = vals["username"]
                    u['WORKSTATION'] = vals["workstation"]
                    u['USER_DN'] = vals["groups"]
                    u['DOMAIN'] = self.guess_domain(vals["groups"])
                    ret[auth_list_line] = u
                
 #                   if vals["prsz"] != None:
#
  #                      if vals["pr1"] != None:
  #                          u["PORT_RANGE_SIZE"] = int(vals["prsz"])
 #                         u['PORT_RANGES'] = []
  #                          pr1 = vals["pr1"].split("-")
 #                           u['PORT_RANGES'].append((int(pr1[0]),int(pr1[1])))

       #                 if vals["pr2"] != None:
      #                      pr2 = vals["pr2"].split("-")
     #                       u['PORT_RANGES'].append((int(pr2[0]),int(pr2[1])))

    #                    if vals["pr3"] != None:
   #                         pr3 = vals["pr3"].split("-")
  #                          u['PORT_RANGES'].append((int(pr3[0]),int(pr3[1])))

 #                       if vals["pr4"] != None:
 #                           pr4 = vals["pr4"].split("-")
 #                           u['PORT_RANGES'].append((int(pr4[0]),int(pr4[1])))

                
                  #ret[auth_list_line] = u
            
            self.logons_ = ret
            self.logoffs_logons = dict_key_diff(prev_logon_dict,ret)
            prev_logon_dict = ret
            
            yield ret

class TestUnit:

    @staticmethod
    def test_lines():
        a = FgtAuthList('../test_data/sample1.log');
        for l in a.get_list():
            print "Auth list len %d" % (len(l),)

    @staticmethod
    def test_dicts():
        a = FgtAuthList('../test_data/sample1.log');

        logon_lists_gen =  a.get_list_of_logons()
        
        try: 
            prev_logon_list = {}
            while True: 
                logon_list = logon_lists_gen.next()
                pprint.pprint(logon_list)
            
            
        except StopIteration:
            print "PUNT!"

    @staticmethod
    def test_dict_diffs():
        a = FgtAuthList('../test_data/sample1.log');

        logon_lists_gen =  a.get_list_of_logons()
        
        try: 
            prev_logon_list = {}
            while True: 
                logon_list = logon_lists_gen.next()
                #pprint.pprint(logon_list)
                
                add,rem = dict_key_diff(prev_logon_list,logon_list)
                
                print "==> LOGOFFS"
                pprint.pprint(rem.keys())
                print 
                print "NEW LOGONS:"
                pprint.pprint(add.keys())
                print "---------------------------"
                
                prev_logon_list = logon_list
                time.sleep(1)
            
            
        except StopIteration:
            print "PUNT!"
            
    @staticmethod
    def test_auth_diffs():
        a = FgtAuthList('../test_data/sample1.log');

        logon_lists_gen =  a.get_list_of_logons()
        
        try: 
            for i in range(0,6):
                logon_lists_gen.next()


            add,rem = a.logons_diff()

            print "==> LOGOFFS"
            for rr in rem.keys():
                pprint.pprint(rem[rr])
            print 
            print "NEW LOGONS:"
            for aa in add.keys():
                pprint.pprint(add[aa])
            print "---------------------------"
            

        except StopIteration:
            print "PUNT!"

    @staticmethod
    def test_auth_next(iterations=0,print_keys=False,print_dicts=False):
        a = FgtAuthList('../test_data/sample1.log');

        try: 
            for i in range(0,iterations):
                a.next()

            add,rem = a.logons_diff()
            logons = a.logons_current()
        
            if print_keys:
                for ll  in logons.keys():
                    print ll
                    if print_dicts:
                        pprint.pprint(logons[ll])
                        
                

            print "=== LOGOFF ==="
            if print_keys:
                for rr in rem.keys():
                    print rr
                    if print_dicts:
                        pprint.pprint(rem[rr])
            print "  ... entries: %d" % (len(rem.keys()),)

            print 

            print "=== LOGON  ==="
            if print_keys:
                for aa in add.keys():
                    print aa
                    if print_dicts:
                        pprint.pprint(add[aa])
            print "  ... entries: %d" % (len(add.keys()),)
            print 
            print "Total logon list entries: %d" % (len(logons.keys()),)
            print "------------------------------------"
            

        except StopIteration:
            print "PUNT!"

if __name__ == "__main__":
    import sys
    #TestUnit.test_lines()
    #TestUnit.test_dicts()
    #TestUnit.test_dict_diffs()
    #TestUnit.test_auth_diffs()
    
    iters = 0
    if len(sys.argv) > 1:
        iters = sys.argv[1]
    TestUnit.test_auth_next(int(iters),True,True)
    
    

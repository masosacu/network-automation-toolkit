
# No working, looking to get pool stat

from multiprocessing import pool

from f5.bigip import ManagementRoot
import functions.tools
from f5.bigip import ManagementRoot
from f5.utils.responses.handlers import Stats

# Ask for username/password.
username, password = functions.tools.get_credential()

host_ip = "10.102.0.232"

#Connect to the BigIP
mgmt = ManagementRoot(host_ip,username,password)

# Get a list off all pools an the BigIP and print their names and thheir
# member's name
pools = mgmt.tm.ltm.pools.get_collection()
for pool in pools:
    print(pool.name)

    for member in pool.members_s.get_collection():
        print(member.name)
        print(member.state)
        #member_stats = Stats(member.stats.load())
        #mbr_status = Stats(member.name.stats)
        #mbr = member_stats
        #print(member_stats.stat.status_availabilityState)
        #print(member_stats)



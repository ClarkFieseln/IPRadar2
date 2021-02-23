# imports
#########
import queue
from threading import Lock
from copy import deepcopy
import configuration
from time import sleep
import time
import shlex,  subprocess

##########################
class FirewallManagerClass(object):
    __hostRuleQueue = queue.Queue()
    __mutexSolved = Lock()
    ruledHostName = {}
    ruledHosts = [] # permanent list
        
    #############
    def __init__(self):
        return
        
    ###########################
    # add rule in Windows Firewall to block host IP
    ###########################
    def __ruleHost(self,  hostIP):
        self.__mutexSolved.acquire()
        try:
            currentTime = time.strftime("%Y_%m_%d_%H_%M_%S", time.gmtime())
            # 1) avoid duplicated entries by first trying:
            print("Check if firewall rule exists before adding it. IP = ",  hostIP)
            command = "netsh advfirewall firewall show rule name=all | find \""+configuration.RULE_NAME_STR+"\" | find \""+hostIP+"\""
            p1 = subprocess.Popen(shlex.split(command), shell=True, stdout=subprocess.PIPE)
            out, err = p1.communicate()
            if p1.returncode == 0:
                p1.terminate()
                p1.kill()
                ###############
                print("Firewall rule exists already, nothing to do.")
            else:
                p1.terminate()
                p1.kill()
                ###############
                print("We can add in firewall rule!")
                #################################################
                # 2) add rule to block incoming traffic from BAD IP:
                command = "netsh advfirewall firewall add rule name=\"IPRadar2-Block-"+currentTime+": in from "+self.ruledHostName[hostIP]+"\" dir=in interface=any action=block remoteip="+hostIP
                p2 = subprocess.Popen(shlex.split(command), shell=True, stdout=subprocess.PIPE)
                out, err = p2.communicate()
                p2.wait()
                if p2.returncode == 0:
                    p2.terminate()
                    p2.kill()
                    #################################################
                    # 3) add rule to block outgoing traffic from BAD IP:
                    print("We can add out firewall rule!")
                    command = "netsh advfirewall firewall add rule name=\"IPRadar2-Block-"+currentTime+": out from "+self.ruledHostName[hostIP]+"\" dir=out interface=any action=block remoteip="+hostIP
                    p3 = subprocess.Popen(shlex.split(command), shell=True, stdout=subprocess.PIPE)
                    out, err = p3.communicate()
                    p3.wait()
                    if p3.returncode == 0:
                        p3.terminate()
                        p3.kill()
                        print("Added in and out rules successfully!")
                    else:
                        print("Error: could not add out rule for IP ",  hostIP)
                else:
                    print("Error: could not add in rule for IP ",  hostIP)
            ############
        except Exception as e:
            print("Exception in __ruleHost() = ",  e)
        finally:
            self.__mutexSolved.release()
    # end of __ruleHost()
    ###############

    ######################
    # process hosts in queue
    ######################
    def processingThread(self):
        # main loop
        ########
        while True:
            # this call does NOT block
            if not self.__hostRuleQueue.empty():
                ruleHost = self.__hostRuleQueue.get_nowait() # get(block=False)
                # add rule
                if  ruleHost != None:
                    self.__ruleHost(ruleHost)
            # wait if queue is empty
            ##############
            if self.__hostRuleQueue.empty():
               sleep(configuration.CHECK_PERIOD_IN_SEC)
    # end of processingThread()
    #######################
    
    ######################
    # get ruled hosts
    ######################
    def getRuledHosts(self):
        ruledHostsTemp = []
        self.__mutexSolved.acquire()
        try:
            if self.__hostRuledList:
                ruledHostsTemp = deepcopy(self.__hostRuledList)
                # emtpy/clear the list with resolved hosts, they were passed already
                self.__hostRuledList = []
            else:
                ruledHostsTemp = []
        except Exception as e:
            print("Exception in getRuledHosts = ",  e)
            ruledHostsTemp = []
        finally:
            self.__mutexSolved.release()

        return ruledHostsTemp
    # end of getRuledHosts()
    ################
    
    ######################
    # put IP to rule (block in Windows Firewall by adding a new rule for in and out traffic from or to this IP)
    ######################
    def putHostToRule(self,  ip, name):
        # store in permanent list
        self.ruledHosts.append(ip) 
        # store name in dict
        self.ruledHostName[ip] = name
        # add host to rule queue:
        self.__hostRuleQueue.put(ip)
    # end of putHostToRule()
    ################









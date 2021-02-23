# imports
######
import queue
from threading import Lock
from copy import deepcopy
import configuration
from pythonping import ping
from time import sleep
import time
import sys

configuration.START_TIME = time.strftime("%Y_%m_%d_%H_%M_%S", time.gmtime())

# output shell to out_DATE.txt ?
if configuration.SHELL_TO_FILE == True:
    sys.stdout = open("Output/out_"+configuration.START_TIME+".txt", 'w', encoding="utf-8")
    sys.stderr = open("Output/out_"+configuration.START_TIME+".txt", 'w', encoding="utf-8")

########################
class PingResolverClass(object):
    __hostPingQueue = queue.Queue()
    __hostPingedList = []
    __mutexSolved = Lock()
    pingedHosts = [] # permanent list
        
    #############
    def __init__(self):
        return
        
    ######################
    # ping host IP
    ######################
    def __pingHost(self,  hostIP):
        self.__mutexSolved.acquire()
        try:
            # in cmd console we have > ping -w 200 -l 40 -n 1 hostIP  (warning: here timeout with poram -w is in milliseconds!)
            ###############################
            # response_list = ping(hostIP, timeout=0.2,  size=40, count=1) # timeout in seconds!
            response_list = ping(hostIP, timeout=configuration.PING_TIMEOUT_SEC,  size=configuration.PING_SIZE_BYTES, count=configuration.PING_COUNT) # timeout in seconds!
            print(response_list)
            # when the response is "Request timed out.." then we get rtt_avg_ms = PING_TIMEOUT_SEC (in ms)
            if response_list.rtt_min < configuration.PING_TIMEOUT_SEC:
                print("Ping to IP = ",  hostIP)
                print("rtt_min_ms = ",  response_list.rtt_min_ms)
                print("rtt_avg_ms = ",  response_list.rtt_avg_ms)
                self.__hostPingedList.append(hostIP)
                # check if response is close to timeout and log infos in such a case
                if (configuration.PING_TIMEOUT_SEC - response_list.rtt_max) < configuration.PING_TIMEOUT_SEC*0.1:
                    print("WARNING! ping response close to max. value, rtt_max_ms = ", response_list.rtt_max_ms)
            else:
                print("Time out in Ping to IP = ",  hostIP)
        except Exception as e:
            print("Exception in __pingHost() = ",  e)
            print("Exception in __pingHost() to IP = ",  hostIP)
        finally:
            self.__mutexSolved.release()
    # end of __pingHost()
    ###############

    ######################
    # process hosts in queue
    ######################
    def processingThread(self):
        # main loop
        ########
        while True:
            # this call does NOT block
            if not self.__hostPingQueue.empty():
                pingHost = self.__hostPingQueue.get_nowait() # get(block=False)
                if  pingHost != None:
                    self.__pingHost(pingHost)
            # wait if queue is empty
            ##############
            if self.__hostPingQueue.empty():
               sleep(configuration.CHECK_PERIOD_IN_SEC)
    # end of processingThread()
    #######################
    
    ######################
    # get pinged hosts
    ######################
    def getPingedHosts(self):
        pingedHostsTemp = []
        self.__mutexSolved.acquire()
        try:
            if self.__hostPingedList:
                pingedHostsTemp = deepcopy(self.__hostPingedList)
                # emtpy/clear the list with resolved hosts, they were passed already
                self.__hostPingedList = []
            else:
                pingedHostsTemp = []
        except Exception as e:
            print("Exception in getPingedHosts = ",  e)
            pingedHostsTemp = []
        finally:
            self.__mutexSolved.release()

        return pingedHostsTemp
    # end of getPingedHosts()
    ################
    
    ######################
    # put IP to ping
    ######################
    def putHostToPing(self,  ip):
        # store in permanent list
        self.pingedHosts.append(ip) 
        # add host to ping queue:
        self.__hostPingQueue.put(ip)
    # end of putHostToPing()
    ################









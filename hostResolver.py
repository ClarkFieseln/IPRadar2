# imports
######
import queue
from threading import Lock
import shlex,  subprocess
from copy import deepcopy
from playsound import playsound
import configuration
from time import sleep
from pathlib import Path
import os

########################
class HostResolverClass(object):
    __hostRequestResolutionQueue = queue.Queue()
    __hostResolvedList = []
    __hostsNotResolved = []
    __mutexSolved = Lock()
    # Tool:
    WHOSIP_EXE = "whosip.exe" # will be completed with absolute path in __init__()
    # counters
    hostsRequested = 0
    hostsResolved = 0
    hostsFailed = 0
    countersLock = Lock()
        
    #############
    def __init__(self):
        #################
        currAbsPath = Path().absolute()
        currAbsPath = str(currAbsPath)
        currAbsPath = currAbsPath.replace("\\", "/")
        ##########################################
        runningScript = os.path.basename(__file__)
        # when executing IPRadar2.exe we'll get hostResolver.pyc instead of hostResolver.py
        if(runningScript=="hostResolver.py"):
            currAbsPath = currAbsPath + "/dist/WhosIP/"
        else:
            currAbsPath = currAbsPath + "/WhosIP/"
        ##########################################
        # print("Current directory: ",  currAbsPath)  
        self.WHOSIP_EXE = currAbsPath+self.WHOSIP_EXE
                
    #####################
    def getHostsFailedPast(self):
        return len(self.__hostsNotResolved) - 1
        
    ######################
    # use command-line tool to resolve host
    # the tool WhosIP is imilar to IPNetINfo which checks:
    # ARIN, RiPE, ARNIC, LACNI, AfriNIC
    # TODO: improvement: store all individual fields of whosip in separate fieds in node so we can use them directly and avoid parsing.
    #            e.g. see checkForHostsResolution() when checking if ower is in configuration.WhiteListOwner
    ######################
    def whosip(self,  hostIP):
        dict_elem_host = {}
        host = " (unknown)" # note: not able to distinguish from default value..?
        whosip_response = "" # "WHOSIP_START#"
        try:
            command = self.WHOSIP_EXE+" "+hostIP
            print(command)
            p1 = subprocess.Popen(shlex.split(command), shell=True, stdout=subprocess.PIPE)
            out, err = p1.communicate()
            if p1.returncode == 0:
                out = out.splitlines()
                for netstatLine in out:
                    line = str(netstatLine)
                    if "b\'" in line:
                        line = line.replace("b\'", "") # workaround to get rid of strange characters.. b' at once..
                    if "\'" in line:
                        line = line.replace("\'", "") # workaround to get rid of strange characters.. each ' around texts
                    if line != "":
                        # comma is used as field separator, if e.g. name has a comma we then replace it with a semi-colon!
                        ######################################################
                        # if "," in line:
                        line = line.replace(",", ";") # workaround to get rid of strange characters.. each ' around texts
                        print(line)
                        whosip_response = whosip_response + line
                        if "Owner Name:" in line:
                            for ix in range(13, len(line)-1):
                                a = line[ix]
                                a = a
                                if line[ix] != " ":
                                    host = line[ix:len(line)]
                                    print("WhosIP Owner Name = ",  host)
                                    break
                        whosip_response = whosip_response + ", "
            else:
                print("Error: could not execute whosip.exe correctly to find host information!")
            ##########
            p1.terminate()
            p1.kill()
        except Exception as e: # avoid catching exceptions like SystemExit, KeyboardInterrupt, etc.
            print("whosip(): Exception: ",  e)
        # build dictionary element
        dict_elem_host = {"ip" : hostIP, "host" : hostIP + " " + host, "whosip" : whosip_response}
        return dict_elem_host
        
    ######################
    # de-queued hosts are processed here
    ######################
    def __processHost(self,  hostIP):
        self.__mutexSolved.acquire()
        try:
            dict_elem_host = self.whosip(hostIP)
            print("resolved host as dict: ",  dict_elem_host["ip"])
            self.__hostResolvedList.append(dict_elem_host)
            self.countersLock.acquire()
            self.hostsResolved = self.hostsResolved + 1
            self.countersLock.release()
            if configuration.SOUND:
                playsound('Sounds/dk-a2600_jump.mp3')
        except Exception as e: # avoid catching exceptions like SystemExit, KeyboardInterrupt, etc.
            print("__processHost(): Exception while trying to resolve IP ",  hostIP)
            print("__processHost(): Exception: ",  e)
            # just in case we empty the queue, could be corrupted
            self.__hostResolvedList = [] # we assume that any previous element has been consumed up to now.
            # append unresolved host to list
            if hostIP not in self.__hostsNotResolved:
                self.__hostsNotResolved.append(hostIP)
                self.countersLock.acquire()
                self.hostsFailed = self.hostsFailed + 1
                self.countersLock.release()
            if configuration.SOUND:
                playsound('Sounds/smb_mariodie.mp3')
        finally:
            self.__mutexSolved.release()
    # end of __processHost()
    ###############

    ######################
    # process hosts in queue
    ######################
    def processingThread(self):
        # main loop
        ########
        while True:
            if not self.__hostRequestResolutionQueue.empty():
                host = self.__hostRequestResolutionQueue.get_nowait()
                if  host != None:
                    # resolve host name
                    self.__processHost(host)
                    
            # wait if queue is empty
            ##############
            if self.__hostRequestResolutionQueue.empty():
               sleep(configuration.CHECK_PERIOD_IN_SEC)
    # end of processingThread()
    #######################
    
    ######################
    # get resolved hosts
    ######################
    def getResolvedHosts(self):
        resolvedHostsTemp = []
        self.__mutexSolved.acquire()
        try:
            if self.__hostResolvedList:
                resolvedHostsTemp = deepcopy(self.__hostResolvedList)
                # emtpy/clear the list with resolved hosts, they were passed already
                self.__hostResolvedList = []
            else:
                resolvedHostsTemp = []
        except Exception as e:
            print("Exception in getResolvedHosts = ",  e)
            resolvedHostsTemp = []
        finally:
            self.__mutexSolved.release()

        return resolvedHostsTemp
    # end of getResolvedHosts()
    ################
    
    ######################
    # put host to resolve
    ######################
    def putHostToResolve(self,  host):
        # try to resolve ONLY ONCE for now..
        # otherwise we are continuously blocking "unresolvable" requests
        if host not in self.__hostsNotResolved:
            self.__hostRequestResolutionQueue.put(host)
            self.countersLock.acquire()
            self.hostsRequested = self.hostsRequested + 1
            self.countersLock.release()
        else:
            # sorry, I tried that already..without success
            pass
    # end of putHostToResolve()
    ################

    #################
    def getNumberOfHostsRequested(self):
        tempVal = 0 # int is an immutable object so assignment will get a COPY of the value
        self.countersLock.acquire()
        tempVal = self.hostsRequested
        self.countersLock.release()
        return tempVal
        
    #################
    def getNumberOfHostsSolved(self):
        tempVal = 0 # int is an immutable object so assignment will get a COPY of the value
        self.countersLock.acquire()
        tempVal = self.hostsResolved
        self.countersLock.release()
        return tempVal
        
    #################
    def getNumberOfHostsFailed(self):
        tempVal = 0 # int is an immutable object so assignment will get a COPY of the value
        self.countersLock.acquire()
        tempVal = self.hostsFailed
        self.countersLock.release()
        return tempVal







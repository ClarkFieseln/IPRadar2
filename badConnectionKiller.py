# imports
#########
import queue
from threading import Lock
from copy import deepcopy
from playsound import playsound
import configuration
from time import sleep
import shlex,  subprocess
from helper_functions import find_2nd
import os
import psutil

#############################
class BadConnectionKillerClass(object):
    parentPID = 9999999
    ownPID = os.getpid()
    dontKillPIDs = [] # parent and all its children
    __badIPQueue = queue.Queue()
    __ipToKillList = [] # TODO: use dict instead?
    __ipKilledList = {} # all processes with connections to IPs in this list are periodically killed
    __ipKilledListComplete = [] # all processes with connections to IPs in this list were actually killed
    __ipConnectedList = [] # TODO: use dict instead?
    __mutex = Lock()
    __mutexActiveConn = Lock()
    # counters
    nrOfBadIPs = 0 # just len(__badIPQueue)
    countersLock = Lock()
    doKillIPs = False
    doKillAll = False
    local = "127.0.0.0" # will be set by processor
    doCheckActiveConnections = False
    numberOfConnections = 0
    
    #############
    def __init__(self):
        # get PID of console child
        print("badConnectionKiller: own PID = ",  self.ownPID)
        p = psutil.Process(self.ownPID)
        self.parentPID = p.ppid()
        print("parent PID = ",  self.parentPID)
        listOfPIDs = psutil.Process(self.parentPID).children(recursive=True)
        listOfPIDs = str(listOfPIDs)
        print("children of parent = ",  listOfPIDs)
        # append PIDs (of children) that we shall NOT kill..
        while "pid=" in listOfPIDs:
            childPIDTemp =  listOfPIDs[listOfPIDs.find("pid=")+4:listOfPIDs.find(",")]
            self.dontKillPIDs.append(childPIDTemp)
            listOfPIDs = listOfPIDs[listOfPIDs.find(",")+1:] # keep final part only and continue parsing..
            listOfPIDs = listOfPIDs[listOfPIDs.find("pid="):]
        # append also PID of parent
        self.dontKillPIDs.append(str(self.parentPID)) # parent PID
        print("dontKillPIDs = ",  self.dontKillPIDs)
        
    ###################
    def setLocalIP(self,  local):
        self.local = local
        
    ######################
    # all IPs in an active connection will be killed
    # used only when NOTHING shall run...
    ######################
    def __killAll(self):
        try:
            # netstat -ano | findstr "ESTABLISHED" | findstr "bad-IP"
            ###############################################
            print("Checking connected IPs = ")
            command = "netstat -ano | findstr \""+configuration.CONN_ESTABLISHED_STR+"\" | findstr \""
            command = command + self.local + "\""
            p1 = subprocess.Popen(shlex.split(command), shell=True, stdout=subprocess.PIPE) # separate shell
            out, err = p1.communicate()
            if p1.returncode == 0:
                out = out.splitlines()
                # TODO: improvement
                # inside loop we may have repeated PIDs = same process holding several connections
                # now we try to kill this PID several times: once per connection
                # we may store the PIDs in a dict (without repetition) and kill only once as required.
                ###############################################
                for netstatLine in out:
                    line = str(netstatLine)
                    print(line)
                    # TODO: improvement: find a way to get the PID of the "sub-process" so e.g. we dont shut down browser completely
                    #################################################################
                    pid = line[line.rfind(" ")+1:len(line)-1]
                    indexi = find_2nd(line[24:], " ")
                    indexi = indexi + 24
                    IP = line[indexi:line.find(":",  indexi)]
                    IP = IP.replace(" ", "")
                    p = psutil.Process(int(pid))
                    pname = p.name()
                    # dont kill processes in white list
                    if pname not in configuration.WhiteListNotKill:
                        # dont kill ourselves!
                        if pid not in self.dontKillPIDs:
                            try:
                                p.kill()
                            except:
                                print("Could not kill PID = ",  pid)
                                pass
                            if IP not in self.__ipKilledList:
                                self.__ipKilledList[IP] = pname
                            message = "Killed process " + pname + " with PID = " + pid + " connected to " + IP
                            self.__ipKilledListComplete.append(pname+" ("+IP+")")
                            if configuration.SOUND:
                                playsound('Sounds/smb_gameover.mp3', block=False)
                        else:
                            message = "**** We DO NOT KILL " + pname + " with PID = " + pid + " connected to " + IP
                        print(message)
                    else:
                        message = "Did NOT kill process "  + pname + " with PID = " + pid + " holding a connection with IP = " + IP + " because it is in the white-list!"
                        print(message)
            else:
                print("Error: could not execute netstat correctly!")
            ##########
            p1.terminate()
            p1.kill()
        except Exception as e: # avoid catching exceptions like SystemExit, KeyboardInterrupt, etc.
            print("__killAll(): Exception: ",  e)
    # end of __killAll()
    ###############
    
    ######################
    # de-queued hosts are processed here
    ######################
    def __processBadIPs(self):
        self.__mutex.acquire()
        try:
            # __ipToKillList has list of IPs to kill
            # netstat -ano | findstr "ESTABLISHED" | findstr "bad-IP"
            ##################################
            for badIP in self.__ipToKillList:
                print("Checking bad IP = ",  badIP)
                command = "netstat -ano | findstr \""+configuration.CONN_ESTABLISHED_STR+"\" | findstr \""
                command = command + self.local + "\""
                command = command + " | findstr \""
                command = command + badIP + "\""
                p1 = subprocess.Popen(shlex.split(command), shell=True, stdout=subprocess.PIPE)
                out, err = p1.communicate()
                if p1.returncode == 0:
                    out = out.splitlines()
                    for netstatLine in out:
                        line = str(netstatLine)
                        print(line)
                        # TODO: improvement: find a way to get the PID of the "sub-process" so e.g. we dont shut down browser completely
                        #################################################################
                        pid = line[line.rfind(" ")+1:len(line)-1]
                        p = psutil.Process(int(pid))
                        pname = p.name()
                        # dont kill processes in white list
                        if pname not in configuration.WhiteListNotKill:
                            try:
                                p.kill()
                                if badIP not in self.__ipKilledList:
                                    self.__ipKilledList[badIP] = pname
                                message = "Killed process "  + pname + " with PID = " + pid + " holding a connection with bad IP = " + badIP
                                print(message)
                                self.__ipKilledListComplete.append(pname+" ("+badIP+")")
                                if configuration.SOUND:
                                    playsound('Sounds/smb_gameover.mp3', block=False)
                            except:
                                print("Could not kill PID = ",  pid)
                        else:
                            message = "Did NOT kill process "  + pname + " with PID = " + pid + " holding a connection with bad IP = " + badIP + " because it is in the white-list!"
                            print(message)
                else:
                    msg2 = "Error: could not execute netstat correctly while trying to kill Bad IP = " + badIP
                    print(msg2)
                ##########
                p1.terminate()
                p1.kill()
                # maybe we killed the PID or it was already killed and got an error
                # in any case we remove it from the request list...
                ############################
                self.__ipToKillList.remove(badIP)
        except Exception as e: # avoid catching exceptions like SystemExit, KeyboardInterrupt, etc.
            print("__processBadIPs(): Exception: ",  e)
        finally:
            self.__mutex.release()
    # end of __processBadIPs()
    ###############
    
    ###########################
    # check active connections
    ###########################
    def __checkActiveConnections(self):
        self.__mutexActiveConn.acquire()
        try:
            # first clear list of connections...will be filled again
            #############################
            self.__ipConnectedList = []
            # now check for connections which are currently established
            ##################################
            print("Checking active connections..")
            command = "netstat -ano | findstr \""+configuration.CONN_ESTABLISHED_STR+"\" | findstr \""
            command = command + self.local + "\""
            p1 = subprocess.Popen(shlex.split(command), shell=True, stdout=subprocess.PIPE)
            out, err = p1.communicate()
            if p1.returncode == 0:
                out = out.splitlines()
                for netstatLine in out:
                    line = str(netstatLine)
                    print(line)
                    posDoublePoint = find_2nd(line, ":")
                    posSpace = line.rfind(" ", posDoublePoint-16,  posDoublePoint)
                    activeIP = line[posSpace+1:posDoublePoint]
                    if activeIP not in self.__ipConnectedList:
                        self.__ipConnectedList.append(activeIP)
                        message = "Found NEW connected IP = " + activeIP
                        print(message)
                    # else:
                        # message = "Found still connected IP = " + activeIP
                        # print(message)
            else:
                print("Error: could not execute netstat correctly to find active connections with command = ",  command)
                pass
            ##########
            p1.terminate()
            p1.kill()
            if configuration.SOUND: # play sound every time we checked...
                playsound('Sounds/smb_stomp.mp3', block=False)
            # set counter
            self.numberOfConnections = len(self.__ipConnectedList)
        except Exception as e: # avoid catching exceptions like SystemExit, KeyboardInterrupt, etc.
            print("__checkActiveConnections(): Exception: ",  e)
        finally:
            self.__mutexActiveConn.release()
    # end of __checkActiveConnections()
    #####################
    
    ######################
    # process hosts in queue
    ######################
    def processingThread(self):
        # main loop
        ########
        while True:
            # check active connections
            ###############
            self.doCheckActiveConnections = not self.doCheckActiveConnections
            if self.doCheckActiveConnections:
                self.__checkActiveConnections()
            # NOTE: this call "blocks" until a new element is put in queue
            # note we dont use a mutex here, otherwise it would block the put for too long!
            while not self.__badIPQueue.empty():
                ip = self.__badIPQueue.get(block=False)
                if ip != None:
                    if ip not in self.__ipToKillList:
                        self.__ipToKillList.append(ip)
                        # next call to __processBadIPs() will whipe out these bad guys..
            #################
            if self.doKillIPs == True:
                self.__processBadIPs()
            elif self.doKillAll == True:
                self.__killAll()
            ##############################
            sleep(configuration.CHECK_PERIOD_IN_SEC)
    # end of processingThread()
    #######################
    
    ######################
    # get connected IPs
    ######################
    def getConnectedIPs(self):
        ipConnectedListTemp = []
        self.__mutexActiveConn.acquire()
        try:
            if self.__ipConnectedList:
                ipConnectedListTemp = deepcopy(self.__ipConnectedList)
        except Exception as e:
            print("Exception in getConnectedIPs = ",  e)
            ipConnectedListTemp = []
        finally:
            self.__mutexActiveConn.release()

        return ipConnectedListTemp
    # end of getConnectedIPs()
    ################
    
    ######################
    # get killed hosts
    ######################
    def getKilledIPs(self):
        ipKilledListTemp = {}
        self.__mutex.acquire()
        try:
            if self.__ipKilledList:
                ipKilledListTemp = deepcopy(self.__ipKilledList)
                # emtpy/clear the list with connections killed, they were passed already
                self.__ipKilledList = {}
            else:
                ipKilledListTemp = {}
        except Exception as e:
            print("Exception in getKilledIPs = ",  e)
            ipKilledListTemp = {}
        finally:
            self.__mutex.release()

        return ipKilledListTemp
    # end of getKilledIPs()
    ################
    
    ######################
    # put bad IP to kill
    ######################
    def putIPToKill(self,  ip):
        # try to resolve ONLY ONCE for now..
        # otherwise we are continuously blocking "unresolvable" requests
        if ip not in self.__badIPQueue.queue:
            self.__badIPQueue.put(ip)
            self.countersLock.acquire()
            self.nrOfBadIPs = self.nrOfBadIPs + 1
            self.countersLock.release()
        else:
            # sorry, I tried that already..without success
            pass
    # end of putIPToKill()
    ################

    #################
    def getNumberOfBadIPs(self):
        tempVal = 0 # int is an immutable object so assignment will get a COPY of the value
        self.countersLock.acquire()
        tempVal = self.nrOfBadIPs
        self.countersLock.release()
        return tempVal
        
    #################
    def getNumberOfIPsKilled(self):
        tempVal = 0 # int is an immutable object so assignment will get a COPY of the value
        self.countersLock.acquire()
        tempVal = len(self.__ipKilledListComplete)
        self.countersLock.release()
        return tempVal
        
    #################
    def getListOfKilledNodes(self):
        ipKilledListCompleteTemp = []
        self.__mutex.acquire()
        try:
            if self.__ipKilledListComplete:
                ipKilledListCompleteTemp = deepcopy(self.__ipKilledListComplete)
            else:
                ipKilledListCompleteTemp = []
        except Exception as e:
            print("Exception in getListOfKilledNodes = ",  e)
            ipKilledListCompleteTemp = []
        finally:
            self.__mutex.release()

        return ipKilledListCompleteTemp
        
    #################
    def killIPs(self):
        self.doKillIPs = True
        self.doKillAll = False
        
    #################
    def killAll(self):
        self.doKillIPs = False
        self.doKillAll = True
        
    #################
    def killNone(self):
        self.doKillIPs = False
        self.doKillAll = False
        
    ###################################
    # command to kill connections to bad IPs right now (only once)
    def killIPsNow(self):
        # TODO: check if trying to kill also connections which are not active
        self.__processBadIPs()
            
    ########################################
    # command to kill active connections to known IPs right now (only once)
    def killAllNow(self):
        self.__killAll()
        
    #############
    def killIP(self,  ip):
        print("Kill requested IP = ",  ip)
        command = "netstat -ano | findstr \""+configuration.CONN_ESTABLISHED_STR+"\" | findstr \""
        command = command + self.local + "\""
        command = command + " | findstr \""
        command = command + ip + "\""
        p1 = subprocess.Popen(shlex.split(command), shell=True, stdout=subprocess.PIPE)
        out, err = p1.communicate()
        if p1.returncode == 0:
            out = out.splitlines()
            for netstatLine in out:
                line = str(netstatLine)
                print(line)
                # TODO: improvement: find a way to get the PID of the "sub-process" so e.g. we dont shut down browser completely
                #################################################################
                pid = line[line.rfind(" ")+1:len(line)-1]
                p = psutil.Process(int(pid))
                pname = p.name()
                # dont kill processes in white list
                if pname not in configuration.WhiteListNotKill:
                    try:
                        p.kill()
                        if ip not in self.__ipKilledList:
                            self.__ipKilledList[ip] = pname
                        message = "Killed process "  + pname + " with PID = " + pid + " holding a connection with passed IP = " + ip
                        print(message)
                        self.__ipKilledListComplete.append(pname+" ("+ip+")")
                        if configuration.SOUND:
                            playsound('Sounds/smb_gameover.mp3', block=False)
                    except:
                        print("Could not kill PID = ",  pid)
                else:
                    message = "Did NOT kill process "  + pname + " with PID = " + pid + " holding a connection with passed IP = " + ip + " because it is in the white-list!"
                    print(message)
        ##########
        p1.terminate()
        p1.kill()

    #################
    def getNumberOfConnections(self):
        return self.numberOfConnections














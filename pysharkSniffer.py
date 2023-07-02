# imports
#########
# these imports help avoiding errors in executable generated with pyinstaller
# but it looks like we dont need them (?)
'''
from py import _std
from py import __metainfo
from py import _builtin 
from py import _error 
from py import _xmlgen 
from py import _code 
from py import _io 
from py import _log 
from py import _path 
from py import _process 
from py import _path 
from py import _vendored_packages
'''

import pyshark
from time import sleep
import configuration
import processor
import threading
import queue
import shlex,  subprocess
import os
from pathlib import Path
from helper_functions import find_2nd

###############
class pysharkSniffer:   
    threadForSniffing = 0 
    threadForProcessing = 1
    capture = 0
    fname = ""
    interface = configuration.INTERFACE
    threadsStarted = False
    inputPacketsCount = 0
    # processedPacketsCount = 0
    tsharkInterfaces = {}
    
    # double queue for processing
    # TODO: improvement: do we need double buffering? with one buffer it works well.
    #################
    # callback -> queueA/B 
    # queueB/A -> process 
    #########################
    # NOTE: as a reminder
    # Mutable objects which can be passed by reference:
    # list, dict, set, byte array
    # Immutable objects: Immutable objects don’t allow modification after creation
    # bool, int, float, complex, string, tuple, frozen set [note: immutable version of set], bytes
    #########################
    packetQueueA = queue.Queue()
    packetQueueB = queue.Queue()
    currentCallbackQueueIsA = [True]
    locationsRead = [False] # we use a "list" instead of a bool so we have a "mutable" variable which we can pass by reference!
    #########################
    
    # processor object from class ProcessorClass
    processorObject = processor.ProcessorClass()
     
    #######################################################
    def __init__(self):
        print("pysharkSniffer initialized")
        ###################
        # print("tshark interfaces:")
        # print(pyshark.tshark.tshark.get_tshark_interfaces())
        # list available interfaces
        ###############
        # when executing IPRadar2.exe we'll get processor.pyc instead of processor.py
        runningScript = os.path.basename(__file__)
        # path
        currAbsPath = Path().absolute()
        currAbsPath = str(currAbsPath)
        currAbsPath = currAbsPath.replace("\\", "/")
        print("Current directory: ",  currAbsPath)  
        # different relative paths depending if we debug or execute IPRadar2.exe
        if(runningScript=="pysharkSniffer.py"): # .py script
            cmdListInterfaces = "\"" + currAbsPath + "/dist/WiresharkPortable/App/Wireshark/tshark\" -D"
        else: # .exe file
            cmdListInterfaces = "\"" + currAbsPath + "/WiresharkPortable/App/Wireshark/tshark\" -D"
        print("tshark interfaces:")
        p1 = subprocess.Popen(shlex.split(cmdListInterfaces), shell=True, stdout=subprocess.PIPE)
        out, err = p1.communicate()
        if p1.returncode == 0:
            out = out.splitlines()
            interfaceNr = 1
            for interface in out:
                interface = str(interface)
                # need to change \\ into \
                interface = interface.replace("\\\\",  "\\")
                interfaceStr = interface[interface.find(".")+2:find_2nd(interface, " ")]
                interfaceDescriptionStr = interface[find_2nd(interface, " ")+1:len(interface)-1]
                self.tsharkInterfaces[interfaceStr] = interfaceDescriptionStr
                print("Interface {} = {} {}".format(interfaceNr,  interfaceStr,  interfaceDescriptionStr))
                interfaceNr = interfaceNr + 1
        else:
            print("Error: could not get interfaces using tshark!")
        ##########
        p1.terminate()
        p1.kill()
        
    #######################################################
    def getInterfaces(self):
        return self.tsharkInterfaces
            
    #######################################################
    def __del__(self):
        print("pysharkSniffer deleted")
        
    #######################################################
    def switchMap(self):
         # switch map in this sequence..
        if configuration.currentmaptype == configuration.SATELLITE:
            configuration.currentmaptype = configuration.ROADMAP
        elif configuration.currentmaptype == configuration.ROADMAP:
            configuration.currentmaptype = configuration.HYBRID
        elif configuration.currentmaptype == configuration.HYBRID:
            configuration.currentmaptype = configuration.TERRAIN
        elif configuration.currentmaptype == configuration.TERRAIN:
            configuration.currentmaptype = configuration.SATELLITE
        else: # use default map or do nothing?
            configuration.currentmaptype = configuration.ROADMAP
        # update map
        self.processorObject.plotMap()
        return configuration.mapTypeNames[configuration.currentmaptype]
        
    #######################################################
    def toggleBounce(self):
        if configuration.BOUNCE == True:
            configuration.BOUNCE = False
            status = "OFF"
        else:
            configuration.BOUNCE = True
            status = "ON"
        # update map
        self.processorObject.plotMap()
        return status
        
    #######################################################
    def toggleHeatmap(self):
        if configuration.HEATMAP == True:
            configuration.HEATMAP = False
            status = "OFF"
        else:
            configuration.HEATMAP = True
            status = "ON"
        # update map
        self.processorObject.plotMap()
        return status
                
    #######################################################
    def toggleShowNodes(self):
        configuration.SHOW_NODES = not configuration.SHOW_NODES
        self.processorObject.plotMap()
        
    #######################################################
    def toggleShowConnections(self):
        configuration.SHOW_CONNECTIONS = not configuration.SHOW_CONNECTIONS
        self.processorObject.plotMap()
        
    #######################################################
    def toggleShowConnectionsActive(self):
        configuration.SHOW_CONNECTIONS_ACTIVE = not configuration.SHOW_CONNECTIONS_ACTIVE
        self.processorObject.plotMap()
 
    #######################################################
    def toggleShowInfo(self):
        configuration.SHOW_INFO = not configuration.SHOW_INFO
        self.processorObject.plotMap()
        
    #######################################################
    def toggleShowGoodHosts(self):
        configuration.SHOW_HOST_GOOD = not configuration.SHOW_HOST_GOOD
        self.processorObject.plotMap()
        
    #######################################################
    def toggleShowUnknownHosts(self):
        configuration.SHOW_HOST_UNKNOWN = not configuration.SHOW_HOST_UNKNOWN
        self.processorObject.plotMap()
        
    #######################################################
    def toggleShowBadHosts(self):
        configuration.SHOW_HOST_BAD = not configuration.SHOW_HOST_BAD
        self.processorObject.plotMap()
        
    #######################################################
    def toggleShowKilledHosts(self):
        configuration.SHOW_HOST_KILLED = not configuration.SHOW_HOST_KILLED
        self.processorObject.plotMap()

    #######################################################
    def toggleShowActiveHosts(self):
        configuration.SHOW_HOST_ACTIVE = not configuration.SHOW_HOST_ACTIVE
        self.processorObject.plotMap()
        
    #######################################################
    def toggleShowPingedNegHosts(self):
        configuration.SHOW_HOST_PING = not configuration.SHOW_HOST_PING
        self.processorObject.plotMap()
        
    #######################################################
    def toggleShowGoodConnections(self):
        configuration.SHOW_CONNECTION_GOOD = not configuration.SHOW_CONNECTION_GOOD
        self.processorObject.plotMap()
        
    #######################################################
    def toggleShowUnknownConnections(self):
        configuration.SHOW_CONNECTION_UNKNOWN = not configuration.SHOW_CONNECTION_UNKNOWN
        self.processorObject.plotMap()
        
    #######################################################
    def toggleShowBadConnections(self):
        configuration.SHOW_CONNECTION_BAD = not configuration.SHOW_CONNECTION_BAD
        self.processorObject.plotMap()
        
    #######################################################
    def toggleShowKilledConnections(self):
        configuration.SHOW_CONNECTION_KILLED = not configuration.SHOW_CONNECTION_KILLED
        self.processorObject.plotMap()
        
    #######################################################
    def setPlot(self,  set):
        configuration.PLOT = set
        self.processorObject.plotMap()
        
    #######################################################
    def setSound(self,  set):
        configuration.SOUND = set
        
    #######################################################
    def setBlockBadInFirewall(self, set):
        configuration.ADD_FIREWALL_RULE_BLOCK_BAD_IP = set
        
    #######################################################
    def getNumberOfConnections(self):
        return self.processorObject.getNumberOfConnections()
        
    #######################################################
    def getNumberOfNodes(self):
        return self.processorObject.getNumberOfNodes()
        
    #######################################################
    def getNumberOfBadNodes(self):
        return self.processorObject.getNumberOfBadNodes()
        
    #######################################################
    def getDictOfNodes(self):
        return self.processorObject.getDictOfNodes()
        
    #######################################################
    def getNumberOfKilledNodes(self):
        return self.processorObject.getNumberOfKilledNodes()
        
    #######################################################
    def getListOfKilledNodes(self):
        return self.processorObject.getListOfKilledNodes()
        
    #######################################################
    def getNumberOfTxKiloBytes(self):
        return self.processorObject.getNumberOfTxKiloBytes()
        
    #######################################################
    def getNumberOfRxKiloBytes(self):
        return self.processorObject.getNumberOfRxKiloBytes()
        
    #######################################################
    def getNumberOfHostsRequested(self):
        return self.processorObject.getNumberOfHostsRequested()
        
    #######################################################
    def getNumberOfHostsSolved(self):
        return self.processorObject.getNumberOfHostsSolved()
        
    #######################################################
    def getNumberOfHostsFailed(self):
        return self.processorObject.getNumberOfHostsFailed()
        
    #######################################################
    def getHostsFailedPast(self):
        return self.processorObject.getHostsFailedPast()
        
    #######################################################
    def getHostsResolvedPast(self):
        return self.processorObject.getHostsResolvedPast()
        
    ##############################
    # setting to kill connections to bad IPs automatically
    ##############################
    def killIPs(self):
        self.processorObject.killIPs()
        
    ##############################
    # setting to kill no IPs
    ##############################
    def killNone(self):
        self.processorObject.killNone()
        
    #################################
    # setting to kill connections to all known IPs automatically
    #################################
    def killAll(self):
        self.processorObject.killAll()
        
    ##################################
    # COMMAND to kill connections to BAD IPs (executed once)
    ##################################
    def killIPsNow(self):
        self.processorObject.killIPsNow()
        
    #####################################
    # COMMAND to kill connections to all active IPs (executed once)
    #####################################
    def killAllNow(self):
        self.processorObject.killAllNow()
        
    ####################################
    # COMMAND to kill connections to specified IP (executed once)
    ####################################
    def killIP(self,  ip):
        self.processorObject.killIP(ip)
        
    ##############
    def pingAll(self):
        if self.processorObject != None:
            self.processorObject.pingAll()
            
    ##############
    def pingRandom(self):
        if self.processorObject != None:
            self.processorObject.pingRandom()
            
    ##############
    def pingRandom2(self):
        if self.processorObject != None:
            self.processorObject.pingRandom2()
            
    ##############
    def pingIP(self,  ip):
        if self.processorObject != None:
            self.processorObject.pingIP(ip)
            
    ##############
    def pingAuto(self,  set):
        if self.processorObject != None:
            if set:
                self.processorObject.pingAutoOn()
            else:
                self.processorObject.pingAutoOff()
                
    ##############
    def updateShowNotShowOwners(self,  listOwnersToShow,  listOwnersToHide):
        self.processorObject.updateShowNotShowOwners(listOwnersToShow,  listOwnersToHide)
        
    #######################################################    
    # TODO: improvement: implement switch live capture on/off:
    def sniff(self,  interface, fname=""): # non-blocking
        self.fname = fname
        self.interface = interface
        # create threads
        # order of creation based on dependencies!
        if self.threadsStarted == False:
            ##################################
            # initialize explicitely so we know the point where all processing threads are started
            self.processorObject.start()
            ##################################
            # we create packet processing thread (threadForSniffing needs it)
            # call without parenthesis, therefore we will have a "non-blocking" thread
            self.threadForPacketProcessing = threading.Thread(name="packetProcessingThread", target=self.processorObject.processingThread,  args=(self.packetQueueA,  self.packetQueueB,  self.currentCallbackQueueIsA,  self.locationsRead))
            self.threadForPacketProcessing.start()
            
        # sniffingThread
        # online capture
        if self.fname == "":
            # thread for sniffig, we use sniffInternal thread to NOT block this call..
            # warning: if we called target=keyProcessingThread()) with parenthesis we would have a "blocking" thread
            self.threadForSniffing = threading.Thread(name="sniffingThread", target=self.sniffingThread) # ()) <- parenthesis means "blocking" thread
            self.threadForSniffing.start()
        # open a capture file offline
        else:
            # and create again the thread for sniffig, we use sniffInternal thread to NOT block this call..
            # we call target=keyProcessingThread()) with parenthesis so we have a "blocking" thread - block until file is processed!
            self.threadForSniffing = threading.Thread(name="sniffingThread", target=self.sniffingThread())
            self.threadForSniffing.start()
            self.threadsStarted = True
            
    #######################################################
    # if used for live-capture, this call will be blocked for ever after assigning the pyshark callback for LiveCapture sniffing
    # if used for reading file this call will not block
    def sniffingThread(self): 
        #########################
        # execution continues at the end of this file

        # ----------------------------------------------------------------------------------------------------------------------
        # callback function to process packets
        ###############################
        def packet_callback(packet):
            if self.currentCallbackQueueIsA[0] == True:
                self.inputPacketsCount = self.inputPacketsCount + 1
                # print("\Log level X: ncallback (A)= ", self.inputPacketsCount)
                self.packetQueueA.put(packet)
            else:
                self.inputPacketsCount = self.inputPacketsCount + 1
                # print("\Log level X: ncallback (B)= ", self.inputPacketsCount)
                self.packetQueueB.put(packet)
        # end of packet_callback(packet)
        ################################
        # ----------------------------------------------------------------------------------------------------------------------

        # wait for processing thread to have read locations from .json file
        #####################################
        while self.locationsRead[0] == False:
            sleep(0.1) # 100ms
        
        # live capture of open file?
        ###############
        if self.fname == "":
            # live capture
            ########
            print("opening interface ", self.interface)
            outputfile = './Output/log_'+configuration.START_TIME+'.pcapng'
            ################
            import asyncio
            loop = asyncio.new_event_loop()
            # asyncio.set_event_loop(loop) # NOTE: this isn't necessary, it seems to be done later in pyshark
            #################
            self.capture = pyshark.LiveCapture(eventloop=loop, interface=self.interface, output_file=outputfile)
            # TODO: check why ring capture does not work. After we set the callback it never gets called.
            #             self.capture = pyshark.LiveRingCapture(interface=interface, ring_file_name=outputfile)
            #######################################################    
            # set callback to capture packets (this call will "block"!)
            ###########################################################
            print("Start capturing packets using callback..")
            try:
                self.capture.apply_on_packets(packet_callback)
            except Exception as e:
                print("pysharkSniffer.sniffingThread(): Exception in call to apply_on_packets(): ", e)
            print("We never reach this point!")
        else:
            # open file
            #######
            print("Start reading packets from file..")
            cap = pyshark.FileCapture(self.fname)
            # process packets
            for packet in cap:
                packet_callback(packet)
            # Note: no need to kill thread, here we go out of it (non-blocking call). Thread will be garbage-collected.
            print("Read and processed all packets from file.")
        










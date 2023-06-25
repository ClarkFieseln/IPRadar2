# imports
######
from time import gmtime, strftime,  sleep,  time
from helper_functions import find_2nd, print_info_layer, print_geolocations
import socket
import requests
from ip2geotools.databases.noncommercial import DbIpCity
import gmplot
from playsound import playsound
import configuration
import math
import json
from node import NodeDataClass,  DbIpCityResponse
import pycountry
import configparser
import threading
from threading import Lock
import pingResolver
import hostResolver
import badConnectionKiller
import firewallManager
from copy import deepcopy
import uuid
from getmac import get_mac_address
import ctypes
import re # for regular expressions
from random import randint

#####################
class ProcessorClass(object):   
    ########################
    # TODO: check this workaround
    sanitized_ip = []
    # variable used by pingRandom() and PingRandom2()
    randomIPList = []
    ########################
    packetQueueA = 0 # will be a reference to pysharkSniffer's variable
    packetQueueB = 0 # will be a reference to pysharkSniffer's variable
    currentCallbackQueueIsA = [True] # will be a reference to pysharkSniffer's variable
    locationsRead = [False] # will be a reference to pysharkSniffer's variable
    processedPacketsCount = 0 
    ##########################
    node_dict = {}
    location_dict = {}
    node_dict_gui = {} # current dict of new/modified nodes to be shown/updated in GUI
    __mutex = Lock() # for processing or accessing node_dict_gui[]
    ##########################
    local = "local IP address"
    public = "public IP address"
    localHost = "local host"
    publicHost = "public host"
    response_public = "will be an object obtained by calling DbIpCity()"
    locationsResolved = []
    hostsResolved = {}
    hostsResolutionRequested = []
    connected_ip_list = []
    pingAuto = True
    pingResolverObject = pingResolver.PingResolverClass()
    threadForPingProcessing = None
    hostResolverObject = hostResolver.HostResolverClass()
    badConnectionKillerObject = badConnectionKiller.BadConnectionKillerClass()
    firewallManagerObject = firewallManager.FirewallManagerClass()
    threadForHostProcessing = None
    threadForBadConnectionKilling = None
    threadForFirewallManagement = None
    needUpdate = False
    tx_kilo_bytes = 0.0
    rx_kilo_bytes = 0.0
    tx_kilo_bytes_alarm = 0.0
    currentNodeNumber = 0
    
    #######################################################
    def getNumberOfConnections(self):
        return self.badConnectionKillerObject.getNumberOfConnections()
        
    #######################################################
    def getNumberOfNodes(self):
        return len(self.node_dict)
        
    #######################################################
    def getNumberOfBadNodes(self):
        return self.badConnectionKillerObject.getNumberOfBadIPs()
        
    #######################################################
    def getNumberOfKilledNodes(self):
        return self.badConnectionKillerObject.getNumberOfIPsKilled()
        
    #######################################################
    def getListOfKilledNodes(self):
        return self.badConnectionKillerObject.getListOfKilledNodes()
        
    #######################################################
    def getNumberOfTxKiloBytes(self):
        return int(self.tx_kilo_bytes)
        
    #######################################################
    def getNumberOfRxKiloBytes(self):
        return int(self.rx_kilo_bytes)
    
    #######################################################
    def getHostsResolvedPast(self):
        return len(self.hostsResolved)
        
    #######################################################
    def getHostsFailedPast(self):
        return self.hostResolverObject.getHostsFailedPast()
        
    #######################################################
    def getNumberOfHostsRequested(self):
        return self.hostResolverObject.getNumberOfHostsRequested()
        
    #######################################################
    def getNumberOfHostsSolved(self):
        return self.hostResolverObject.getNumberOfHostsSolved()
        
    #######################################################
    def getNumberOfHostsFailed(self):
        return self.hostResolverObject.getNumberOfHostsFailed()
        
    ##############
    def killIPs(self):
        if self.badConnectionKillerObject != None:
            self.badConnectionKillerObject.killIPs()
            
    ##############
    def killNone(self):
        if self.badConnectionKillerObject != None:
            self.badConnectionKillerObject.killNone()
            
    ##############
    def killAll(self):
        if self.badConnectionKillerObject != None:
            self.badConnectionKillerObject.killAll()
            
    ###################################
    # command to kill connections to bad IPs right now (only once)
    def killIPsNow(self):
        if self.badConnectionKillerObject != None:
            self.badConnectionKillerObject.killIPsNow()
            
    ########################################
    # command to kill active connections to known IPs right now (only once)
    def killAllNow(self):
        if self.badConnectionKillerObject != None:
            self.badConnectionKillerObject.killAllNow()
            
    ########################################
    # command to kill active connection to specified IP right now (only once)
    def killIP(self,  ip):
        if self.badConnectionKillerObject != None:
            self.badConnectionKillerObject.killIP(ip)
            
    ##############
    # TODO: why cant we just pass bool as argument and set flag with a single method pingAuto(self,  set) ?
    def pingAutoOn(self): #,  set):
        self.pingAuto = True
        '''
        if set:
            self.pingAuto = True
        else:
            self.pingAuto = False
        '''
        
    ##############
    def pingAutoOff(self):
        self.pingAuto = False
            
    ##############
    def pingAll(self):
        if self.pingResolverObject != None:
            self.__mutex.acquire()
            # set ping to False and make a request to update
            # NOTE: we also ping ourselves..but the check to avoid this is not worth the time..
            for key, value in self.node_dict.items():
                value.ping = False
                # add/modify updated IP to GUI-List
                self.node_dict_gui[key] =  value
                # send request
                self.pingResolverObject.putHostToPing(key)
            self.__mutex.release()
            # set flag
            self.needUpdate = True
            
    ################
    # we first send UDP-packets
    # after that we wait enough time so they've been received and processed
    # then we request the ping resolution if still required
    def pingRandom(self):
        if self.pingResolverObject != None:
            self.randomIPList = []
            byte_message = bytes("Hi!", "utf-8")
            # generate NR_OF_RANDOM_IPS_TO_PING random IPs to ping by sending UPD-packets
            ###################################################
            for count in range (1, configuration.NR_OF_RANDOM_IPS_TO_PING):
                randomIP = str(randint(0, 255))+ "."+str(randint(0, 255))+ "."+str(randint(0, 255))+ "."+str(randint(0, 255))
                # append to list, we may need it later to send pings
                self.randomIPList.append(randomIP)
                # send UDP packet
                try:
                    opened_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    # NOTE: port 5005 is RTP (Real-time Transport Protocol - RFC 3551, RFC 4571)
                    opened_socket.sendto(byte_message, (randomIP, 5005))
                    print("UDP packet sent to random IP = ", randomIP)
                except Exception as e:
                    self.randomIPList.remove(randomIP)
                    print("Exception: processor.pingRandom(): Exception = ",  e)
                    print("Exception: processor.pingRandom(): socket Exception with IP = ",  randomIP)
            # wait some time for the UDP packets to be processed and IPs added in node_dict{}
            ###############################################
            # 10 seconds seems enough (alternatively, we could use a temporary list containing all IPs which need ping and service that in background..)
            sleep(10)
            # no ping really:
            #########
            self.pingRandom2()
            
    #################
    def pingRandom2(self):
        # if pingAuto == True, then all previous UDP packets will produce also a ping to the corresponding IPs
        # otherwise we do it here:
        #########################################################
        if self.pingAuto == False:
            if self.pingResolverObject != None:
                self.__mutex.acquire()
                # set ping to False and make a request to update
                # NOTE: we also ping ourselves..but the check to avoid this is not worth the time..
                for key in self.randomIPList:
                    if key in self.node_dict:
                        self.node_dict[key].ping = False
                        # add/modify updated IP to GUI-List
                        self.node_dict_gui[key] =  self.node_dict[key]
                        # send request
                        self.pingResolverObject.putHostToPing(key)
                        print("Ping to random IP = ", key)
                    else:
                        print("Cause not yet in node_dict, do NOT ping to random IP = ", key)
                self.__mutex.release()
                # set flag
                self.needUpdate = True
            
    ###########################
    # ping a specific host (only known hosts allowed)
    ###########################
    def pingIP(self,  host):
        if self.pingResolverObject != None:
            if (host.find(".") == -1) or (host not in self.node_dict):
                ip = socket.gethostbyname(host)
            else:
                ip = host
            # set ping to False and make a request to update
            ###########################
            if ip in self.node_dict:
                self.node_dict[ip].ping = False
                # add/modify updated IP to GUI-List
                self.__mutex.acquire()
                self.node_dict_gui[ip] =  self.node_dict[ip]
                self.__mutex.release()
                # send request
                self.pingResolverObject.putHostToPing(ip)
                # set flag
                self.needUpdate = True
                
    ##############
    # TODO: improvement: avoid all these loops by handling dicts objects instead - in mainWindow.py directly is better.
    def updateShowNotShowOwners(self,  listOwnersToShow,  listOwnersToHide):
        # owners to show:
        for show in listOwnersToShow:
            for ip in self.node_dict:
                if show in self.node_dict[ip].whosip:
                    if self.node_dict[ip].show_host == False:
                        self.node_dict[ip].show_host = True
                        # add/modify updated IP to GUI-List
                        self.__mutex.acquire()
                        self.node_dict_gui[ip] =  self.node_dict[ip]
                        self.__mutex.release()
                        # set flag
                        self.needUpdate = True
        # owners to hide:
        for hide in listOwnersToHide:
            for ip in self.node_dict:
                if hide in self.node_dict[ip].whosip:
                    if self.node_dict[ip].show_host == True:
                        self.node_dict[ip].show_host = False
                        # add/modify updated IP to GUI-List
                        self.__mutex.acquire()
                        self.node_dict_gui[ip] =  self.node_dict[ip]
                        self.__mutex.release()
                        # set flag
                        self.needUpdate = True
                    
    # start()
    # create and START processing threads
    #######################
    def start(self):
        print("processor.start(): start threads")
        # create ping processor
        ##############
        # first create ping processing thread 
        self.threadForPingProcessing = threading.Thread(name="pingProcessingThread", target=self.pingResolverObject.processingThread)
        self.threadForPingProcessing.start()
        
        # create host processor and bad connection killer threads
        ################################
        # first create host processing thread (threadForPacketProcessing needs it)
        self.threadForHostProcessing = threading.Thread(name="hostProcessingThread", target=self.hostResolverObject.processingThread)
        self.threadForHostProcessing.start()
        
        # then create bad connection killer thread (threadForPacketProcessing needs it)
        self.threadForBadConnectionKilling = threading.Thread(name="badConnectionKillerThread", target=self.badConnectionKillerObject.processingThread)
        self.threadForBadConnectionKilling.start()
        
        # then create firewall management thread (threadForFirewallManagement needs it)
        self.threadForFirewallManagement = threading.Thread(name="firewallManagementThread", target=self.firewallManagerObject.processingThread)
        self.threadForFirewallManagement.start()
        
    # __init__()
    # initialize known locations from file
    # initialize known hosts from file
    # resolve local and public hosts
    ######################
    def __init__(self): # (self):
        print("processor.__init__(): load cfg file, etc.")
        # Load the configuration file
        ################
        print("Reading config.ini")
        config = configparser.ConfigParser(allow_no_value=True)
        config.read("config.ini")
        print("sections: ",  config.sections())
        if "myConfig" in config:
            print("keys in section myConfig:")
            if "INTERFACE" in config["myConfig"]:
                configuration.INTERFACE = config['myConfig']['INTERFACE']
                # TODO: improvement: print configuration.VAR instead of accessing againt the .ini file... TODO: for all variables
                # print("INTERFACE = ",  configuration.INTERFACE)
                print("INTERFACE = ",  config['myConfig']['INTERFACE'])
            if "FONT_SIZE" in config["myConfig"]:
                configuration.FONT_SIZE = int(config['myConfig']['FONT_SIZE'])
                print("FONT_SIZE = ",  int(config['myConfig']['FONT_SIZE']))
            if "MAX_TX_KILOBYTES" in config["myConfig"]:
                configuration.MAX_TX_KILOBYTES = int(config['myConfig']['MAX_TX_KILOBYTES'])
                print("MAX_TX_KILOBYTES = ",  int(config['myConfig']['MAX_TX_KILOBYTES']))
            if "NR_OF_RANDOM_IPS_TO_PING" in config["myConfig"]:
                configuration.NR_OF_RANDOM_IPS_TO_PING = int(config['myConfig']['NR_OF_RANDOM_IPS_TO_PING'])
                print("NR_OF_RANDOM_IPS_TO_PING = ",  int(config['myConfig']['NR_OF_RANDOM_IPS_TO_PING']))
            if "CHECK_PERIOD_IN_SEC" in config["myConfig"]:
                configuration.CHECK_PERIOD_IN_SEC = float(config['myConfig']['CHECK_PERIOD_IN_SEC'])
                print("CHECK_PERIOD_IN_SEC = ",  float(config['myConfig']['CHECK_PERIOD_IN_SEC']))   
            if "RUN_AS_ADMIN" in config["myConfig"]:
                configuration.RUN_AS_ADMIN = int(config['myConfig']['RUN_AS_ADMIN'])
                print("RUN_AS_ADMIN = ",  int(config['myConfig']['RUN_AS_ADMIN']))
            ###########################################
            if "ADD_FIREWALL_RULE_BLOCK_BAD_IP" in config["myConfig"]:
                configuration.ADD_FIREWALL_RULE_BLOCK_BAD_IP = int(config['myConfig']['ADD_FIREWALL_RULE_BLOCK_BAD_IP'])
                print("ADD_FIREWALL_RULE_BLOCK_BAD_IP = ",  int(config['myConfig']['ADD_FIREWALL_RULE_BLOCK_BAD_IP']))
            # show message by inconsistent configuration
            if configuration.ADD_FIREWALL_RULE_BLOCK_BAD_IP:
                    if configuration.RUN_AS_ADMIN == False:
                        print("CONFIGURATION ERROR: ADD_FIREWALL_RULE_BLOCK_BAD_IP is True but RUN_AS_ADMIN is False, so NO rules will be added to the Firewall as requested!")
                        ctypes.windll.user32.MessageBoxW(0, "No Admin rights, so NO rules will be added to the Firewall as configured. Set both ADD_FIREWALL_RULE_BLOCK_BAD_IP and RUN_AS_ADMIN to True.", "Warning: configuration error!", 0)
            ###########################################
            if "SHELL_TO_FILE" in config["myConfig"]:
                configuration.SHELL_TO_FILE = int(config['myConfig']['SHELL_TO_FILE'])
                print("SHELL_TO_FILE = ",  int(config['myConfig']['SHELL_TO_FILE']))
            if "PACKED_OUTPUT" in config["myConfig"]:
                configuration.PACKED_OUTPUT = int(config['myConfig']['PACKED_OUTPUT'])
                print("PACKED_OUTPUT = ",  int(config['myConfig']['PACKED_OUTPUT']))
            if "ROUTER_IP" in config["myConfig"]:
                configuration.ROUTER_IP = config['myConfig']['ROUTER_IP']
                print("ROUTER_IP = ",  config['myConfig']['ROUTER_IP'])
            if "RULE_NAME_STR" in config["myConfig"]:
                configuration.RULE_NAME_STR = config['myConfig']['RULE_NAME_STR']
                print("RULE_NAME_STR = ",  config['myConfig']['RULE_NAME_STR'])
            if "CONN_ESTABLISHED_STR" in config["myConfig"]:
                configuration.CONN_ESTABLISHED_STR = config['myConfig']['CONN_ESTABLISHED_STR']
                print("CONN_ESTABLISHED_STR = ",  config['myConfig']['CONN_ESTABLISHED_STR'])
            if "PUBLIC_IP" in config["myConfig"]:
                configuration.PUBLIC_IP = config['myConfig']['PUBLIC_IP']
                print("PUBLIC_IP = ",  config['myConfig']['PUBLIC_IP'])
            if "MY_CITY" in config["myConfig"]:
                configuration.MY_CITY = config['myConfig']['MY_CITY']
                print("MY_CITY = ",  config['myConfig']['MY_CITY'])
            if "MY_COUNTRY" in config["myConfig"]:
                configuration.MY_COUNTRY = config['myConfig']['MY_COUNTRY']
                print("MY_COUNTRY = ",  config['myConfig']['MY_COUNTRY'])
            if "MY_IP_ADDRESS" in config["myConfig"]:
                configuration.MY_IP_ADDRESS = config['myConfig']['MY_IP_ADDRESS']
                print("MY_IP_ADDRESS = ",  config['myConfig']['MY_IP_ADDRESS'])
            if "MY_LATITUDE" in config["myConfig"]:
                configuration.MY_LATITUDE = float(config['myConfig']['MY_LATITUDE'])
                print("MY_LATITUDE = ",  float(config['myConfig']['MY_LATITUDE']))
            if "MY_LONGITUDE" in config["myConfig"]:
                configuration.MY_LONGITUDE = float(config['myConfig']['MY_LONGITUDE'])
                print("MY_LONGITUDE = ",  float(config['myConfig']['MY_LONGITUDE']))
            if "MY_REGION" in config["myConfig"]:
                configuration.MY_REGION = config['myConfig']['MY_REGION']
                print("MY_REGION = ",  config['myConfig']['MY_REGION'])
            if "MAP_CENTER_LAT" in config["myConfig"]:
                configuration.MAP_CENTER_LAT = float(config['myConfig']['MAP_CENTER_LAT'])
                print("MAP_CENTER_LAT = ",  float(config['myConfig']['MAP_CENTER_LAT'])) 
            if "MAP_CENTER_LON" in config["myConfig"]:
                configuration.MAP_CENTER_LON = float(config['myConfig']['MAP_CENTER_LON'])
                print("MAP_CENTER_LON = ",  float(config['myConfig']['MAP_CENTER_LON']))    
            if "MAP_INFO_LAT" in config["myConfig"]:
                configuration.MAP_INFO_LAT = float(config['myConfig']['MAP_INFO_LAT'])
                print("MAP_INFO_LAT = ",  float(config['myConfig']['MAP_INFO_LAT']))   
            if "MAP_INFO_LON" in config["myConfig"]:
                configuration.MAP_INFO_LON = float(config['myConfig']['MAP_INFO_LON'])
                print("MAP_INFO_LON = ",  float(config['myConfig']['MAP_INFO_LON']))               
            if "MAP_ZOOM" in config["myConfig"]:
                configuration.MAP_ZOOM = int(config['myConfig']['MAP_ZOOM'])
                print("MAP_ZOOM = ",  int(config['myConfig']['MAP_ZOOM']))          
            if "USE_WHITE_LIST" in config["myConfig"]:
                configuration.USE_WHITE_LIST = int(config['myConfig']['USE_WHITE_LIST'])
                print("USE_WHITE_LIST = ",  configuration.USE_WHITE_LIST)     
            if "BlackList" in config["myConfig"]:
                configuration.BlackList = config['myConfig']['BlackList']
                print("BlackList = ",  configuration.BlackList)     
            if "WhiteList" in config["myConfig"]:
                configuration.WhiteList = config['myConfig']['WhiteList']
                print("WhiteList = ",  configuration.WhiteList)   
            if "WhiteListNotKill" in config["myConfig"]:
                configuration.WhiteListNotKill = json.loads(config['myConfig']['WhiteListNotKill'])
                print("WhiteListNotKill = ",  configuration.WhiteListNotKill)
            if "BlackListOwner" in config["myConfig"]:
                configuration.BlackListOwner = json.loads(config['myConfig']['BlackListOwner'])
                print("BlackListOwner = ",  configuration.BlackListOwner)
            if "WhiteListOwner" in config["myConfig"]:
                configuration.WhiteListOwner = json.loads(config['myConfig']['WhiteListOwner'])
                print("WhiteListOwner = ",  configuration.WhiteListOwner)
            if "BlackListCity" in config["myConfig"]:
                configuration.BlackListCity = json.loads(config['myConfig']['BlackListCity'])
                print("BlackListCity = ",  configuration.BlackListCity)
            if "WhiteListCity" in config["myConfig"]:
                configuration.WhiteListCity = json.loads(config['myConfig']['WhiteListCity'])
                print("WhiteListCity = ",  configuration.WhiteListCity)
        ###########################        
        
        # initialize list with known locations from file
        ##########################
        locationsFile = open("locationsResolved.json",  "r", encoding="utf-8")
        self.locationsResolved = list(locationsFile) # list of geo-locations, each in json format (same in .json file)
        locationsFile.close()
        i = 0
        # covert json "string" to dictionary format - index exception only works with "dictionary" format!
        for location in self.locationsResolved:
            if location != "":
                self.locationsResolved[i] = json.loads(location)
                i = i +1
        
        # MAC address of device
        ##############
        print("MAC address (hex) = ",  hex(uuid.getnode())) 
        print("MAC address (fmt) =  ", end="") 
        print(':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) 
        for ele in range(0,8*6,8)][::-1])) 
        # MAC address of router
        print("MAC of router = ",  get_mac_address(ip=configuration.ROUTER_IP))
        # resolve local and public host
        #################
        self.localHost = socket.gethostname()
        self.local = socket.gethostbyname(self.localHost)
        self.badConnectionKillerObject.setLocalIP(self.local)
        print("Local IP address = ", self.local)
        netlocalendpos = find_2nd(self.local, ".")
        self.netlocal = self.local[:netlocalendpos+1]
        #################
        if configuration.PUBLIC_IP == "":
            try:
                self.public = requests.get('http://ip.42.pl/raw').text
            except Exception as e:
                self.public = ""
                print("processor.__init__(): Exception when calling requests.get('http://ip.42.pl/raw'): ",  e)
                ctypes.windll.user32.MessageBoxW(0, "Could not retrieve the public IP. Please check your network connection!", "Warning! No public IP.", 0)
        else:
            self.public = configuration.PUBLIC_IP
        #################
        print("Public IP address = ", self.public)
        try:
            self.publicHost = socket.gethostbyaddr(self.public)
            self.publicHost = self.publicHost[0]
        except Exception as e:
            self.publicHost = "(not found)"
            print("processor.__init__(): Exception when calling gethostbyaddr(): ",  e)
        print("Host name of Local IP address = ",  self.localHost)
        print("Host name of Public IP address = ",  self.publicHost)
        # Note: we dont get location with DbIpCity.get() because we may appear e.g. in "another" city near us.
        #          Instead, we use configuration:
        self.response_public = DbIpCityResponse(
                                configuration.MY_CITY, configuration.MY_COUNTRY, configuration.MY_IP_ADDRESS, configuration.MY_LATITUDE, 
                                configuration.MY_LONGITUDE, configuration.MY_REGION)
        self.response_public.ip_address =  self.public # overwrite IP, even if it is actually somewhere else
        print("Location:\n",  self.response_public)
    ######################
    # end of __init__()
    
    ######################
    # helper function used in plotMap()
    # converts input float argument rx 
    # to an integer in the range MIN_MARKER_SIZE to MAX_MARKER_SIZE
    # considering saturation defined by MAX_RX_BYTES, where we return MAX_MARKER_SIZE
    def getRxInt(self, rx):
        # set rx_int
        if rx < configuration.MAX_RX_BYTES:
            # linear growth between zero and max. traffic
            # moving between 30 and 130
            rx_int = (rx*100.0)/configuration.MAX_RX_BYTES + configuration.MIN_MARKER_SIZE
        else:
            # saturation
            rx_int = configuration.MAX_MARKER_SIZE
        # return value
        return rx_int
    ######################
    # end of getRxInt()
        
    #-------------------------------------------------------------------------------------------------------------------
    ######################
    # plot the map
    # Each time plotMap() is called we create NEW structures (latitude_local[]..) to draw.
    # This could be improved by storing and extending these structures instead, but we dont do that
    # in order to be more flexible and e.g. apply filters based directly on the original data.
    ######################
    def plotMap(self):
        # firs clear update flag
        self.needUpdate = False
        # Local variables
        latitude_local_list = []
        longitude_local_list = []
        latitude_bad_local_list = []
        longitude_bad_local_list = []
        # copy values to avoid inconsistencies if configuration is changed
        MIN_MARKER_SIZE = configuration.MIN_MARKER_SIZE
        BOUNCE = configuration.BOUNCE
        HEATMAP = configuration.HEATMAP
        HEATMAP_SRC = configuration.HEATMAP_SRC
        HEATMAP_DST = configuration.HEATMAP_DST
        SHOW_NODES = configuration.SHOW_NODES
        SHOW_CONNECTIONS = configuration.SHOW_CONNECTIONS
        SHOW_INFO = configuration.SHOW_INFO
        SHOW_HOST_GOOD = configuration.SHOW_HOST_GOOD
        SHOW_HOST_UNKNOWN = configuration.SHOW_HOST_UNKNOWN
        SHOW_HOST_BAD = configuration.SHOW_HOST_BAD
        SHOW_HOST_KILLED = configuration.SHOW_HOST_KILLED
        SHOW_HOST_PING = configuration.SHOW_HOST_PING
        SHOW_CONNECTION_GOOD = configuration.SHOW_CONNECTION_GOOD
        SHOW_CONNECTION_UNKNOWN = configuration.SHOW_CONNECTION_UNKNOWN
        SHOW_CONNECTION_BAD = configuration.SHOW_CONNECTION_BAD
        SHOW_CONNECTION_KILLED = configuration.SHOW_CONNECTION_KILLED
        SHOW_CONNECTIONS_ACTIVE = configuration.SHOW_CONNECTIONS_ACTIVE
        
        # create map object
        ############
        gmap = gmplot.GoogleMapPlotter(configuration.MAP_CENTER_LAT, configuration.MAP_CENTER_LON, configuration.MAP_ZOOM, configuration.currentmaptype,  showHeatmap=HEATMAP) 
        gmap.grids = True
        
        # API key
        # TODO: enter key here (from a file)
        ##############
        # gmap.apikey = "AIzaKyOeLFMnA__VmQDiZRiuz4kKjF_c9r1kWe8"
        # gmap.apikey = "free"
        
        # Grid
        ##############
        # gmap.grid(-67.42, 67.42, 10.0, -122.15, 42.15, 10.0) # eh?
        
        # Rings (distance rings)
        # TODO: new feature: to make it look more like a radar ;-)
        
        # same geo-locations are spread in a CIRCLE
        #########################
        for srcNode in self.node_dict.values():
            # first calculate size of node depending on RX traffic
            ##############################
            tx_int = MIN_MARKER_SIZE
            # only External Nodes for now..
            if srcNode.local == True:
                rx_int = MIN_MARKER_SIZE
            else:
                rx_int = self.getRxInt(float(srcNode.rx))
            ##############################
            # show srcNode with that owner ?
            if srcNode.show_host == True:
                if srcNode.bad:
                    latitude_bad_local = [] 
                    longitude_bad_local = []
                    # add all connections to communication partners as RED lines
                    for dstNode in srcNode.comm_partner_list:
                        # show dstNode with that owner ?
                        if self.node_dict[dstNode].show_host == True:
                            activeConnection = srcNode.conn_established==True or self.node_dict[dstNode].conn_established==True
                            killedConnection = dstNode in srcNode.comm_partner_list_killed or srcNode.ip in self.node_dict[dstNode].comm_partner_list_killed
                            # plot RED line
                            if (SHOW_CONNECTIONS and (SHOW_CONNECTION_BAD or (killedConnection and SHOW_CONNECTION_KILLED) or (activeConnection and SHOW_CONNECTIONS_ACTIVE))):
                                latitude_bad_local.append(srcNode.lat_plot)
                                longitude_bad_local.append(srcNode.lon_plot)
                                latitude_bad_local.append(self.node_dict[dstNode].lat_plot)
                                longitude_bad_local.append(self.node_dict[dstNode].lon_plot)
                                #############
                                # killed connections override other colors
                                if killedConnection:
                                    connection_color = configuration.CON_KILLED_COLOR
                                else:
                                    connection_color = configuration.CON_BAD_COLOR
                                #############
                                if activeConnection:
                                    gmap.plot(latitude_bad_local, longitude_bad_local, connection_color, edge_width=4.0)
                                else:
                                    gmap.plot(latitude_bad_local, longitude_bad_local, connection_color, edge_width=2.0)
                            # needed for heatmap
                            if HEATMAP:
                                if HEATMAP_SRC == True:
                                    latitude_bad_local_list.append(srcNode.lat_plot)
                                    longitude_bad_local_list.append(srcNode.lon_plot)
                                if HEATMAP_DST == True:
                                    latitude_bad_local_list.append(self.node_dict[dstNode].lat_plot)
                                    longitude_bad_local_list.append(self.node_dict[dstNode].lon_plot)
                    # add marker RED of source
                    if SHOW_NODES and (SHOW_HOST_BAD or (SHOW_HOST_KILLED and srcNode.killed==True) or (SHOW_HOST_PING and srcNode.ping==False)):
                        #############
                        # killed nodes override other colors
                        if srcNode.killed:
                            node_color = configuration.NODE_KILLED_COLOR
                        else:
                            node_color = configuration.NODE_BAD_COLOR
                        gmap.marker(srcNode.lat_plot, srcNode.lon_plot, node_color, title=srcNode.host, bounce=BOUNCE, dot=srcNode.ping, tx=tx_int, rx=rx_int)
                else: # this is a good guy
                    # add connections to communication partners 
                    # bad destinations will be added to bad path - RED lines
                    for dstNode in srcNode.comm_partner_list:
                        # show dstNode with that owner ?
                        if self.node_dict[dstNode].show_host == True:
                            latitude_local = []
                            longitude_local = []
                            latitude_bad_local = [] 
                            longitude_bad_local = []
                            if self.node_dict[dstNode].bad: # destination is bad
                                activeConnection = srcNode.conn_established==True or self.node_dict[dstNode].conn_established==True
                                killedConnection = dstNode in srcNode.comm_partner_list_killed or srcNode.ip in self.node_dict[dstNode].comm_partner_list_killed
                                # plot RED line
                                if (SHOW_CONNECTIONS and (SHOW_CONNECTION_BAD or (killedConnection and SHOW_CONNECTION_KILLED) or (activeConnection and SHOW_CONNECTIONS_ACTIVE))):
                                    latitude_bad_local.append(srcNode.lat_plot)
                                    longitude_bad_local.append(srcNode.lon_plot)
                                    latitude_bad_local.append(self.node_dict[dstNode].lat_plot)
                                    longitude_bad_local.append(self.node_dict[dstNode].lon_plot)
                                    #############
                                    # killed connections override other colors
                                    if killedConnection:
                                        connection_color = configuration.CON_KILLED_COLOR
                                    else:
                                        connection_color = configuration.CON_BAD_COLOR
                                    #############
                                    if activeConnection:
                                        gmap.plot(latitude_bad_local, longitude_bad_local, connection_color, edge_width=4.0)
                                    else:
                                        gmap.plot(latitude_bad_local, longitude_bad_local, connection_color, edge_width=2.0)
                                # needed for heatmap
                                if HEATMAP:
                                    if HEATMAP_SRC == True:
                                        latitude_bad_local_list.append(srcNode.lat_plot)
                                        longitude_bad_local_list.append(srcNode.lon_plot)
                                    if HEATMAP_DST == True:
                                        latitude_bad_local_list.append(self.node_dict[dstNode].lat_plot)
                                        longitude_bad_local_list.append(self.node_dict[dstNode].lon_plot)
                            else: # both hosts are good
                                activeConnection = srcNode.conn_established==True or self.node_dict[dstNode].conn_established==True
                                killedConnection = dstNode in srcNode.comm_partner_list_killed or srcNode.ip in self.node_dict[dstNode].comm_partner_list_killed
                                # plot line
                                if SHOW_CONNECTIONS:
                                    latitude_local.append(srcNode.lat_plot)
                                    longitude_local.append(srcNode.lon_plot)
                                    latitude_local.append(self.node_dict[dstNode].lat_plot)
                                    longitude_local.append(self.node_dict[dstNode].lon_plot)
                                    if srcNode.host_resolved == False or self.node_dict[dstNode].host_resolved == False:
                                        if (SHOW_CONNECTION_UNKNOWN or (killedConnection and SHOW_CONNECTION_KILLED) or (activeConnection and SHOW_CONNECTIONS_ACTIVE)):
                                            #############
                                            # killed connections override other colors
                                            if killedConnection:
                                                connection_color = configuration.CON_KILLED_COLOR
                                            else:
                                                connection_color = configuration.CON_UNKNOWN_COLOR
                                            #############
                                            if activeConnection:
                                                gmap.plot(latitude_local, longitude_local, connection_color, edge_width=4.0)
                                            else:
                                                gmap.plot(latitude_local, longitude_local, connection_color, edge_width=2.0)
                                    else:
                                        if (SHOW_CONNECTION_GOOD or (killedConnection and SHOW_CONNECTION_KILLED) or (activeConnection and SHOW_CONNECTIONS_ACTIVE)):
                                            #############
                                            # killed connections override other colors
                                            if killedConnection:
                                                connection_color = configuration.CON_KILLED_COLOR
                                            else:
                                                connection_color = configuration.CON_GOOD_COLOR
                                            #############
                                            if activeConnection:
                                                gmap.plot(latitude_local, longitude_local, connection_color, edge_width=4.0)
                                            else:
                                                gmap.plot(latitude_local, longitude_local, connection_color, edge_width=2.0)
                                # needed for heatmap
                                if HEATMAP:
                                    if HEATMAP_SRC == True:
                                        latitude_local_list.append(srcNode.lat_plot)
                                        longitude_local_list.append(srcNode.lon_plot)
                                    if HEATMAP_DST == True:
                                        latitude_local_list.append(self.node_dict[dstNode].lat_plot)
                                        longitude_local_list.append(self.node_dict[dstNode].lon_plot)
                    # add marker UNKNOWN source
                    if srcNode.host_resolved == False:
                        if SHOW_NODES and (SHOW_HOST_UNKNOWN or (SHOW_HOST_KILLED and srcNode.killed==True) or (SHOW_HOST_PING and srcNode.ping==False)):
                            if "(unknown)" in srcNode.host:
                                #############
                                # killed nodes override other colors
                                if srcNode.killed:
                                    node_color = configuration.NODE_KILLED_COLOR
                                else:
                                    node_color = configuration.NODE_UNKNOWN_OLD_COLOR
                                #############
                                gmap.marker(srcNode.lat_plot, srcNode.lon_plot, node_color, title=srcNode.host, bounce=BOUNCE, dot=srcNode.ping, tx=tx_int, rx=rx_int)
                            else:
                                #############
                                # killed nodes override other colors
                                if srcNode.killed:
                                    node_color = configuration.NODE_KILLED_COLOR
                                else:
                                    node_color = configuration.NODE_UNKNOWN_COLOR
                                #############
                                gmap.marker(srcNode.lat_plot, srcNode.lon_plot, node_color, title=srcNode.host, bounce=BOUNCE, dot=srcNode.ping, tx=tx_int, rx=rx_int)
                    else:
                        # add marker GOOD source
                        if SHOW_NODES and (SHOW_HOST_GOOD or (SHOW_HOST_KILLED and srcNode.killed==True) or (SHOW_HOST_PING and srcNode.ping==False)):
                            markerColor = configuration.NODE_GOOD_COLOR
                            # we assume internal NW sources are always good (yes, even your wife! :-)
                            if srcNode.ip.startswith(self.netlocal):
                                if srcNode.ip == configuration.ROUTER_IP:
                                    markerColor = configuration.NODE_ROUTER_COLOR
                                # TODO: distinguish local PCs, broadcast and multicast
                                elif srcNode.ip == self.local:
                                    markerColor = configuration.NODE_MY_DEVICE_COLOR
                                else:
                                    markerColor = configuration.NODE_DEFAULT_COLOR
                            #############
                            # killed nodes override other colors
                            if srcNode.killed:
                                node_color = configuration.NODE_KILLED_COLOR
                            else:
                                node_color = markerColor
                            #############
                            gmap.marker(srcNode.lat_plot, srcNode.lon_plot, node_color, title=srcNode.host, bounce=BOUNCE, dot=srcNode.ping, tx=tx_int, rx=rx_int)
        
        ###########################
        # heatmap
        if HEATMAP:
            gmap.heatmap(latitude_local_list, longitude_local_list, threshold=10, radius=40)
            gmap.heatmap(latitude_bad_local_list, longitude_bad_local_list, threshold=10, radius=40)

        ############################
        # marker with last update-time
        ############################
        if SHOW_INFO:
            info = strftime("%Y.%m.%d %H:%M:%S", gmtime()) + " marks = " + str(len(self.node_dict))
            gmap.marker(configuration.MAP_INFO_LAT, configuration.MAP_INFO_LON, configuration.NODE_DEFAULT_COLOR, title=info, bounce=BOUNCE, dot=False, tx=MIN_MARKER_SIZE, rx=MIN_MARKER_SIZE)

        # WORKAROUND
        # TODO: find actual problem!
        #################
        # check also 
        tempDoDraw = True
        for point in gmap.points:
            if point[0] == None or point[1] == None:
                # tuples cannot be changed!
                # point[0] = 0.1
                # point[1] = 0.1
                tempDoDraw = False
                print("************* ERR: point with None value!!!")
                for ip in self.node_dict:
                    if self.node_dict[ip].lat == None or self.node_dict[ip].lon == None:
                        self.node_dict[ip].lat = 0.1
                        self.node_dict[ip].lon = 0.1
                        print("************* corrected lat, lon of IP ",  ip)
        #################

        # draw map
        #######
        if tempDoDraw:
            try:
                gmap.draw("Output/map_"+configuration.START_TIME+".html")
            except Exception as e:
                print("plotMap()->gmap.draw() throwed exception = ",  e)
    ##########
    # end of plotMap()
    #-------------------------------------------------------------------------------------------------------------------
    
    #-------------------------------------------------------------------------------------------------------------------
    #########################
    # check if new hosts have been pinged positively
    def checkForHostsPinged(self):
        pinged_host_list = self.pingResolverObject.getPingedHosts()
        if pinged_host_list:
            # loop list of already resolved hosts
            for ipAddress in pinged_host_list:
                # check because if it is a "random" IP it will not yet be in node_dict
                if ipAddress in self.node_dict:
                    self.node_dict[ipAddress].ping = True
                    # add/modify updated IP to GUI-List
                    self.__mutex.acquire()
                    self.node_dict_gui[ipAddress] =  self.node_dict[ipAddress]
                    self.__mutex.release()
                else:
                    print("Error: ping result of host which is not yet in node_dict! IP = ", ipAddress)
            # set flag
            self.needUpdate = True
    #########################
    # end of checkForHostsPinged()
    #-------------------------------------------------------------------------------------------------------------------
    
    #-------------------------------------------------------------------------------------------------------------------
    ######################
    # check if new hosts have been resolved
    def checkForHostsResolution(self):
        resolved_host_list = self.hostResolverObject.getResolvedHosts()
        if resolved_host_list:
            # loop list of already resolved hosts
            for host in resolved_host_list:
                ipAddress = host["ip"]
                self.node_dict[ipAddress].host = str(self.node_dict[ipAddress].pos) + ": " + host["host"]
                self.node_dict[ipAddress].whosip = host["whosip"]
                self.node_dict[ipAddress].host_resolved = True
                if ipAddress not in self.hostsResolved:
                    # is this (unknown)?
                    # add only if really resolved..
                    if "(unknown)" not in host["host"]:
                        # add to dict of resolved hosts
                        self.hostsResolved[ipAddress] = host["host"]
                        print("resolved host = " + host["host"] + " for IP = " + host["ip"] + " in position " + str(self.node_dict[ipAddress].pos))
                # if BAD: it may be a "white-listed" owner -> make it GOOD again
                # note: when we marked host as BAD, we didn't yet know the owner and could not check if it was white-listed
                #############################################################
                if self.node_dict[ipAddress].bad:
                    for owner in configuration.WhiteListOwner:
                        # check if owner in whosip (ignore upper/lower case)
                        # TODO: improvement: store all individual fields of whosip in separate fieds in node so we can use them directly
                        if re.search("Owner Name:   "+owner,  self.node_dict[ipAddress].whosip, re.IGNORECASE) != None:
                            # mark as good again
                            self.node_dict[ipAddress].bad = False
                            print("\n\"WARNING! previously detected illegal IP {0} in country {1} is set back to GOOD cause whilte-list owner = {2}\"".format(ipAddress,  self.node_dict[ipAddress].country_iso,  owner))
                            self.sanitized_ip.append(ipAddress)
                            break
                    # if we are still BAD it means bad IP has no white-listed owner
                    if self.node_dict[ipAddress].bad == True:
                        print("\n\"ALARM CONFIRMATION! the detected illegal IP {0} in country {1} is indeed a BAD guy.\"".format(ipAddress,  self.node_dict[ipAddress].country_iso))
                # else if not yet BAD: it may be an illegal OWNER -> make it BAD and add it to firewall rule
                ####################################################
                else:
                    # owner empty?
                    #########
                    if re.search("Owner Name:   ,", self.node_dict[ipAddress].whosip) != None: 
                        print("Owner is empty so we assume it is BAD!")
                        self.node_dict[ipAddress].bad = True
                        print("\n\"ALARM! detected illegal owner {0} with IP {1} in country {2}\"".format("",  ipAddress,  self.node_dict[ipAddress].country_iso))
                    # otherwise check black list of owners
                    ######################
                    else:
                        for badOwner in configuration.BlackListOwner:
                            # black-listed owner?
                            if re.search("Owner Name:   "+badOwner,  self.node_dict[ipAddress].whosip, re.IGNORECASE) != None:
                                reallyBad = True
                                # got black-listed owner string but - just to be 100% sure - we check that owner does NOT contain string in white-list
                                for goodOwner in configuration.WhiteListOwner:
                                    if re.search("Owner Name:   "+goodOwner,  self.node_dict[ipAddress].whosip, re.IGNORECASE) != None:
                                        # got white-listed owner string, although we had black-listed owner string
                                        print("What? got good owner string {0}, although we had bad owner string {1}. Just to be sure we leave it as GOOD!".format(goodOwner,  badOwner))
                                        reallyBad = False
                                        break
                                # owner in black-list and NOT in white-list    
                                if reallyBad:
                                    self.node_dict[ipAddress].bad = True
                                    print("\n\"ALARM! detected illegal owner {0} with IP {1} in country {2}\"".format(badOwner,  ipAddress,  self.node_dict[ipAddress].country_iso))
                                    break
                                
                # handle BAD host as it corresponds
                #####################
                if self.node_dict[ipAddress].bad == True:
                    print("\n\"Processing  bad IP = {0} \"".format(ipAddress))
                    # add bad IP to bad connection killer
                    self.badConnectionKillerObject.putIPToKill(ipAddress)
                    # add rule to Firewall?
                    #############
                    if configuration.ADD_FIREWALL_RULE_BLOCK_BAD_IP:
                        if configuration.RUN_AS_ADMIN:
                            response_src_temp = self.node_dict[ipAddress].country_iso+","+self.node_dict[ipAddress].city
                            response_src_temp = response_src_temp+","+str(self.node_dict[ipAddress].whosip).replace("'", "")
                            ##################
                            # and now remove all spaces
                            # firewall does not like spaces
                            response_src_temp = response_src_temp.replace(" ", "")
                            self.firewallManagerObject.putHostToRule(ipAddress, response_src_temp)
                        else:
                            msg = "ERROR: shall add rule to firewall to block IP " + ipAddress + " but have no Admin rights!"
                            print(msg)
                    # play alarm?
                    ########
                    if configuration.SOUND:
                        playsound('Sounds/Alarm/salamisound-8723691-alarm-sirene-auto.mp3', block=False)
                        
                # add/modify updated IP to GUI-List
                #####################
                self.__mutex.acquire()
                self.node_dict_gui[ipAddress] =  self.node_dict[ipAddress]
                self.__mutex.release()
                ###################
            # set flag
            self.needUpdate = True
    #########################
    # end of checkForHostsResolution()
    #-------------------------------------------------------------------------------------------------------------------
    
    #-------------------------------------------------------------------------------------------------------------------
    #########################
    # check if new processes have been killed in order to stop the connection to a BAD IP
    def checkKilledConnections(self):
        killed_ip_dict = self.badConnectionKillerObject.getKilledIPs()
        if killed_ip_dict:
            # loop dict of killed connections
            for killed_ip,  killed_process in killed_ip_dict.items():
                # mark node as killed (if available in node dict)
                if killed_ip in self.node_dict:
                    self.node_dict[killed_ip].killed = True
                    self.node_dict[killed_ip].killed_process = killed_process
                    # add/modify updated IP to GUI-List
                    self.__mutex.acquire()
                    self.node_dict_gui[killed_ip] =  self.node_dict[killed_ip]
                    self.__mutex.release()
                # loop all nodes
                for ip in self.node_dict:
                    if killed_ip in self.node_dict[ip].comm_partner_list:
                        self.node_dict[ip].comm_partner_list_killed.append(killed_ip)
                        self.node_dict[ip].comm_partner_list.remove(killed_ip)
                        print("Killed connection "+ip+" to "+killed_ip)
                        # add/modify updated IP to GUI-List
                        self.__mutex.acquire()
                        self.node_dict_gui[ip] =  self.node_dict[ip]
                        self.__mutex.release()
            # set flag
            self.needUpdate = True
    #########################
    # end of checkKilledConnections()
    #-------------------------------------------------------------------------------------------------------------------
    
    #-------------------------------------------------------------------------------------------------------------------
    #########################
    # check current active connections (=estalished)
    def checkActiveConnections(self):
        oldNrOfConnections = len(self.connected_ip_list)
        connected_ip_list_temp = self.badConnectionKillerObject.getConnectedIPs()
        # need copy so we can remove unknown IPs later
        connected_ip_list_local = deepcopy(connected_ip_list_temp) 
        if connected_ip_list_local:
            # first clear all connection flags which dont exist anymore
            for oldConnectedIP in self.connected_ip_list:
                if oldConnectedIP not in connected_ip_list_local:
                    # change from True to False
                    self.node_dict[oldConnectedIP].conn_established = False
            # loop list of active connections and set flag to True in node_dict
            for connected_ip in connected_ip_list_local:
                if connected_ip in self.node_dict: # need check in case we detect a conneciton of an IP which is not yet registered..
                    self.node_dict[connected_ip].conn_established = True
                else:
                    # we make sure only known IPs are kept in the list
                    connected_ip_list_temp.remove(connected_ip)
            ###########################
            # cross check to detect changes and inform GUI
            ###########################
            for ip in self.connected_ip_list:
               if ip not in connected_ip_list_temp:
                    # add/modify updated IP to GUI-List
                    if ip in self.node_dict: # may be connection of IP whic is not (yet) registered
                        self.__mutex.acquire()
                        self.node_dict_gui[ip] =  self.node_dict[ip]
                        self.__mutex.release()
            for ip in connected_ip_list_temp:
               if ip not in self.connected_ip_list:
                    # add/modify updated IP to GUI-List
                    if ip in self.node_dict: # may be connection of IP whic is not (yet) registered
                        self.__mutex.acquire()
                        self.node_dict_gui[ip] =  self.node_dict[ip]
                        self.__mutex.release()
            ####################################
            # update list of connected IPs
            self.connected_ip_list = connected_ip_list_temp
        else:
            # clear flags,  reset list and also local handling...
            if self.connected_ip_list: # need this?
                # NOTE: getConnectedIPs() returns constantly empty list
                # so we need to check if there are really zero connections by checking nr. of connections
                if self.badConnectionKillerObject.getNumberOfConnections() == 0:
                    for oldConnectedIP in self.connected_ip_list:
                        # for some reason we need this check. 
                        # TODO: how is it possible that the oldConnectedIP is NOT in the node_dict?
                        # we checked before and we copied from connected_ip_list_temp only IPs that exist in node_dict..
                        #######################################################
                        if oldConnectedIP in self.node_dict:
                            self.node_dict[oldConnectedIP].conn_established = False
                    # for some reason we need this check
                    # TODO: same as above..
                    #############################
                    if self.local in self.node_dict:
                        # clear also local IP
                        self.node_dict[self.local].conn_established = False
                    # now clear list
                    self.connected_ip_list = []
                else:
                    # TODO: correct this behavior: getConnectedIPs() returns permanently empty list
                    msg = "Error: nr. of connections = " + str(self.badConnectionKillerObject.getNumberOfConnections()) + " but returned list is empty!"
                    print(msg)
        # need update?
        # for now we only update when previous nr. of connections differs to current nr. of connecitons
        # TODO: cover also the case where changes in connections result in the same number of connections
        if oldNrOfConnections != len(self.connected_ip_list):
            self.needUpdate = True
    #########################
    # end of checkActiveConnections()
    #-------------------------------------------------------------------------------------------------------------------
    
    #-------------------------------------------------------------------------------------------------------------------
    ######################
    # de-queued packets are processed here
    # "re-draw" map ONLY if new connection received!
    ######################
    def processPacket(self,  packet):
        print("processing nr. of packets = " + str(self.processedPacketsCount) + ", still in queue " + str(self.sizeOfProcessingQueue))
        
        # IP attribute available?
        ##############
        try:
            packet.ip
        except AttributeError:
            print("processor.processPacket(): Exception: AttributeError on packet.ip")
            #############################
            # TODO: implement handling of packets without IP address field:
            # print("packet = ",  packet) 
            #############################
            return

        # local copies of IPs
        ###############
        source = packet.ip.src
        destination = packet.ip.dst

        # when we have our "local" IP address we map it to the "public" IP address:
        ##########################################
        src_is_local = False
        host_src_resolved = False
        host_dst_resolved = False
        transmitting = False
        receiving = False
        
        # set SRC host if local
        if source.startswith(self.netlocal):
            if source == configuration.ROUTER_IP:
                host_src = source + " (router) " + self.publicHost # public host for router/gateway
            # TODO: distinguish local PCs, broadcast and multicast
            elif source == self.local:
                host_src = source + " (my device) " + self.localHost
                transmitting = True
            else:
                # TODO: improvement: see if there is a way to obtain the COMPUTER NAME of the machine in the lcoal NW
                # and use it instead of self.publicHost
                host_src = source + " (local) " + self.publicHost
            src_is_local = True
            host_src_resolved = True
        else:
            host_src = source + " src_host"
            
        # and now set DST host if local
        ##########################
        dst_is_local = False
        if destination.startswith(self.netlocal):
            if destination == configuration.ROUTER_IP:
                host_dst = destination + " (router) " + self.publicHost # public host for router/gateway
            # TODO: distinguish local PCs, broadcast and multicast
            elif destination == self.local:
                host_dst = destination + " (my device) " + self.localHost
                receiving = True
            else:
                # TODO: improvement: see if there is a way to obtain the COMPUTER NAME of the machine in the lcoal NW
                # and use it instead of self.publicHost
                host_dst = destination + " (local) " + self.publicHost
            dst_is_local = True
            host_dst_resolved = True
        else:
            host_dst = destination + " dst_host"
            
        # nr. of TX and RX KiloBytes
        #################
        if transmitting:
            self.tx_kilo_bytes = self.tx_kilo_bytes + float(packet.length)/1024.0
            self.tx_kilo_bytes_alarm = self.tx_kilo_bytes_alarm + float(packet.length)/1024.0
            if self.tx_kilo_bytes_alarm > configuration.MAX_TX_KILOBYTES:
                # set to zero and start counting again..until we reach MAX_TX_KILOBYTES again
                self.tx_kilo_bytes_alarm = 0.0
                print("ALARM: got more TX bytes than maximum = ",  configuration.MAX_TX_KILOBYTES)
                if configuration.SOUND:
                    playsound('Sounds/Alarm/salamisound-4299638-alarm-sirene-13-mal-heulen.mp3', block=False)
        elif receiving:
            self.rx_kilo_bytes = self.rx_kilo_bytes + float(packet.length)/1024.0

        # is this a NEW connection?
        ################
        newConnection = True
        if source in self.node_dict: 
            if destination in self.node_dict[source].comm_partner_list:
                # existent connection, we'll return
                newConnection = False
                
        if newConnection:
            # we have a NEW connection
            #################
            print_info_layer(packet)
            # different sound for local and remote connections
            if configuration.SOUND:
                if src_is_local and dst_is_local:
                    playsound('Sounds/mb_sc.mp3', block=False)
                else:
                    playsound('Sounds/smb_flagpole.mp3', block=False)
            
            # resolve geolocation for source address
            ######################
            geoLocationNotResolved = True
            # check if src location already exists
            # TODO: check if this takes even more time than just calling DbIpCityResponse() in any case.
            #            That will depend on the size of the file locationsResolved.json and the nr. of locations we need to resolve in a specified time period.
            #             On the other side it's always good to reduce network traffic, right? So, using locationsResolved.json is probably a good idea after all.
            if src_is_local:
                # Note: local IP, we store it neither in self.locationsResolved nor in locationsResolved.json
                response_src = self.response_public
                geoLocationNotResolved = False
            else:
                for location in self.locationsResolved:
                    if location != "":
                        if location["ip_address"] == source:
                            response_src = DbIpCityResponse(
                                location["city"], location["country"], location["ip_address"], location["latitude"], 
                                location["longitude"], location["region"])
                            geoLocationNotResolved = False
                            break
            # source already resolved?    
            if geoLocationNotResolved:
                try:
                    response_src = DbIpCity.get(source, api_key='free')
                    # workaround
                    # TODO: need this or use instead exception catch?
                    #############################
                    if response_src.latitude == None or response_src.longitude == None:
                        print("****** processor.py.processPacket():ERROR: DbIpCity.get(source) = None")
                        # return
                        # INSTEAD of returning we set default lat lon
                        response_src.latitude = 0.1
                        response_src.longitude = 0.1
                    # WORKAROUND: for some reason sometimes latitude and longitude are None
                    #############################
                    # in order to detect that we check by using them and evtl. generating an exception
                    response_src.latitude = response_src.latitude
                    response_src.longitude = response_src.longitude
                # KeyError
                except Exception as e:
                    print("processor.py.processPacket():Exception: DbIpCity.get(source) = ",  e)
                    return
                # cath further errors
                if response_src == None:
                    return
                # convert new location to json format
                js = response_src.to_json()
                # append to file only if really resolved
                if (response_src.latitude != 0.1) and (response_src.longitude != 0.1):
                    locationsFile = open("locationsResolved.json",  "a", encoding="utf-8")
                    locationsFile.write(js) 
                    locationsFile.write("\n")
                    locationsFile.close()
                # store in memory
                js = json.loads(response_src.to_json())
                self.locationsResolved.append(js)
                
            # resolve geolocation for destination address
            ######################
            geoLocationNotResolved = True
            # check if dst location already exists
            if dst_is_local:
                # Note: local IP, we store it neither in self.locationsResolved nor in locationsResolved.json
                response_dst = self.response_public
                geoLocationNotResolved = False
            else:
                for location in self.locationsResolved:
                    if location != "":
                        if location["ip_address"] == destination:
                            response_dst = DbIpCityResponse(
                                location["city"], location["country"], location["ip_address"], location["latitude"], 
                                location["longitude"], location["region"])
                            geoLocationNotResolved = False
                            break
            # destination already resolved?    
            if geoLocationNotResolved:
                try:
                    response_dst = DbIpCity.get(destination, api_key='free')
                    # workaround
                    # TODO: need this or use instead exception catch?
                    #############################
                    if response_dst.latitude == None or response_dst.longitude == None:
                        print("******** processor.py.processPacket():ERROR: DbIpCity.get(destination) = None")
                        # return
                        # INSTEAD of returning we set default lat lon
                        response_dst.latitude = 0.1
                        response_dst.longitude = 0.1
                    # WORKAROUND: for some reason sometimes latitude or longitude are None
                    ########
                    # in order to detect that we check by using them and evtl. generating an exception
                    response_dst.latitude = response_dst.latitude
                    response_dst.longitude = response_dst.longitude
                # KeyError
                except Exception as e:
                    print("processor.py.processPacket():Exception: DbIpCity.get(destination) = ",  e)
                    return
                # cath further errors
                if response_dst == None:
                    return
                # convert new location to json format
                js = response_dst.to_json()
                # append to file only if really resolved
                if (response_dst.latitude != 0.1) and (response_dst.longitude != 0.1):
                    locationsFile = open("locationsResolved.json",  "a", encoding="utf-8")
                    locationsFile.write(js) 
                    locationsFile.write("\n")
                    locationsFile.close()
                # store in memory
                js = json.loads(response_dst.to_json())
                self.locationsResolved.append(js)
                
            if self.pingAuto:
                # we always ping new host as a source:
                if src_is_local != self.local:
                    self.pingResolverObject.putHostToPing(source)
                # we always ping new host as a destination:
                if dst_is_local != self.local:
                    self.pingResolverObject.putHostToPing(destination)
                
            # request/initiate host resolution (will be done delayed in a separate thread in background)
            ###################################################
            if src_is_local == False:
                if source in self.hostsResolved:
                    host_src = self.hostsResolved[source]
                    # if an "unknown" host was added to the list then we don't flag it as resolved
                    if "(unknown)" not in host_src:
                        host_src_resolved = True
                elif source not in self.hostsResolutionRequested: # could be currently in request
                    self.hostsResolutionRequested.append(source)
                    self.hostResolverObject.putHostToResolve(source)
                    if configuration.SOUND:
                        playsound('Sounds/smb_bump.mp3', block=False)
            if dst_is_local == False:
                if destination in self.hostsResolved:
                    host_dst = self.hostsResolved[destination]
                    # if an "unknown" host was added to the list then we don't flag it as resolved
                    if "(unknown)" not in host_dst:
                        host_dst_resolved = True
                elif destination not in self.hostsResolutionRequested: # could be currently in request
                    self.hostsResolutionRequested.append(destination)
                    self.hostResolverObject.putHostToResolve(destination)
                    if configuration.SOUND:
                        playsound('Sounds/smb_bump.mp3', block=False)
                 
            # MAC address
            #########
            # getmac page: https://github.com/GhostofGoes/getmac
            # "Remote hosts" refer to hosts in your local layer 2 network, also commonly referred to as a "broadcast domain", "LAN", or "VLAN".
            # As far as I know, there is no reliable method to get a MAC address for a remote host "external" to the LAN.
            if src_is_local == True:
               mac_src =  get_mac_address(ip=source)
            else:
                mac_src = ""
            if dst_is_local == True:
               mac_dst =  get_mac_address(ip=destination)
            else:
                mac_dst = ""
            #########
            
            # create nodes
            # cases:      src         dst         (exist)
            # 1.a            x            x
            # 1.b            x
            # 2.a                         x
            # 2.b         
            ################
            case = ""
            if source in self.node_dict: 
                # add destination in comm_partner_list of source
                self.node_dict[source].comm_partner_list.append(destination)
                ####################
                if destination not in self.node_dict: 
                    # add destination in node_dict (1.b)
                    case = "1b"
                    #########
                    # WARNING !!!
                    # we may need to try/except variables response_dst.latitude and response_dst.longitude
                    #########
                    dest_node = NodeDataClass(self.currentNodeNumber, destination, mac_dst, response_dst.latitude,  response_dst.longitude,  response_dst.latitude,  response_dst.longitude, 1,
                                        response_dst.country, pycountry.countries.get(alpha_2=response_dst.country),
                                        response_dst.region, response_dst.city,  host_dst, True, "", host_dst_resolved, ping=False, bad=False, killed=False, killed_process="", local=dst_is_local, conn_established=False,
                                        tx=0, rx=0, date=strftime("%Y.%m.%d", gmtime()), time=strftime("%H:%M:%S", gmtime()), comm_partner_list=[], comm_partner_list_killed=[])
                    self.node_dict[destination] = dest_node # new value in dict with key destination (its like an "append")  
                    self.currentNodeNumber = self.currentNodeNumber + 1
                else:
                    case = "1a"
                    pass
            else:
                # add source in node_dict
                source_node = NodeDataClass(self.currentNodeNumber, source, mac_src, response_src.latitude,  response_src.longitude,  response_src.latitude,  response_src.longitude,  1,
                                        response_src.country, pycountry.countries.get(alpha_2=response_src.country),
                                        response_src.region, response_src.city,  host_src, True, "",  host_src_resolved, ping=False, bad=False, killed=False, killed_process="", local=src_is_local, conn_established=False,
                                        tx=0, rx=0, date=strftime("%Y.%m.%d", gmtime()), time=strftime("%H:%M:%S", gmtime()), comm_partner_list=[destination], comm_partner_list_killed=[])
                self.node_dict[source] = source_node # new value in dict with key source (its like an "append")  
                self.currentNodeNumber = self.currentNodeNumber + 1
                ######################
                # no source, check if destination exists
                if destination not in self.node_dict:
                    # add destination in node_dict (2.b)
                    case = "2b"
                    #########
                    # WARNING !!!
                    # we may need to try/except variables response_dst.latitude and response_dst.longitude
                    #########
                    dest_node = NodeDataClass(self.currentNodeNumber, destination, mac_dst, response_dst.latitude,  response_dst.longitude,  response_dst.latitude,  response_dst.longitude,  1,
                                        response_dst.country, pycountry.countries.get(alpha_2=response_dst.country),
                                        response_dst.region, response_dst.city,  host_dst, True, "",  host_dst_resolved, ping=False, bad=False, killed=False, killed_process="", local=dst_is_local, conn_established=False,
                                        tx=0, rx=0, date=strftime("%Y.%m.%d", gmtime()), time=strftime("%H:%M:%S", gmtime()), comm_partner_list=[], comm_partner_list_killed=[])
                    self.node_dict[destination] = dest_node # new value in dict with key destination (its like an "append")  
                    self.currentNodeNumber = self.currentNodeNumber + 1
                else:
                    case = "2a"
                    pass

            ########################
            # update module variable location_dict (src)
            latlonsrc = str(self.node_dict[source].lat) + "," + str(self.node_dict[source].lon)
            if latlonsrc in self.location_dict: 
                if case == "2a" or case == "2b":
                    # increment count
                    self.location_dict[latlonsrc] = self.location_dict[latlonsrc] + 1 # updates value
                    # update also  the source position in node_dict
                    self.node_dict[source].position = self.location_dict[latlonsrc]
                    # and update the drawing position
                    # GeoLocationPhi = math.radians(360.0/self.node_dict[source].position)
                    GeoLocationPhi = math.radians(6.28*360.0/self.node_dict[source].position)
                    # set delta to CIRCLE in geo-location
                    latDelta = configuration.GeoLocationRadius*math.cos(GeoLocationPhi)
                    lonDelta = configuration.GeoLocationRadius*math.sin(GeoLocationPhi)
                    self.node_dict[source].lat_plot = self.node_dict[source].lat+latDelta
                    self.node_dict[source].lon_plot = self.node_dict[source].lon+lonDelta
            else: # it must be case 2a or 2b
                # add NEW location
                self.location_dict[latlonsrc] = 1 # new value 1 in dict with key latlonsrc (its like an "append")    
                # Note: self.node_dict[source].position already set to 1 by default        
            ########################
            # update module variable location_dict (dst)
            latlondst = str(self.node_dict[destination].lat) + "," + str(self.node_dict[destination].lon)
            if latlondst in self.location_dict: 
                if case == "1b" or case == "2b":
                    # increment count
                    self.location_dict[latlondst] = self.location_dict[latlondst] + 1 # updates value
                    # update also  the source position in node_dict
                    self.node_dict[destination].position = self.location_dict[latlondst]
                    # and update the drawing position
                    # GeoLocationPhi = math.radians(360.0/self.node_dict[destination].position)
                    GeoLocationPhi = math.radians(6.28*360.0/self.node_dict[destination].position)
                    # set delta to CIRCLE in geo-location
                    latDelta = configuration.GeoLocationRadius*math.cos(GeoLocationPhi)
                    lonDelta = configuration.GeoLocationRadius*math.sin(GeoLocationPhi)
                    self.node_dict[destination].lat_plot = self.node_dict[destination].lat+latDelta
                    self.node_dict[destination].lon_plot = self.node_dict[destination].lon+lonDelta
            else: # it must be case 1b or 2b
                # add NEW location
                self.location_dict[latlondst] = 1 # new value (its like an "append")    
                # Note: self.node_dict[destination].position already set to 1 by default 
                
            # src in black list / NOT in white list?
            #######################
            badIP = True
            if configuration.USE_WHITE_LIST:
                badIP = ((response_src.country not in configuration.WhiteList) and (response_src.city not in configuration.WhiteListCity)) or (response_src.city in configuration.BlackListCity)
            else:
                badIP = ((response_src.country in configuration.BlackList) and (response_src.city not in configuration.WhiteListCity)) or (response_src.city in configuration.BlackListCity)
            if badIP:
                # TODO: check this workaround - why do we need to check against sanitized_ip?
                if source not in self.sanitized_ip:
                    self.node_dict[source].bad = True
                    print("\n\"ALARM! detected PRESUMABLY illegal IP {0} in country {1}, city {2} but owner not yet known.\"".format(source,  response_src.country,  response_src.city))
                    # we delay putIPToKill(), adding rule to firewall and playing sound because it may be a whilte-listed onwer and we don't yet know the owner..
                    ##############################################################################
            # dst in black list or NOT in white list?
            #######################
            badIP = True
            if configuration.USE_WHITE_LIST:
                badIP = ((response_dst.country not in configuration.WhiteList) and (response_dst.city not in configuration.WhiteListCity)) or (response_dst.city in configuration.BlackListCity)
            else:
                badIP = ((response_dst.country in configuration.BlackList) and (response_dst.city not in configuration.WhiteListCity)) or (response_dst.city in configuration.BlackListCity)
            if badIP:
                # TODO: check this workaround - why do we need to check against sanitized_ip?
                if destination not in self.sanitized_ip:
                    self.node_dict[destination].bad = True
                    print("\n\"ALARM! detected PRESUMABLY illegal IP {0} in country {1}, city {2} but owner not yet known.\"".format(destination,  response_dst.country,  response_dst.city))
                    # we delay putIPToKill(), adding rule to firewall and playing sound because it may be a whilte-listed onwer and we don't yet know the owner..
                    ##############################################################################
                
            # print geolocations in CONSOLE
            ###################
            print_geolocations(response_src, response_dst, self.node_dict[source].host, self.node_dict[destination].host)
            
            # add new IP to GUI-List
            # eventually both, source and destination have been created or modified
            self.__mutex.acquire()
            self.node_dict_gui[source] =  self.node_dict[source]
            self.node_dict_gui[destination] = self.node_dict[destination]
            self.__mutex.release()

            # plot map is handled in block outside "if newConnection"
            ######################################################
        # end of block "if newConnection:"
        # if both IPs already exist we only update nr. of packets in next code block, outside this else..
        #####################################################
        
        #######################
        # common block for new and existent IPs
        #######################
        # Local -> Extern ?
        # for now we only care about TX bytes from local - that is, is there any INFORMATION LEAKAGE ?
        # but we also log RX to show in GUI as well. TX will additionally influence the size of the markers.
        # increment nr. of sent bytes from local in .rx of destination so it can be shown in marker height.
        # TODO: why do we need 2 steps here?
        rx = int(self.node_dict[destination].rx) + int(packet.length)
        self.node_dict[destination].rx = rx
        tx = int(self.node_dict[source].tx) + int(packet.length)
        self.node_dict[source].tx = tx
        
        # update self.node_dict_gui only if data is sent to outside: Local -> Extern
        if src_is_local == True:
            # Note: whatch out! we are NOT using the mutex...could have problems(?)
            # self.__mutex.acquire()
            self.node_dict_gui[destination] = self.node_dict[destination]
            # self.__mutex.release()
            # set flag to update plot
            self.needUpdate = True
            # txt = "Log level X: "+destination+" received "+str(packet.length)+", total = "+str(rx)
            # print(txt)
        # end of common block for existent and new IP addresses
        #########################################################
        
        ############
        if newConnection:
            # plot map
            if configuration.PLOT:
                self.plotMap()
            
        return 
    ##############
    # end of processPacket()
    #-------------------------------------------------------------------------------------------------------------------
    
    #################
    #-------------------------------------------------------------------------------------------------------------------
    def getDictOfNodes(self):
        node_dict_gui_temp = {}
        self.__mutex.acquire()
        try:
            if self.node_dict_gui:
                for key,  value in self.node_dict_gui.items():
                    node_dict_gui_temp[key] = value
                # now clear local list
                self.node_dict_gui = {}
            else:
                node_dict_gui_temp = {}
        except Exception as e:
            print("Exception in processor.getDictOfNodes() = ",  e)
            node_dict_gui_temp = {}
        finally:
            self.__mutex.release()

        return node_dict_gui_temp
    #################
    # end getListOfNodes()
    #-------------------------------------------------------------------------------------------------------------------
    
    #-------------------------------------------------------------------------------------------------------------------
    #############################
    # switch queues when current used queue gets empty (was guaranteed before call)
    def switchQueues(self): 
        if self.currentCallbackQueueIsA[0] == False:
            # queue is empty, we switch:
            # self.inputPacketsCount = 0
            self.processedPacketsCount = 0
            self.currentCallbackQueueIsA[0] = True
            # TODO: improvement: implement Log level 
            # print("\nLog level X: switch to callback queue A")
        else:
            # queue is empty, we switch:
            # self.inputPacketsCount = 0
            self.processedPacketsCount = 0
            self.currentCallbackQueueIsA[0] = False
            # TODO: improvement: implement Log level 
            # print("\nLog level X: switch to callback queue B")
    ###################
    # end of switchQueuesIfNeeded()
    #-------------------------------------------------------------------------------------------------------------------
 
    # ----------------------------------------------------------------------------------------------------------------------
    # thread to processi packets in queue
    ######################################
    def processingThread(self,  packetQueueA,  packetQueueB,  currentCallbackQueueIsA,  locationsRead):
        # set processor variables
        self.packetQueueA = packetQueueA
        self.packetQueueB = packetQueueB
        # set queue-switch-flag according configuration
        ###########################
        if configuration.USE_DOUBLE_BUFFER == True:
            self.currentCallbackQueueIsA = currentCallbackQueueIsA
        else:
            self.currentCallbackQueueIsA = [not self.currentCallbackQueueIsA[0]]
        ###########################
        self.locationsRead = locationsRead
   
        # synch point with sniffer thread -> signal to start now! 
        ################################
        self.locationsRead[0] = True
    
        # first time we need to wait for data on queue A
        # we continue when queue has at least one element
        ############################
        if configuration.USE_DOUBLE_BUFFER == True:
            while self.packetQueueA.empty(): # default queue at startup is A
                sleep(0.1) # 100ms
            # we switch queue
            # self.inputPacketsCount = 0
            self.processedPacketsCount = 0
            self.currentCallbackQueueIsA[0] = False
            # TODO: improvement: implement log level
            # print("\nLog level X: switch to callback queue B")
            
        # start time
        startTime = time()
            
        # main loop
        # poll queue as fast as we can!
        # and execute periodic tasks cooperatively
        ########################
        while True:
            if self.currentCallbackQueueIsA[0] == False:
                try:
                    # we "block" until a new element is put in the queue or the timer expires
                    # timeout of X seconds = period to check for active connections, etc. will ensure that
                    # we call self.checkActiveConnections(), etc. even if no new packets are received
                    ##########################################
                    packet = self.packetQueueA.get(block=True,  timeout=configuration.CHECK_PERIOD_IN_SEC*2.0) # 4.0) # get_nowait()
                    self.processedPacketsCount = self.processedPacketsCount + 1
                    # print("\nmain loop(A) = " + str(self.processedPacketsCount)) #  + ", still in queue " + str(self.sizeOfProcessingQueue))
                    self.sizeOfProcessingQueue = self.packetQueueA.qsize()
                    if  packet != None:
                        self.processPacket(packet)
                    if self.packetQueueA.empty() == True:
                        if configuration.USE_DOUBLE_BUFFER == True:
                            # switch only if the other queue is NOT empty, otherwise continue with queueA
                            if self.packetQueueB.empty() == False:
                                self.switchQueues()
                except Exception: # as e:
                    # print("No packet received in queue A within timeout.") # " Got exception = ", e)
                    # print("Queue A timeout.") # " Got exception = ", e)
                    pass
            else:
                try:
                    # we "block" until a new element is put in the queue or the timer expires
                    # timeout of X seconds = period to check for active connections, etc. will ensure that
                    # we call self.checkActiveConnections(), etc. even if no new packets are received
                    ##########################################
                    packet = self.packetQueueB.get(block=True,  timeout=configuration.CHECK_PERIOD_IN_SEC*2.0) # 4.0) # get_nowait()
                    self.processedPacketsCount = self.processedPacketsCount + 1
                    # print("\nmain loop(B) = " + str(self.processedPacketsCount)) #  + ", still in queue " + str(self.sizeOfProcessingQueue))
                    self.sizeOfProcessingQueue = self.packetQueueB.qsize()
                    if  packet != None:
                        self.processPacket(packet)
                    if self.packetQueueB.empty() == True:
                        if configuration.USE_DOUBLE_BUFFER == True:
                            # switch only if the other queue is NOT empty, otherwise continue with queueB
                            if self.packetQueueA.empty() == False:
                                self.switchQueues()
                except Exception: # as e:
                    # print("No packet received in Queue B within timeout.") # " Got exception = ", e)
                    # print("Queue B timeout.") # " Got exception = ", e)
                    pass
                    
            # currentTime
            ########
            timeDiff = time() - startTime
            
            # periodic tasks
            ##########
            if timeDiff > configuration.CHECK_PERIOD_IN_SEC:
                # start time
                startTime = time()
                print("Checking processing status..")
                #####################################
                # because we have a timeout queue..get(block=True,  timeout=2)
                # we will get here to do some stuff even if no new packets arrive..
                #####################################
                self.checkForHostsPinged()
                self.checkForHostsResolution()
                self.checkKilledConnections()
                self.checkActiveConnections()
                if self.needUpdate:
                    if configuration.PLOT:
                        self.plotMap()
        # end of main loop
        ##########
####################
# end of ProcessorClass
# -------------------------------------







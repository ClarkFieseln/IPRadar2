#######################################
# this file contains a super-set of configuration settings 
# some of whiche are also defined in config.ini
# values in config.ini will override the values given here!
#######################################

# run as admin?
# to kill (some) processes or add rules to the Windows firewall..
# when running as Admin we get a console
# very strange behavior...we start a complete new instance of the App
# we cannot debug when running as Admin..
###########################
RUN_AS_ADMIN = False

# font size
FONT_SIZE = 8

# rule name has to be set to the corresponding language
# run cmd:
# >netsh advfirewall firewall show rule name=all
# check left-side before ----------------------------
RULE_NAME_STR = "Rule name"

# connection "established" has to be set to the corresponding language
# run cmd:
# >netstat -an
# check for "established" connections in column Status
CONN_ESTABLISHED_STR = "ESTABLISHED"

# add a new rule in Windows Firewall to block a BAD-IP automatically
# WARNING!   ->  if set to True, then RUN_AS_ADMIN shall also be set to True !!!
ADD_FIREWALL_RULE_BLOCK_BAD_IP = False 

# shell to file?
SHELL_TO_FILE = False

# auto scroll node list?
AUTO_SCROLL_NODE_LIST = True

# PING parameters:
PING_TIMEOUT_SEC = 0.25
PING_SIZE_BYTES = 40
PING_COUNT = 1
# if option to ping a specified amount of random IPs is selected:
NR_OF_RANDOM_IPS_TO_PING = 10

# statistics
# saturation value MAX_COMM_BYTES
#######################
# MAX_COMM_BYTES = 1000.0 # 1KB
MAX_COMM_BYTES = 1000000.0 # 1MB
MAX_RX_BYTES = MAX_COMM_BYTES # from point of view of RX-Node
MAX_TX_BYTES = MAX_COMM_BYTES # from point of view or TX-Node
# to draw markers as a function of network traffic
MIN_MARKER_SIZE = 30
MAX_MARKER_SIZE = 130

# max TX data
# trigger Alarm if exceeded
MAX_TX_KILOBYTES = 10000

# to obtain interfaces, open cmd in folder with IPRadar2.exe and type: "WiresharkPortable/App/Wireshark/tshark" -D
INTERFACE = ""
        
# use double buffer between pyshark-callback and processing-thread
# *********************************************
# TODO: solve bug with double-buffer. It hangs when queue reaches zero the nth time...
# *********************************************
USE_DOUBLE_BUFFER = False

# check period in seconds
# to check, hosts resolutions, kill IPs and active connections
CHECK_PERIOD_IN_SEC = 0.5
# derived from this value we have:
# PING every (configuration.CHECK_PERIOD_IN_SEC)
# RESOLVE HOST evey (configuration.CHECK_PERIOD_IN_SEC)
# CHECK Active Connections and KILL every (configuration.CHECK_PERIOD_IN_SEC)
# UPDATE GUI every (configuration.CHECK_PERIOD_IN_SEC*2.0)
# trigger check of the above (CHECK_PERIOD_IN_SEC) -> put at lower rate than it can consume at once..

# packed visualization of output to terminal
# TODO: remove this 
PACKED_OUTPUT = False

# for drawing
GeoLocationRadius = 0.1

# local router
ROUTER_IP = "192.168.178.1"

# public IP
# can be found here:
# https://ifconfig.me/ip
# or here:
# https://www.whatismyip.com/
# if defined as empty (= "") then request..() will be used to determine it during execution.
PUBLIC_IP = ""

# colors
NODE_GOOD_COLOR = "green"
NODE_UNKNOWN_COLOR = "orange"
NODE_UNKNOWN_OLD_COLOR = "yellow"
NODE_BAD_COLOR = "red"
NODE_MY_DEVICE_COLOR = "purple"
NODE_ROUTER_COLOR = "yellow"
NODE_DEFAULT_COLOR = "blue"
NODE_KILLED_COLOR = "pink"
CON_GOOD_COLOR = "cornflowerblue"
CON_UNKNOWN_COLOR = "orange"
CON_BAD_COLOR = "red"
CON_DEFAULT_COLOR = "blue"
CON_KILLED_COLOR = "black"

# host locations
# needed because otherwise we see e.g. Frankfurt
MY_CITY = "Dallas"
MY_COUNTRY = "US"
MY_IP_ADDRESS = ROUTER_IP # will be replaced by resolved "public" IP
MY_LATITUDE = 32.8
MY_LONGITUDE = -96.9
MY_REGION = "Texas"

# map settings
# center in Dallas
MAP_CENTER_LAT = 32.8
MAP_CENTER_LON = -96.9
MAP_INFO_LAT = 30.0
MAP_INFO_LON = -50.0
# zoom enough to see the whole world in full-screen
MAP_ZOOM = 3

# features
BOUNCE = True
HEATMAP = False # TODO: rename to SHOW_HEATMAP
HEATMAP_SRC = True
HEATMAP_DST = True
# switch between map backgrounds
# default map types: roadmap, satellite, hybrid and terrain
SATELLITE = 0
ROADMAP = 1
HYBRID = 2
TERRAIN = 3
currentmaptype = ROADMAP
mapTypeNames = ["SATELLITE", "ROADMAP", "HYBRID", "TERRAIN" ]
# Show
SHOW_NODES = True
SHOW_CONNECTIONS = True
SHOW_CONNECTIONS_ACTIVE = True
SHOW_INFO = True
SHOW_HOST_GOOD = True
SHOW_HOST_UNKNOWN = True
SHOW_HOST_BAD = True
SHOW_HOST_KILLED = True
SHOW_HOST_ACTIVE = True
SHOW_HOST_PING = True
SHOW_CONNECTION_GOOD = True
SHOW_CONNECTION_UNKNOWN = True
SHOW_CONNECTION_BAD = True
SHOW_CONNECTION_KILLED = True
PLOT = True
#############################
# BUG: due to a Windows-BUG, playing sounds with playsound() causes a dramatic "memory leak",
# reaching Gigabytes of memory in a matter of hours!
# I think this is related to the problem with audiodg.exe
# (old drivers from 2011 and new services from Win10 from 2019 cannot be changed)
# People with newer PCs will probably have no memory leak, but just in case we set SOUND to False per default.
#############################
SOUND = False # True

# use white list or black list (exclusive alternatives!)
USE_WHITE_LIST = True # if False then we'll use the Blacklist

# Black List
# see: https://dev.maxmind.com/geoip/legacy/codes/iso3166/
BlackList = { # it's in fact a dictionary
"A1":"Anonymous Proxy", 
"A2":"Satellite Provider", 
"O1":"Other Country", 
"AF":"Afghanistan",
"SY":"Syrian Arab Republic"
}

# EXCLUSIVE White List
# see: https://dev.maxmind.com/geoip/legacy/codes/iso3166/
WhiteList = { # it's in fact a dictionary
"BE":"Belgium", 
"CH":"Switzerland", 
"DE":"Germany", 
"GB":"United Kingdom", 
"HK":"Hong Kong",
"IE":"Ireland", 
"IT":"Italy",
"JP":"Japan",
"NL":"Netherlands", 
"NO":"Norway",
# "SE":"Sweden",
# "FI":"Finland",
"US":"United States"
}

# EXCLUSIVE White List for NOT killing
WhiteListNotKill = [
"svchost.exe",
"pythonw.exe",
"python.exe",
# "firefox.exe", 
# "usocoreworker.exe", # battery saver process windows?
# "taskhostw.exe", # host process windows BUT could be used by hackers?
"thunderbird.exe", 
"whosip.exe",
"Avira.VpnService.exe",
"Avira.ServiceHost.exe",
"MsMpEng.exe"
]

# Black List for BAD owner
# Rule: if BlackListOwner AND NOT WhiteListOwner
########################################
# WARNING: NOT IDENTIFIED owner names will be marked as BAD!
########################################
BlackListOwner = [
"CEDIA", # uni Ecuador (mirror for Linux servers)
"Hostway LLC",
"EDIS GmbH",
"EDIS Infrastructure",
"Hosting Services Inc. (dba Midphase)",
"INTERNET-GROUP-DATACENTER"
]

# NON-EXCLUSIVE White List for good owner
# Rule: if BlackListOwner AND NOT WhiteListOwner
###############################
WhiteListOwner = [
"Microsoft", # windows, office, ..
"Google", 
"Amazon",  
"ARIN",  # ARIN Operations to resolve host
"RiPE", # to resolve host
"LACNIC", # to resolve host (latinamerica)
"AfriNIC", # to resolve host (africa)
"Yahoo", 
"Facebook", 
"Mozilla",  # browser, Thunderbird
"Thunderbird", # ?
"Akamai", # nevertheless strange connections with this owner (?)
"Avira", 
"Cloudflare"
]

# Black List for BAD city
###############################
BlackListCity = [
"Montreal (Ville-Marie)",
"Damascus"
]

# NON-EXCLUSIVE White List for good city
###############################
WhiteListCity = [
"Centreville", # ARIN in US - white-listed double by country and by city
"San Francisco",
# "Seattle", # Amazon  
"Los Angeles"
]

# start time:
START_TIME = "YYYY_mm_dd_HH_MM_SS"











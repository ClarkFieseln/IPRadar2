# imports
from dataclasses import dataclass

################
@dataclass
class NodeDataClass:
    pos: int
    ip: str
    mac: str
    lat: float
    lon: float
    lat_plot: float
    lon_plot: float
    position: int # position in "circle" with center lat, lon
    country_iso: str
    country_str: str
    region: str
    city: str
    host: str
    show_host: bool
    whosip: str # delimiters: WHOSIP_START, WHOSIP_END
    host_resolved: bool
    ping: bool
    bad: bool
    killed: bool
    killed_process: str
    local: bool # local Network? incl. broadcast and multicast
    conn_established: bool
    tx: int
    rx: int 
    date: str
    time: str
    comm_partner_list: list
    comm_partner_list_killed: list
    
##################
@dataclass
class DbIpCityResponse:
    city: str
    country: str
    ip_address: str
    latitude: float
    longitude: float
    region: str









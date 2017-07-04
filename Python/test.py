from scapy.all import *
from scapy.layer,dot11 import *

import sys

interface = "wlan0" 
ssid_list = []
count = 0
def sniffer(p):

    if Dot11Elt in p:
	if p.getlayer(Dot11Elt)[0].info not in ssid_list:
	    print p.getlayer(Dot11Elt)[0].info
            ssid_list.append(p.info)
sniff(iface=interface, prn=sniffer) 

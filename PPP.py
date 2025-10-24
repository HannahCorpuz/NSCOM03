
#import scapy
from scapy.all import *

import sys
import time
from socket import *
import struct

#Ping made via PPPoE

print("Hello World!")

src_mac = scapy.layers.l2.Ether().src

print(src_mac)
def ppp_create(destination):
    try:
        trueip = gethostbyname(destination)
        dst_mac = scapy.layers.l2.getmacbyip(trueip)
        print(dst_mac)
        if dst_mac is None:
            print("MAC address not found for this IP")
            return
        pppPacket = Ether(dst=dst_mac, src=src_mac) / PPPoED(sessionid=0x1234, code="") / PPP(proto=0x0021) / IP(trueip) / ICMP()
        print(sys.path)
    except Exception as e:
        print("PPP packet creation Failed: ", e)
        return
    
destination = input("Enter IP to send packets: ")
ppp_create(destination)
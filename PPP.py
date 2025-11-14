from scapy.all import *
import time

def pktcb(pkt):
    print("SNIFF:", pkt.summary())

print("Sniffing on ppp0 for 10 packets ...")
sniffer = AsyncSniffer(iface="ppp0", prn=pktcb)
sniffer.start()

# List of 10 different packets to send
packets = [
    IP(dst="10.0.0.2")/ICMP()/b"icmp-test",
    IP(dst="10.0.0.2")/TCP(dport=80)/b"http-test",
    IP(dst="10.0.0.2")/UDP(dport=53)/b"dns-query",
    IP(dst="10.0.0.2")/TCP(dport=22)/b"ssh-test",
    IP(dst="10.0.0.2")/UDP(dport=69)/b"tftp-test",
    IP(dst="10.0.0.2")/TCP(dport=25)/b"smtp-test",
    IP(dst="10.0.0.2")/UDP(dport=123)/b"ntp-test",
    IP(dst="10.0.0.2")/TCP(dport=110)/b"pop3-test",
    IP(dst="10.0.0.2")/UDP(dport=161)/b"snmp-test",
    IP(dst="10.0.0.2")/TCP(dport=443)/b"https-test"
]

for i, pkt in enumerate(packets, start=1):
    send(pkt, iface="ppp0")
    print(f"Sent packet #{i}: {pkt.summary()}")
    time.sleep(1)

print("Done.")

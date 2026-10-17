from scapy.all import sniff

def inspect_packet(pkt):
    print(pkt.summary())

sniff(iface="wlan0", prn=inspect_packet, count=5, filter="tcp port 80")

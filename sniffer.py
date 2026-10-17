import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

INTERFACE = "wlan0"
LOG_FILE = "sniffer_log.txt"

packet_count = 0

def process_packet(packet):
    global packet_count

    if IP not in packet:
        return

    packet_count += 1
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src = packet[IP].src
    dst = packet[IP].dst
    ttl = packet[IP].ttl

    print(f"\n{'='*70}")
    print(f"Packet #{packet_count} | {timestamp}")
    print(f"{'='*70}")
    print(f"[IP]     {src} -> {dst}   (TTL={ttl})")

    if TCP in packet:
        sport, dport = packet[TCP].sport, packet[TCP].dport
        flags = str(packet[TCP].flags)
        proto = "TCP"
        print(f"[TCP]    {src}:{sport} -> {dst}:{dport}   flags={flags}")

    elif UDP in packet:
        sport, dport = packet[UDP].sport, packet[UDP].dport
        proto = "UDP"
        print(f"[UDP]    {src}:{sport} -> {dst}:{dport}")

    elif ICMP in packet:
        proto = "ICMP"
        print(f"[ICMP]   type={packet[ICMP].type} code={packet[ICMP].code}")

    else:
        proto = f"OTHER({packet[IP].proto})"
        print(f"[{proto}] no transport-layer breakdown available")

    if Raw in packet:
        payload = packet[Raw].load
        try:
            text = payload.decode("utf-8", errors="replace")
        except Exception:
            text = repr(payload)
        print(f"[PAYLOAD] {len(payload)} bytes")
        print(f"          {text[:150]}")
    else:
        print(f"[PAYLOAD] none (header-only packet)")

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {proto} {src} -> {dst} len={len(packet)}\n")


print(f"Sniffing on {INTERFACE}... press Ctrl+C to stop\n")
try:
    sniff(iface=INTERFACE, prn=process_packet, store=False, filter="tcp port 443")
except KeyboardInterrupt:
    print(f"\nStopped. Captured {packet_count} packets. Log saved to {LOG_FILE}")

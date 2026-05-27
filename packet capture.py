from scapy.all import sniff, IP, IPv6, TCP, UDP, Raw, DNS, DNSQR
import datetime
import geoip2.database
import ipaddress
import os
import math
from collections import Counter
from math import radians, sin, cos, asin, sqrt
import csv

def log(src, timeStamp, long, lat):
    write_header = not os.path.exists("logs.txt") or os.path.getsize("logs.txt") == 0
    with open("logs.txt", "a") as file:
        if write_header:
            file.write("timestamp,source_ip,latitude,longitude\n")
        file.write(f"{timeStamp.strftime('%Y-%m-%dT%H:%M:%SZ')},{src},{lat},{long}\n")

def tcp_packet(pkt, timeStamp):
    src, dst, sport, dport, flags = pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport, pkt[TCP].flags

    print("=======TCP Packet=========")
    
    print(f"Time: [{timeStamp.strftime('%H:%M:%S')}]")
    print(f"Source IP: {src}")
    print(f"Destination IP: {dst}")
    print(f"Source Port: {sport}")
    print(f"Destination Port: {dport}")
    private_ip_address = ipaddress.ip_address(src)
    if not private_ip_address.is_private:     
        with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
            response = reader.city(src)
            print(f"Country:  + {response.country.name}")
            print(f"City:  + {response.city.name}")
            log(src, timeStamp, response.location.longitude, response.location.latitude)

    if Raw in pkt:
        payload = pkt[Raw].load[:50]  # First 50 bytes
        print("===Payload===")
        print(f"Payload: {payload}")

    
    print("==========================")

def udp_packet(pkt, timeStamp):
    src, dst, sport, dport = pkt[IP].src, pkt[IP].dst, pkt[UDP].sport, pkt[UDP].dport
    print("=======UDP Packet=========")
 #   print(f"[{timestamp}] UDP {src}:{sport} → {dst}:{dport}")
    print(f"Time: [{timeStamp.strftime('%H:%M:%S')}]")
    print(f"Source IP: {src}")
    print(f"Destination IP: {dst}")
    print(f"Source Port: {sport}")
    print(f"Destination Port: {dport}")
    private_ip_address = ipaddress.ip_address(src)
    if not private_ip_address.is_private:     
        with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
            response = reader.city(src)
            print(f"Country and City of the ip address: {src}")
            print(f"Country:  + {response.country.name}")
            print(f"City:  + {response.city.name}")
    
    if Raw in pkt:
            payload = pkt[Raw].load[:50]  # First 50 bytes
            print(f"Payload: {payload}")
    
    print("==========================")

def analyze_packet(pkt):
    timeStamp = datetime.datetime.now()#.strftime("%H:%M:%S")

    if IP in pkt:
 
        if TCP in pkt:
            tcp_packet(pkt, timeStamp)

        elif UDP in pkt:
            udp_packet(pkt, timeStamp)

def shannon_entropy(domain):
    name = domain.split('.')[0]
    if not name:
        return 0.0
    counts = Counter(name)
    length = len(name)
    return -sum((c/length) * math.log2(c/length) for c in counts.values())

# To check for specific domains open a new terminal while running packet capture.py and enter "nslookup" + domain name
def dns_packet(pkt, timeStamp):
    if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
        domain = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
        # skip reverse DNS lookups
        if domain.endswith('.arpa'):
            return
        src = pkt[IP].src if pkt.haslayer(IP) else pkt[IPv6].src

        entropy = shannon_entropy(domain)
        length = len(domain)

        # anomaly score
        score = 0.0
        if entropy > 3.2:
            score += 0.4
        if length > 40:
            score += 0.3
        digit_ratio = sum(c.isdigit() for c in domain) / max(len(domain), 1)
        if digit_ratio > 0.3:
            score += 0.3

        print("=======DNS Query=========")
        print(f"Time: [{timeStamp.strftime('%H:%M:%S')}]")
        print(f"Source IP: {src}")
        print(f"Domain: {domain}")
        print(f"Entropy: {entropy:.2f}  Length: {length}  Score: {score:.2f}")
        if score >= 0.4:
            print(f"⚠️  SUSPICIOUS DOMAIN (score {score:.2f})")
        print("==========================")

        # log it for later analysis
        flag = "SUSPICIOUS" if score >= 0.4 else "OK"
        with open("dns_logs.txt", "a") as f:
            f.write(f"{timeStamp.strftime('%Y-%m-%dT%H:%M:%SZ')},{src},{domain},"
                    f"{entropy:.3f},{length},{score:.2f},{flag}\n")
            


def analyze_packet(pkt):
    timeStamp = datetime.datetime.now()
    if pkt.haslayer(DNS):          # check DNS first, regardless of IP version
        dns_packet(pkt, timeStamp)
    elif IP in pkt:
        if TCP in pkt:
            tcp_packet(pkt, timeStamp)
        elif UDP in pkt:
            udp_packet(pkt, timeStamp)

sniff(iface="Ethernet", prn=analyze_packet, store=False)
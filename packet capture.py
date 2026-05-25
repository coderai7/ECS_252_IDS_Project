from scapy.all import sniff, IP, TCP, UDP, Raw
import datetime
import geoip2.database
import ipaddress
import socket

def log(src, timeStamp, long, lat, domain):

   # now = datetime.now

    with open("logs.txt", "a") as file:
        file.write(f"IP: {src}\n")
        file.write(f"Longitude: {long}\n")
        file.write(f"Latitude: {lat}\n")
        file.write(f"{timeStamp.strftime("%Y-%m-%dT%H:%M:%SZ")}\n")
        file.write(f"Domain: {domain}\n")
        file.write("\n")

def tcp_packet(pkt, timeStamp):
    src, dst, sport, dport, flags = pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport, pkt[TCP].flags

    print("=======TCP Packet=========")
    
    print(f"Time: [{timeStamp.strftime("%H:%M:%S")}]")
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
            try:
                domain = socket.gethostbyaddr(src)
            except socket.herror:
                domain = "example.com"
            log(src, timeStamp, response.location.longitude, response.location.latitude, domain)

    if Raw in pkt:
        payload = pkt[Raw].load[:50]  # First 50 bytes
        print("===Payload===")
        print(f"Payload: {payload}")

    
    print("==========================")

def udp_packet(pkt, timeStamp):
    src, dst, sport, dport = pkt[IP].src, pkt[IP].dst, pkt[UDP].sport, pkt[UDP].dport
    print("=======UDP Packet=========")
 #   print(f"[{timestamp}] UDP {src}:{sport} → {dst}:{dport}")
    print(f"Time: [{timeStamp.strftime("%H:%M:%S")}]")
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


# Sniff on a specific interface indefinitely
sniff(iface="Ethernet", prn=analyze_packet, store=False)
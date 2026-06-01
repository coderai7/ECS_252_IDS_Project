from scapy.all import IP, UDP, DNS, DNSQR, send
import time

TARGET_DNS = "8.8.8.8"

test_cases = [

    ("xk3f9p2mzqwvr7t8n1jc.com",                          "High entropy - should flag SUSPICIOUS"),
    ("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0.evil.com", "Long + high digits - should flag SUSPICIOUS"),
    ("x9k2p7m4q1w8v3t6n5jc0z.data.io",                    "High entropy + digits - should flag SUSPICIOUS"),
    ("google.com",                                          "Normal domain - should be OK"),
    ("github.com",                                          "Normal domain - should be OK"),
    ("microsoft.com",                                       "Normal domain - should be OK"),
]

def send_dns_query(domain, description):
    print(f"\n[*] Sending: {domain}")
    print(f"    Test:     {description}")

    pkt = (
        IP(dst=TARGET_DNS) /
        UDP(dport=53) /
        DNS(rd=1, qd=DNSQR(qname=domain))
    )

    send(pkt, verbose=False)
    time.sleep(0.5)  

if __name__ == "__main__":
    print("=== DNS Packet Test Script ===")
    print(f"Sending queries to {TARGET_DNS}\n")

    for domain, description in test_cases:
        send_dns_query(domain, description)

    print("\n[✓] All test packets sent. Check your sniffer output and dns_logs.txt.")
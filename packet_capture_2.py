from scapy.all import sniff, IP, IPv6, TCP, UDP, Raw, DNS, DNSQR
import datetime
import geoip2.database
import ipaddress
import os
import math
import socket
import re
from collections import Counter
from math import radians, sin, cos, asin, sqrt
import csv

# ---------------------------------------------------------------------------
# TLD → expected ISO country codes (expand as needed)
# ---------------------------------------------------------------------------
TLD_COUNTRY_MAP = {
    "jp": ["JP"], "uk": ["GB"], "co.uk": ["GB"], "de": ["DE"],
    "fr": ["FR"], "cn": ["CN"], "ru": ["RU"], "au": ["AU"],
    "ca": ["CA"], "br": ["BR"], "in": ["IN"], "kr": ["KR"],
    "it": ["IT"], "es": ["ES"], "nl": ["NL"], "se": ["SE"],
    "no": ["NO"], "fi": ["FI"], "pl": ["PL"], "ch": ["CH"],
    "nz": ["NZ"], "za": ["ZA"], "mx": ["MX"], "sg": ["SG"],
    "hk": ["HK"], "tw": ["TW"], "be": ["BE"], "at": ["AT"],
    "pt": ["PT"], "cz": ["CZ"], "hu": ["HU"], "ro": ["RO"],
    "gr": ["GR"], "ua": ["UA"], "tr": ["TR"], "ar": ["AR"],
    "cl": ["CL"], "eg": ["EG"], "il": ["IL"], "ae": ["AE"],
    "sa": ["SA"], "th": ["TH"], "vn": ["VN"], "id": ["ID"],
    "my": ["MY"], "ph": ["PH"], "pk": ["PK"], "bd": ["BD"],
    "ng": ["NG"], "ke": ["KE"], "gh": ["GH"], "tz": ["TZ"],
}

# Regions implied by AWS/GCP/Azure hostname keywords → ISO codes
CLOUD_REGION_MAP = {
    "ap-northeast-1": ["JP"],          # Tokyo
    "ap-northeast-2": ["KR"],          # Seoul
    "ap-northeast-3": ["JP"],          # Osaka
    "ap-southeast-1": ["SG"],          # Singapore
    "ap-southeast-2": ["AU"],          # Sydney
    "ap-south-1":     ["IN"],          # Mumbai
    "eu-west-1":      ["IE"],          # Ireland
    "eu-west-2":      ["GB"],          # London
    "eu-west-3":      ["FR"],          # Paris
    "eu-central-1":   ["DE"],          # Frankfurt
    "eu-north-1":     ["SE"],          # Stockholm
    "us-east-1":      ["US"],
    "us-east-2":      ["US"],
    "us-west-1":      ["US"],
    "us-west-2":      ["US"],
    "sa-east-1":      ["BR"],          # São Paulo
    "ca-central-1":   ["CA"],
    "me-south-1":     ["BH"],          # Bahrain
    "af-south-1":     ["ZA"],          # Cape Town
    # GCP
    "northamerica-northeast1": ["CA"],
    "southamerica-east1":      ["BR"],
    "europe-west1":            ["BE"],
    "europe-west2":            ["GB"],
    "europe-west3":            ["DE"],
    "europe-west4":            ["NL"],
    "asia-east1":              ["TW"],
    "asia-northeast1":         ["JP"],
    "asia-northeast3":         ["KR"],
    "asia-south1":             ["IN"],
    "asia-southeast1":         ["SG"],
    "australia-southeast1":    ["AU"],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log(src, timeStamp, long, lat):
    write_header = not os.path.exists("logs.txt") or os.path.getsize("logs.txt") == 0
    with open("logs.txt", "a") as file:
        if write_header:
            file.write("timestamp,source_ip,latitude,longitude\n")
        file.write(f"{timeStamp.strftime('%Y-%m-%dT%H:%M:%SZ')},{src},{lat},{long}\n")


def log_geo_mismatch(timeStamp, ip, hostname, tld_or_region,
                     expected_countries, actual_country, reason):
    write_header = (
        not os.path.exists("geo_mismatch.txt")
        or os.path.getsize("geo_mismatch.txt") == 0
    )
    with open("geo_mismatch.txt", "a") as f:
        if write_header:
            f.write("timestamp,ip,hostname,tld_or_region,"
                    "expected_countries,actual_country,reason\n")
        f.write(
            f"{timeStamp.strftime('%Y-%m-%dT%H:%M:%SZ')},{ip},{hostname},"
            f"{tld_or_region},{'/'.join(expected_countries)},"
            f"{actual_country},{reason}\n"
        )


def get_tld_expected_countries(domain: str):
    """
    Return (tld_key, [expected ISO codes]) for the domain's ccTLD,
    or (None, []) if it's a generic TLD (com/net/org/…).
    Handles second-level ccTLDs like co.uk.
    """
    parts = domain.lower().rstrip('.').split('.')
    # Check second-level + TLD first (e.g. co.uk)
    if len(parts) >= 2:
        two = '.'.join(parts[-2:])
        if two in TLD_COUNTRY_MAP:
            return two, TLD_COUNTRY_MAP[two]
    # Single TLD
    if parts:
        one = parts[-1]
        if one in TLD_COUNTRY_MAP:
            return one, TLD_COUNTRY_MAP[one]
    return None, []


def get_cloud_region_expected_countries(hostname: str):
    """
    Scan the hostname for known cloud region strings and return
    (region_key, [expected ISO codes]), or (None, []).
    """
    lower = hostname.lower()
    for region, countries in CLOUD_REGION_MAP.items():
        if region in lower:
            return region, countries
    return None, []


def reverse_dns(ip: str) -> str | None:
    """Return PTR hostname for ip, or None on failure."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def forward_resolve(hostname: str) -> list[str]:
    """Return list of IPs for hostname (A/AAAA), empty list on failure."""
    try:
        infos = socket.getaddrinfo(hostname, None)
        return list({info[4][0] for info in infos})
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Core cross-reference: Hostname ↔ Geo Consistency
# ---------------------------------------------------------------------------

def check_hostname_geo_consistency(ip: str, timeStamp, source: str = "TCP/UDP"):
    """
    1. Reverse-resolve ip → PTR hostname
    2. Extract TLD or cloud-region expected countries from that hostname
    3. Compare against GeoIP2 country for ip
    4. Report mismatch if any

    Returns a dict with the findings (for use in callers).
    """
    result = {
        "ip": ip,
        "hostname": None,
        "geo_country": None,
        "geo_country_iso": None,
        "expected_countries": [],
        "tld_or_region": None,
        "mismatch": False,
        "mismatch_reason": None,
    }

    # --- Step 1: reverse DNS ---
    hostname = reverse_dns(ip)
    result["hostname"] = hostname

    # --- Step 2: GeoIP2 lookup ---
    try:
        with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
            geo = reader.city(ip)
            result["geo_country"] = geo.country.name
            result["geo_country_iso"] = geo.country.iso_code
    except Exception:
        return result  # can't do comparison without geo data

    if hostname is None:
        # No PTR record — note it but can't compare
        result["mismatch_reason"] = "NO_PTR_RECORD"
        return result

    # --- Step 3: TLD check ---
    tld_key, tld_expected = get_tld_expected_countries(hostname)
    # --- Step 4: Cloud region check ---
    region_key, region_expected = get_cloud_region_expected_countries(hostname)

    if tld_expected:
        result["tld_or_region"] = tld_key
        result["expected_countries"] = tld_expected
        if result["geo_country_iso"] not in tld_expected:
            result["mismatch"] = True
            result["mismatch_reason"] = (
                f"TLD '.{tld_key}' implies {tld_expected} "
                f"but GeoIP2 says {result['geo_country_iso']} ({result['geo_country']})"
            )
    elif region_expected:
        result["tld_or_region"] = region_key
        result["expected_countries"] = region_expected
        if result["geo_country_iso"] not in region_expected:
            result["mismatch"] = True
            result["mismatch_reason"] = (
                f"Cloud region '{region_key}' implies {region_expected} "
                f"but GeoIP2 says {result['geo_country_iso']} ({result['geo_country']})"
            )

    # --- Step 5: Forward-confirm the hostname resolves back to the same IP ---
    if hostname:
        fwd_ips = forward_resolve(hostname)
        if fwd_ips and ip not in fwd_ips:
            result["mismatch"] = True
            fwd_note = (
                f"PTR '{hostname}' forward-resolves to {fwd_ips}, not {ip} "
                f"(possible PTR spoofing / CDN edge)"
            )
            result["mismatch_reason"] = (
                (result["mismatch_reason"] + " | " + fwd_note)
                if result["mismatch_reason"]
                else fwd_note
            )

    # --- Step 6: Log and print mismatch ---
    if result["mismatch"]:
        print(f"  ⚠️  GEO MISMATCH [{source}]: {result['mismatch_reason']}")
        log_geo_mismatch(
            timeStamp, ip, hostname,
            result["tld_or_region"] or "n/a",
            result["expected_countries"],
            f"{result['geo_country_iso']} ({result['geo_country']})",
            result["mismatch_reason"],
        )

    return result


def print_geo_consistency_block(result: dict):
    """Pretty-print the consistency check results."""
    hostname = result["hostname"] or "(no PTR)"
    geo = (f"{result['geo_country_iso']} / {result['geo_country']}"
           if result["geo_country"] else "unknown")
    print(f"  PTR Hostname : {hostname}")
    print(f"  GeoIP Country: {geo}")
    if result["tld_or_region"]:
        print(f"  Expected ({result['tld_or_region']}): {result['expected_countries']}")
    if result["mismatch_reason"] and not result["mismatch"]:
        print(f"  ℹ️  Note: {result['mismatch_reason']}")


# ---------------------------------------------------------------------------
# Packet handlers
# ---------------------------------------------------------------------------

def tcp_packet(pkt, timeStamp):
    src  = pkt[IP].src
    dst  = pkt[IP].dst
    sport = pkt[TCP].sport
    dport = pkt[TCP].dport

    print("=======TCP Packet=========")
    print(f"Time: [{timeStamp.strftime('%H:%M:%S')}]")
    print(f"Source IP:        {src}")
    print(f"Destination IP:   {dst}")
    print(f"Source Port:      {sport}")
    print(f"Destination Port: {dport}")

    if not ipaddress.ip_address(src).is_private:
        with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
            response = reader.city(src)
            print(f"Country: {response.country.name}")
            print(f"City:    {response.city.name}")
            log(src, timeStamp, response.location.longitude, response.location.latitude)

        # --- Hostname ↔ Geo Consistency ---
        print("  --- Hostname ↔ Geo Consistency ---")
        result = check_hostname_geo_consistency(src, timeStamp, source="TCP")
        print_geo_consistency_block(result)

    if Raw in pkt:
        payload = pkt[Raw].load[:50]
        print("===Payload===")
        print(f"Payload: {payload}")

    print("==========================")


def udp_packet(pkt, timeStamp):
    src   = pkt[IP].src
    dst   = pkt[IP].dst
    sport = pkt[UDP].sport
    dport = pkt[UDP].dport

    print("=======UDP Packet=========")
    print(f"Time: [{timeStamp.strftime('%H:%M:%S')}]")
    print(f"Source IP:        {src}")
    print(f"Destination IP:   {dst}")
    print(f"Source Port:      {sport}")
    print(f"Destination Port: {dport}")

    if not ipaddress.ip_address(src).is_private:
        with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
            response = reader.city(src)
            print(f"Country: {response.country.name}")
            print(f"City:    {response.city.name}")

        # --- Hostname ↔ Geo Consistency ---
        print("  --- Hostname ↔ Geo Consistency ---")
        result = check_hostname_geo_consistency(src, timeStamp, source="UDP")
        print_geo_consistency_block(result)

    if Raw in pkt:
        payload = pkt[Raw].load[:50]
        print(f"Payload: {payload}")

    print("==========================")


def shannon_entropy(domain):
    name = domain.split('.')[0]
    if not name:
        return 0.0
    counts = Counter(name)
    length = len(name)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def dns_packet(pkt, timeStamp):
    if not (pkt.haslayer(DNSQR) and pkt[DNS].qr == 0):
        return

    domain = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
    if domain.endswith('.arpa'):
        return

    src = pkt[IP].src if pkt.haslayer(IP) else pkt[IPv6].src

    entropy    = shannon_entropy(domain)
    length     = len(domain)
    digit_ratio = sum(c.isdigit() for c in domain) / max(len(domain), 1)

    # --- DNS anomaly score ---
    score = 0.0
    if entropy > 3.2:
        score += 0.4
    if length > 40:
        score += 0.3
    if digit_ratio > 0.3:
        score += 0.3

    print("=======DNS Query=========")
    print(f"Time: [{timeStamp.strftime('%H:%M:%S')}]")
    print(f"Source IP: {src}")
    print(f"Domain:    {domain}")
    print(f"Entropy: {entropy:.2f}  Length: {length}  Score: {score:.2f}")
    if score >= 0.4:
        print(f"⚠️  SUSPICIOUS DOMAIN (score {score:.2f})")

    # --- Hostname ↔ Geo Consistency on the queried domain ---
    # Resolve the domain to IPs and check each public IP
    print("  --- Hostname ↔ Geo Consistency (DNS target) ---")
    resolved_ips = forward_resolve(domain)
    if resolved_ips:
        for rip in resolved_ips:
            try:
                if not ipaddress.ip_address(rip).is_private:
                    result = check_hostname_geo_consistency(rip, timeStamp, source="DNS")
                    print(f"  Resolved IP: {rip}")
                    print_geo_consistency_block(result)

                    # Extra signal: combine DNS score + geo mismatch
                    if result["mismatch"] and score >= 0.4:
                        print(f"  🚨 HIGH RISK: suspicious DNS score ({score:.2f})"
                              f" AND geo mismatch for '{domain}'")
            except ValueError:
                pass
    else:
        print("  (domain did not resolve)")

    print("==========================")

    flag = "SUSPICIOUS" if score >= 0.4 else "OK"
    with open("dns_logs.txt", "a") as f:
        f.write(
            f"{timeStamp.strftime('%Y-%m-%dT%H:%M:%SZ')},{src},{domain},"
            f"{entropy:.3f},{length},{score:.2f},{flag}\n"
        )


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def analyze_packet(pkt):
    timeStamp = datetime.datetime.now()
    if pkt.haslayer(DNS):
        dns_packet(pkt, timeStamp)
    elif IP in pkt:
        if TCP in pkt:
            tcp_packet(pkt, timeStamp)
        elif UDP in pkt:
            udp_packet(pkt, timeStamp)


sniff(iface="Ethernet", prn=analyze_packet, store=False)

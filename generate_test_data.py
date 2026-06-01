import os
from datetime import datetime, timedelta
import random
import csv

# clear logs so the test is clean
for f in ("logs.txt", "dns_logs.txt", "geo_mismatch.txt", "ground_truth.csv"):
    if os.path.exists(f): os.remove(f)

random.seed(42)
base_time = datetime(2026, 5, 28, 12, 0, 0)

# track ground truth
ground_truth = []

# helpers for writing entries
def write_geo(ts, ip, lat, lon):
    write_header = not os.path.exists("logs.txt") or os.path.getsize("logs.txt") == 0
    with open("logs.txt", "a") as f:
        if write_header: f.write("timestamp,source_ip,latitude,longitude\n")
        f.write(f"{ts.strftime('%Y-%m-%dT%H:%M:%SZ')},{ip},{lat},{lon}\n")

def write_dns(ts, ip, domain, score):
    flag = "SUSPICIOUS" if score >= 0.4 else "OK"
    with open("dns_logs.txt", "a") as f:
        f.write(f"{ts.strftime('%Y-%m-%dT%H:%M:%SZ')},{ip},{domain},"
                f"3.0,15,{score:.2f},{flag}\n")

def write_mismatch(ts, ip):
    write_header = not os.path.exists("geo_mismatch.txt") or os.path.getsize("geo_mismatch.txt") == 0
    with open("geo_mismatch.txt", "a") as f:
        if write_header:
            f.write("timestamp,ip,hostname,tld_or_region,expected_countries,actual_country,reason\n")
        f.write(f"{ts.strftime('%Y-%m-%dT%H:%M:%SZ')},{ip},fake.example.jp,jp,JP,US,test_mismatch\n")

# generate 90 benign entries
for i in range(90):
    ts = base_time + timedelta(seconds=i*5)
    ip = f"203.0.113.{i+1}"
    # most benign IPs have only one weak signal or none
    roll = random.random()
    if roll < 0.3:
        # benign with a low DNS score
        write_dns(ts, ip, "example.com", 0.0)
    elif roll < 0.5:
        # benign with a slightly weak signal
        write_dns(ts, ip, "ab12cd34.cdn.com", 0.4)
    elif roll < 0.7:
        # benign with a geo mismatch only
        write_mismatch(ts, ip)
    else:
        # benign with no anomalies at all
        write_geo(ts, ip, 37.0, -122.0)
    ground_truth.append((ip, ts.isoformat(), "benign"))

# generate 10 malicious entries wilt MULTIPLE alert signals 
mal_base = base_time + timedelta(minutes=10)
for i in range(10):
    ts = mal_base + timedelta(seconds=i*5)
    ip = f"198.51.100.{i+1}"    # documentation range, safely fake
    # malicious entries with 2 or 3 signals within the time window
    write_dns(ts, ip, f"x{random.randint(0,9999):04d}rqpwmnz.com", 0.7) # high DNS score
    write_mismatch(ts + timedelta(seconds=10), ip) # geo-mismatch
    if i < 5:
        # add a geo-velocity event for half of them
        write_geo(ts - timedelta(minutes=1), ip, 37.7749, -122.4194) # San Francisco
        write_geo(ts + timedelta(seconds=30), ip, 51.5074, -0.1278) # London (impossible travel, unless you have interdimensional tech :))
    ground_truth.append((ip, ts.isoformat(), "malicious"))

# save ground truth
with open("ground_truth.csv", "w") as f:
    f.write("ip,timestamp,label\n")
    for ip, ts, label in ground_truth:
        f.write(f"{ip},{ts},{label}\n")

print(f"Generated {len(ground_truth)} entries")
print(f"Ground truth saved to ground_truth.csv")
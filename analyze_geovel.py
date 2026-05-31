import csv
from datetime import datetime, timedelta
from collections import defaultdict
from math import radians, sin, cos, asin, sqrt

def haversine_km(lat1, lon1, lat2, lon2):
    R = 6371.0
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlat, dlon = lat2 - lat1, lon2 - lon1
    a = sin(dlat/2)**2 + cos(lat1)*cos(lat2)*sin(dlon/2)**2
    return 2 * R * asin(sqrt(a))

# Dictionary for scores per ip address
events = defaultdict(list)   # ip: [(timestamp, signal_name, value)]

# Compute geo-velocity from geo-location log
last_seen = {}
with open("logs.txt") as f:
    for row in csv.DictReader(f):
        try:
            ts = datetime.fromisoformat(row['timestamp'].replace('Z','+00:00'))
            ip = row['source_ip']
            lat, lon = float(row['latitude']), float(row['longitude'])
        except (ValueError, KeyError):
            continue
        if ip in last_seen:
            prev_ts, prev_lat, prev_lon = last_seen[ip]
            dist = haversine_km(prev_lat, prev_lon, lat, lon)
            hours = (ts - prev_ts).total_seconds() / 3600
            if hours > 0 and dist > 100:
                speed = dist / hours
                if speed > 1000:
                    events[ip].append((ts, "geovel", speed))
        last_seen[ip] = (ts, lat, lon)

# record suspicious domains from DNS log
with open("dns_logs.txt") as f:
    for line in f:
        parts = line.strip().split(',')
        if len(parts) < 6: continue
        try:
            ts = datetime.fromisoformat(parts[0].replace('Z','+00:00'))
            src, score = parts[1], float(parts[5])
        except ValueError:
            continue
        if score >= 0.4:
            events[src].append((ts, "dns", score))

# Record mismatch from geo-mismatch log, if there are any
try:
    with open("geo_mismatch.txt") as f:
        for row in csv.DictReader(f):
            try:
                ts = datetime.fromisoformat(row['timestamp'].replace('Z','+00:00'))
                events[row['ip']].append((ts, "geo_mismatch", 1.0))
            except (ValueError, KeyError):
                continue
except FileNotFoundError:
    pass

# Correlate signals per IP within a time window
WINDOW_SECONDS = 60
THRESHOLD = 0.5

def correlation_score(signals):
    weights = {"dns": 0.4, "geo_mismatch": 0.3, "geovel": 0.3}
    score = 0.0
    for sig_name, val in signals.items():
        if sig_name == "dns":
            score += weights["dns"] * val
        elif sig_name == "geo_mismatch":
            score += weights["geo_mismatch"] * 1.0
        elif sig_name == "geovel":
            score += weights["geovel"] * (1.0 if val > 5000 else 0.6)
    return round(score, 2)

alerts = 0
for ip, ev_list in events.items():
    ev_list.sort()
    for i, (ts, sig, val) in enumerate(ev_list):
        nearby = {sig: val}
        for ts2, sig2, val2 in ev_list[i+1:]:
            if (ts2 - ts).total_seconds() > WINDOW_SECONDS:
                break
            nearby[sig2] = val2
        if len(nearby) >= 2:    # at least 2 different signals agree, change if you want more or less
            corr = correlation_score(nearby)
            if corr >= THRESHOLD:
                print(f"🚨 {ip} at {ts.isoformat()} | signals: {nearby} | score: {corr:.2f}")
                alerts += 1
                break

print(f"\nTotal correlated alerts: {alerts}")
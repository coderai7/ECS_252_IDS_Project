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

# Load ground truth labels
truth = {}
with open("ground_truth.csv") as f:
    for row in csv.DictReader(f):
        truth[row['ip']] = row['label']

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

# Correlation function
window_seconds = 60
threshold = 0.5

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

# Compare a set of alerted IPs against ground truth
def evaluate(alerted_ips, config_name):
    tp = sum(1 for ip in alerted_ips if truth.get(ip) == "malicious")
    fp = sum(1 for ip in alerted_ips if truth.get(ip) == "benign")
    fn = sum(1 for ip, lbl in truth.items() if lbl == "malicious" and ip not in alerted_ips)
    tn = sum(1 for ip, lbl in truth.items() if lbl == "benign" and ip not in alerted_ips)
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall    = tp / (tp + fn) if (tp + fn) else 0
    fpr       = fp / (fp + tn) if (fp + tn) else 0
    print(f"{config_name:<35} TP={tp:3d} FP={fp:3d} FN={fn:3d} TN={tn:3d} "
          f"Precision={precision:.1%} Recall={recall:.1%} FPR={fpr:.1%}")

# Run different configurations

# DNS alone
dns_alerts = {ip for ip, evs in events.items() if any(s == "dns" for _, s, _ in evs)}
evaluate(dns_alerts, "DNS only")

# Geo mismatch alone
geo_alerts = {ip for ip, evs in events.items() if any(s == "geo_mismatch" for _, s, _ in evs)}
evaluate(geo_alerts, "Geo mismatch only")

# Geo-velocity alone
geovel_alerts = {ip for ip, evs in events.items() if any(s == "geovel" for _, s, _ in evs)}
evaluate(geovel_alerts, "Geo-velocity only")

# Any signal fires
any_alerts = set(events.keys())
evaluate(any_alerts, "Any single signal (OR)")

# Correlated (>= 2 signals, score >= threshold)
corr_alerts = set()
for ip, ev_list in events.items():
    ev_list.sort()
    for i, (ts, sig, val) in enumerate(ev_list):
        nearby = {sig: val}
        for ts2, sig2, val2 in ev_list[i+1:]:
            if (ts2 - ts).total_seconds() > window_seconds:
                break
            nearby[sig2] = val2
        if len(nearby) >= 2 and correlation_score(nearby) >= threshold:
            corr_alerts.add(ip)
            break
evaluate(corr_alerts, f"Correlated (>=2 signals, thr={threshold})")
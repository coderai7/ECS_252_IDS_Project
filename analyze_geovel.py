import csv
from math import radians, sin, cos, asin, sqrt
from datetime import datetime

def haversine_km(lat1, lon1, lat2, lon2):
    R = 6371.0
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlat, dlon = lat2 - lat1, lon2 - lon1
    a = sin(dlat/2)**2 + cos(lat1)*cos(lat2)*sin(dlon/2)**2
    return 2 * R * asin(sqrt(a))

last_seen = {}
MAX_KMH = 1000

with open("logs.txt") as f:
    reader = csv.DictReader(f)
    for row in reader:
        ip = row['source_ip']
        ts = datetime.fromisoformat(row['timestamp'].replace('Z', '+00:00'))
        lat, lon = float(row['latitude']), float(row['longitude'])
        if ip in last_seen:
            prev_ts, prev_lat, prev_lon = last_seen[ip]
            dist = haversine_km(prev_lat, prev_lon, lat, lon)
            hours = (ts - prev_ts).total_seconds() / 3600
            if hours > 0 and dist > 100:
                speed = dist / hours
                if speed > MAX_KMH:
                    print(f"🚨 {ip}: {dist:.0f} km in {hours:.3f} h = {speed:.0f} km/h")
        last_seen[ip] = (ts, lat, lon)

print("Analysis complete.")
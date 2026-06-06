# Multi-Signal IDS for Reducing False Positives

A network intrusion detection system that combines three detection methods through a correlation layer to reduce false positives compared to single-signal approaches.

## Overview

Most IDSs raise too many false alarms, so defenders ignore alerts and miss real threats. This project tests whether combining IP geolocation, DNS anomaly scoring, and IP geo-velocity through correlation produces fewer false alarms than any single method, without sacrificing detection.

## How it works

**Capture** — sniffs packets using Scapy.

**Three independent detectors:**
- **IP geolocation** — flags hostnames whose country doesn't match the GeoIP database
- **DNS anomaly scoring** — measures randomness of queried domain names (Shannon entropy, length, digit ratio)
- **IP geo-velocity** — compares an IP's location across time and flags impossible travel using the Haversine formula

**Correlation layer** — groups signals by source IP, checks whether multiple fired within a 60-second window, and raises an alert only when at least two agree and the weighted score (DNS 0.4, geo 0.3, geo-velocity 0.3) exceeds 0.5.

## Requirements

- Scapy, geoip2 (`pip install scapy geoip2`)
- MaxMind GeoLite2 City database (`GeoLite2-City.mmdb` in project root)

## Usage

```bash
# 1. Capture traffic (run as admin/root, Ctrl+C to stop)
python "packet_capture.py"

# 2. Run correlation analysis on the logs
python analyze_geovel.py
```

The sniffer writes `logs.txt`, `dns_logs.txt`, and `geo_mismatch.txt`. The analysis script reads them and reports correlated alerts.

## Authors

Alfredo Ortiz (aoortiz@ucdavis.edu), Simon Zheng (sdzheng@ucdavis.edu) — UC Davis ECS 252, Spring 2026

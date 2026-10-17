from collections import defaultdict

def detect_brute_force(events, threshold=5):
    ip_counter = defaultdict(int)
    alerts = []
    for event in events:
        if event.get("event_type") == "Failed Login":
            ip = event.get("source_ip", "-")
            ip_counter[ip] += 1
            if ip_counter[ip] >= threshold:
                alerts.append({
                    "alert_type": "Brute Force Attack",
                    "severity": "Critical",
                    "source_ip": ip,
                    "count": ip_counter[ip],
                    "title": f"Brute force from {ip}",
                    "description": f"{ip_counter[ip]} failed login attempts detected from {ip}."
                })
    return alerts
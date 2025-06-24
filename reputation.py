import requests
import ipaddress

VT_API_KEY = "YOUR API KEY"
ABUSE_API_KEY = "YOUR API KEY"

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private or ip in {"127.0.0.1", "0.0.0.0"}
    except:
        return False

def check_ip_reputation(ip):
    if is_private_ip(ip):
        return "Local"

    vt_result = check_virustotal(ip)

    if vt_result == "Malicious":
        abuse_result = check_abuseipdb(ip)
        if abuse_result in ("Malicious", "Suspicious"):
            return "Malicious"
        return "Malicious"

    elif vt_result == "Suspicious":
        abuse_result = check_abuseipdb(ip)
        if abuse_result == "Malicious":
            return "Malicious"
        elif abuse_result == "Suspicious":
            return "Suspicious"
        return "Suspicious"

    elif vt_result == "Clean":
        return "Clean"

    return "unknown"

def check_virustotal(ip):
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VT_API_KEY}
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            return "unknown"

        data = resp.json()
        attr = data.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        reputation = attr.get("reputation", 0)
        categories = attr.get("categories", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        # Logika deteksi
        if malicious >= 1:
            return "Malicious"
        if suspicious >= 1:
            return "Suspicious"
        if reputation < -20:
            return "Suspicious"
        if any("malware" in v.lower() or "phishing" in v.lower() for v in categories.values()):
            return "Suspicious"

        return "Clean"

    except Exception:
        return "unknown"

def check_abuseipdb(ip):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Accept": "application/json",
            "Key": ABUSE_API_KEY
        }
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        resp = requests.get(url, headers=headers, params=params)
        if resp.status_code != 200:
            return "unknown"

        data = resp.json()["data"]
        score = data["abuseConfidenceScore"]

        if score > 80:
            return "malicious"
        elif score > 30:
            return "suspicious"
        else:
            return "clean"

    except Exception:
        return "unknown"

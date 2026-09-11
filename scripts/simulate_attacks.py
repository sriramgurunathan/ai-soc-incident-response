"""
ApexShield Threat Simulation CLI (Python)
Simulates:
1. Normal Employee Login Friction (3-4 attempts over time -> success)
2. Malware / Automated Brute Force Burst (7 attempts in <2 seconds)
3. SQL Injection Exploit
4. Cross-Site Scripting (XSS)
5. Port Scanning Reconnaissance
"""
import time
import requests
import argparse

BASE_URL = "http://127.0.0.1:8000"

def run_human_friction(username="john.doe"):
    print(f"[*] Simulating Normal Human Login Friction for user '{username}'...")
    url = f"{BASE_URL}/api/v1/simulate/human-login-friction?target_user={username}"
    resp = requests.post(url)
    print(f"Status Code: {resp.status_code}")
    print(resp.json())

def run_malware_burst(username="john.doe"):
    print(f"[*] Simulating High-Velocity Malware Brute Force on '{username}'...")
    url = f"{BASE_URL}/api/v1/simulate/malware-brute-force?target_user={username}"
    resp = requests.post(url)
    print(f"Status Code: {resp.status_code}")
    data = resp.json()
    print(f"[!] Threat Generated: {data.get('classification')}")
    print(f"[!] Incident Number: {data.get('incident_number')}")
    print(f"[!] MITRE Technique: {data.get('mitre_technique')}")

def run_sqli():
    print("[*] Simulating SQL Injection exploit probe...")
    url = f"{BASE_URL}/api/v1/simulate/sqli"
    resp = requests.post(url)
    print(resp.json())

def run_xss():
    print("[*] Simulating Cross-Site Scripting (XSS) probe...")
    url = f"{BASE_URL}/api/v1/simulate/xss"
    resp = requests.post(url)
    print(resp.json())

def run_port_scan():
    print("[*] Simulating Network Port Scan reconnaissance...")
    url = f"{BASE_URL}/api/v1/simulate/port-scan"
    resp = requests.post(url)
    print(resp.json())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ApexShield SOC Threat Simulation Tool")
    parser.add_argument("--attack", choices=["friction", "burst", "sqli", "xss", "portscan", "all"], default="all")
    parser.add_argument("--user", default="john.doe")
    args = parser.parse_args()

    if args.attack in ["friction", "all"]:
        run_human_friction(args.user)
        time.sleep(1)
    if args.attack in ["burst", "all"]:
        run_malware_burst(args.user)
        time.sleep(1)
    if args.attack in ["sqli", "all"]:
        run_sqli()
        time.sleep(1)
    if args.attack in ["xss", "all"]:
        run_xss()
        time.sleep(1)
    if args.attack in ["portscan", "all"]:
        run_port_scan()

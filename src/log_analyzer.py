import json
import re

# File paths
log_file_path = 'data/sample_logs_batch2.txt'
output_file_path = 'data/simulated_output.json'

# Extract port number from log
def extract_port(log_entry):
    match = re.search(r'dpt=(\d+)', log_entry.lower())
    return int(match.group(1)) if match else None

# Rule-based threat analyzer
def analyze_log(log_entry):
    entry = log_entry.lower()
    port = extract_port(entry)

    # SSH brute-force
    if ("ssh" in entry or port == 22) and any(term in entry for term in ["fail", "repeated", "login"]):
        return classify(log_entry, True, "brute-force attack (SSH)", 8, "Block IP and enable rate-limiting on SSH")

    # RDP brute-force
    if "rdp" in entry or port == 3389:
        return classify(log_entry, True, "brute-force attack (RDP)", 9, "Enable account lockout and enforce MFA on RDP")

    # FTP access attempts
    if "ftp" in entry or port == 21:
        return classify(log_entry, True, "unauthorized FTP access", 6, "Disable FTP if unused and block suspicious IPs")

    # SMB lateral movement
    if "smb" in entry or port == 445:
        return classify(log_entry, True, "internal reconnaissance (SMB)", 7, "Investigate internal source for compromise")

    # SNMP scans
    if "snmp" in entry or port == 161:
        return classify(log_entry, True, "reconnaissance (SNMP scan)", 5, "Block SNMP access from untrusted sources")

    # Telnet access attempts
    if "telnet" in entry or port == 23:
        return classify(log_entry, True, "unauthorized access attempt (Telnet)", 6, "Block Telnet traffic and monitor source")

    # DNS
    if "dns" in entry or port == 53:
        return classify(log_entry, False, "benign DNS query", 0, "No action needed")

    # HTTPS
    if "https" in entry or port == 443:
        return classify(log_entry, False, "benign HTTPS session", 0, "No action needed")

    # Googlebot crawling
    if "googlebot" in entry:
        return classify(log_entry, False, "benign crawler (Googlebot)", 0, "No action needed")

    # HTTP
    if "http" in entry or port == 80:
        return classify(log_entry, False, "benign HTTP traffic", 0, "No action needed")

    # Fallback
    return classify(log_entry, False, "unknown or benign", 0, "No action needed")

# Output formatter
def classify(log_entry, suspicious, threat_type, severity, recommendation):
    print(f"🕵️ {log_entry.strip()} → {threat_type}")
    return {
        "log": log_entry.strip(),
        "suspicious": suspicious,
        "threat_type": threat_type,
        "severity": severity,
        "recommended_action": recommendation
    }

# Run the analyzer
results = []

with open(log_file_path, 'r') as log_file:
    logs = log_file.readlines()
    for log in logs:
        results.append(analyze_log(log))

with open(output_file_path, 'w') as output_file:
    json.dump(results, output_file, indent=2)

print("\n✅ Log analysis complete. Results saved to:", output_file_path)


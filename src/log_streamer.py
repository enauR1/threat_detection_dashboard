# src/log_streamer.py
import json
import os
import time
import random
from datetime import datetime

class LogStreamer:
    def __init__(self, log_source="sample", batch_size=5):
        self.log_source = log_source
        self.batch_size = batch_size
        self.log_index = 0
        self.sample_logs = []
        self.load_sample_logs()
    
    def load_sample_logs(self):
        """Load sample logs from a file"""
        try:
            # Try to find the log file
            log_file = os.path.join('data', 'sample_logs.txt')
            if not os.path.exists(log_file):
                log_file = os.path.join('..', 'data', 'sample_logs.txt')
            
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    self.sample_logs = [line.strip() for line in f if line.strip()]
            else:
                # Default logs if file doesn't exist
                self.sample_logs = [
                    "Multiple connection attempts from IP 192.168.1.105 to port 22 (SSH)",
                    "Failed login attempt for admin user from IP 10.0.0.15, 5th attempt in 2 minutes",
                    "Possible SQL injection attempt detected in web form submission",
                    "Unusual outbound traffic spike to IP 203.0.113.100 on port 445",
                    "DNS request to known malicious domain blocked",
                    "Successful login by user admin from IP 192.168.1.10",
                    "Regular outbound HTTPS traffic to various endpoints",
                    "Connection attempt to internal service from internal IP 10.0.0.25"
                ]
        except Exception as e:
            print(f"Error loading sample logs: {str(e)}")
            self.sample_logs = ["Error loading logs"]
    
    def get_logs(self, count=None):
        """Get a batch of logs"""
        if count is None:
            count = self.batch_size
        
        if self.log_source == "sample":
            return self.get_sample_logs(count)
        elif self.log_source == "file":
            return self.get_file_logs(count)
        else:
            return self.generate_synthetic_logs(count)
    
    def get_sample_logs(self, count):
        """Get logs from the sample list"""
        logs = []
        for _ in range(count):
            # Cycle through sample logs
            log_text = self.sample_logs[self.log_index % len(self.sample_logs)]
            self.log_index += 1
            
            # Create log entry
            log_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source": random.choice(["Firewall", "IDS", "Authentication", "Network"]),
                "message": log_text
            }
            logs.append(log_entry)
        
        return logs
    
    def get_file_logs(self, count):
        """Get logs from a file source (placeholder)"""
        # This would be implemented to read from actual log files
        return self.get_sample_logs(count)  # Fallback to sample logs
    
    def generate_synthetic_logs(self, count):
        """Generate synthetic logs for testing"""
        log_templates = [
            "Connection from IP {ip} to port {port} ({service})",
            "{result} login attempt for user {user} from IP {ip}",
            "Port scan detected from IP {ip}, scanning ports {port_range}",
            "Unusual {direction} traffic to IP {ip} on port {port}",
            "DNS request to {domain_type} domain {domain}",
            "Firewall {action} connection from {ip} to {target}",
            "System file {file} {action} by user {user}",
            "Unexpected privilege escalation for user {user}"
        ]
        
        logs = []
        for _ in range(count):
            template = random.choice(log_templates)
            
            # Fill in template variables
            log_text = template.format(
                ip=f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
                port=random.choice([22, 80, 443, 3389, 8080, 8443, 445, 139]),
                service=random.choice(["SSH", "HTTP", "HTTPS", "RDP", "SMB"]),
                result=random.choice(["Failed", "Successful"]),
                user=random.choice(["admin", "root", "user", "system", "guest"]),
                port_range=f"{random.randint(20, 100)}-{random.randint(101, 1000)}",
                direction=random.choice(["inbound", "outbound"]),
                domain_type=random.choice(["known malicious", "suspicious", "legitimate"]),
                domain=f"example{random.randint(1, 999)}.com",
                action=random.choice(["blocked", "allowed", "flagged", "monitored"]),
                target=f"10.0.0.{random.randint(1, 254)}",
                file=f"/etc/{random.choice(['passwd', 'shadow', 'hosts', 'config', 'system'])}"
            )
            
            # Create log entry
            log_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source": random.choice(["Firewall", "IDS", "Authentication", "Network"]),
                "message": log_text
            }
            logs.append(log_entry)
        
        return logs
    
    def save_logs(self, logs, filename="live_logs.json"):
        """Save logs to a JSON file"""
        try:
            # Try to save in data directory
            data_dir = os.path.join('data')
            if not os.path.exists(data_dir):
                data_dir = os.path.join('..', 'data')
            
            if not os.path.exists(data_dir):
                os.makedirs(data_dir)
                
            with open(os.path.join(data_dir, filename), 'w') as f:
                json.dump(logs, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving logs: {str(e)}")
            return False
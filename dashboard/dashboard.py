# dashboard/dashboard.py
import streamlit as st
import pandas as pd
import json
import time
import os
import requests
import re
import random
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go

# Set page configuration
st.set_page_config(
    page_title="AI Threat Detection Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# Initialize theme state if not already done
if 'theme' not in st.session_state:
    st.session_state.theme = "Light"

# Apply theme based on session state
if st.session_state.get('theme') == "Dark":
    # Dark theme CSS
    st.markdown("""
    <style>
        /* Overall app background and text */
        .stApp {
            background-color: #0e1117;
            color: #fafafa;
        }
        
        /* Sidebar */
        [data-testid="stSidebar"] {
            background-color: #1a1a1a;
            border-right: 1px solid #333;
        }
        
        /* Fix sidebar text color */
        [data-testid="stSidebar"] .stMarkdown,
        [data-testid="stSidebar"] .stSelectbox label,
        [data-testid="stSidebar"] .stSlider label,
        [data-testid="stSidebar"] .stHeader,
        [data-testid="stSidebar"] p,
        [data-testid="stSidebar"] span,
        [data-testid="stSidebar"] div:not(.stAlert) {
            color: #fafafa !important;
        }
        
        /* Fix sidebar input fields */
        [data-testid="stSidebar"] input,
        [data-testid="stSidebar"] .stTextInput input, 
        [data-testid="stSidebar"] .stNumberInput input {
            color: #fafafa !important;
            background-color: #333 !important;
        }
        
        /* Fix sidebar widgets */
        [data-testid="stSidebar"] .stSelectbox [data-baseweb="select"] div,
        [data-testid="stSidebar"] .stMultiSelect [data-baseweb="select"] div {
            background-color: #333 !important;
            color: #fafafa !important;
        }

        /* Fix dropdown menu options - make text black for better visibility */
        [data-baseweb="popover"] div[role="listbox"] div {
            color: #000000 !important;
        }

        /* Keep selected option text white */
        [data-baseweb="select"] div[data-testid="stMarkdown"] {
            color: #fafafa !important;
        }
                
        /* Fix top right menu buttons */
        [data-testid="stToolbar"] button,
        [data-testid="baseButton-headerNoPadding"],
        div[data-testid="stActionButtonIcon"] {
            color: #fafafa !important;
            background-color: rgba(38, 39, 48, 0.3) !important;
            border-color: #4d4d4d !important;
        }

        /* Fix deploy and other top menu items */
        .main-menu-dropdown,
        [data-testid="stAppViewBlockContainer"] > div:first-child div button {
            color: #fafafa !important;
        }

        /* Fix dropdown menus */
        [data-baseweb="select"] svg,
        [data-baseweb="select"] span {
            color: #fafafa !important;
        }

        /* Fix header buttons hover */
        [data-testid="stToolbar"] button:hover,
        [data-testid="baseButton-headerNoPadding"]:hover {
            background-color: rgba(70, 70, 80, 0.5) !important;
        }       
                       
        /* Containers and cards */
        [data-testid="stContainer"] {
            background-color: #262730;
            border: 1px solid #333;
        }
        
        /* Headers */
        h1, h2, h3, h4, h5, h6 {
            color: #fff !important;
        }
        
        /* Expanders */
        .streamlit-expanderHeader {
            background-color: #262730;
            color: white;
        }
        
        /* Dataframes */
        .dataframe {
            background-color: #0e1117;
            color: white;
        }
        
        .dataframe tbody tr:nth-child(even) {
            background-color: #1a1a1a;
        }
        
        .dataframe th {
            background-color: #262730;
            color: white;
        }
        
        /* Buttons */
        .stButton>button {
            color: #fafafa;
            background-color: #262730;
            border: 1px solid #333;
        }
        
        /* Text inputs */
        .stTextInput>div>div {
            background-color: #262730;
            color: #fafafa;
        }
    </style>
    """, unsafe_allow_html=True)

# -------------------- LM Studio Analyzer Class --------------------
class LMStudioAnalyzer:
    def __init__(self, api_url="http://localhost:1234/v1"):
        self.api_url = api_url
        self.cache = {}
        self.connection_failures = 0  # Track consecutive failures
        self.max_failures = 3  # Max failures before going offline
        self.is_healthy = True  # Connection health status
        
    def analyze_log(self, log_entry):
        """Analyze a log entry with connection recovery"""
        # Check cache first
        if log_entry in self.cache:
            return self.cache[log_entry]
        
        # If too many failures, return offline response
        if self.connection_failures >= self.max_failures:
            self.is_healthy = False
            return {
                "is_threat": False,
                "threat_level": "Offline",
                "threat_type": "System Offline",
                "explanation": f"LM Studio disconnected after {self.connection_failures} failures. Using basic pattern matching.",
                "recommended_action": "Reconnect to LM Studio for AI analysis",
                "confidence": "Low"
            }
        
        # Build prompt (your existing prompt code here)
        prompt = f"""
        Analyze the following security log entry to determine if it represents a security threat.
        
        Security log: {log_entry}
        
        Respond ONLY in the following JSON format:
        {{
          "is_threat": true/false,
          "threat_level": "Critical/High/Medium/Low/None",
          "threat_type": "Specific type or 'Normal Activity'",
          "explanation": "Brief explanation",
          "recommended_action": "Specific steps or 'Continue routine monitoring'",
          "confidence": "High/Medium/Low"
        }}
        """
        
        try:
            response = requests.post(
                f"{self.api_url}/chat/completions",
                headers={"Content-Type": "application/json"},
                json={
                    "model": "local-model",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.1
                },
                timeout=10  # Shorter timeout for faster failure detection
            )
            
            if response.status_code == 200:
                # Success! Reset failure counter
                self.connection_failures = 0
                self.is_healthy = True
                
                result = response.json()
                answer = result['choices'][0]['message']['content']
                
                # JSON parsing (your existing code)
                try:
                    json_match = re.search(r'\{.*\}', answer, re.DOTALL)
                    if json_match:
                        json_str = json_match.group(0)
                        result = json.loads(json_str)
                    else:
                        result = json.loads(answer)
                    
                    self.cache[log_entry] = result
                    return result
                    
                except json.JSONDecodeError:
                    return self._create_fallback_response(log_entry, "JSON parse error")
            else:
                # Server error
                self.connection_failures += 1
                return self._create_fallback_response(log_entry, f"Server error: {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            # Connection failed
            self.connection_failures += 1
            return self._create_fallback_response(log_entry, "Connection lost to LM Studio")
            
        except requests.exceptions.Timeout:
            # Request timed out
            self.connection_failures += 1
            return self._create_fallback_response(log_entry, "Request timeout")
            
        except Exception as e:
            # Any other error
            self.connection_failures += 1
            return self._create_fallback_response(log_entry, f"Unexpected error: {str(e)}")
    
    def _create_fallback_response(self, log_entry, error_msg):
        """Create a fallback response when LM Studio is unavailable"""
        # Basic pattern matching for common threats
        log_lower = log_entry.lower()
        
        if any(word in log_lower for word in ['failed', 'error', 'unauthorized', 'denied']):
            threat_level = "Medium"
            is_threat = True
            threat_type = "Potential Security Event"
        elif any(word in log_lower for word in ['malware', 'virus', 'attack', 'breach']):
            threat_level = "High" 
            is_threat = True
            threat_type = "Security Threat Detected"
        else:
            threat_level = "Low"
            is_threat = False
            threat_type = "Normal Activity"
            
        return {
            "is_threat": is_threat,
            "threat_level": threat_level,
            "threat_type": threat_type,
            "explanation": f"LM Studio offline ({error_msg}). Basic pattern analysis used.",
            "recommended_action": "Restore LM Studio connection for full AI analysis",
            "confidence": "Low"
        }
    
    def get_health_status(self):
        """Get current connection health"""
        if self.connection_failures == 0:
            return "🟢 Healthy", "Connected and functioning"
        elif self.connection_failures < self.max_failures:
            return "🟡 Degraded", f"{self.connection_failures} recent failures"
        else:
            return "🔴 Offline", f"Disconnected after {self.connection_failures} failures"
            
    def test_connection(self):
        """Test the connection to LM Studio API"""
        try:
            response = requests.get(
                f"{self.api_url}/models",
                timeout=5
            )
            if response.status_code == 200:
                return True, "Connected to LM Studio API successfully"
            else:
                return False, f"Connection error: Status code {response.status_code}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

# -------------------- Threat Correlation Engine --------------------
class ThreatCorrelationEngine:
    def __init__(self, time_window=30):
        """Initialize correlation engine with a time window (in minutes)"""
        self.time_window = time_window
        self.potential_attack_patterns = {
            "brute_force": {
                "indicators": ["failed login", "authentication failure", "unsuccessful login"],
                "threshold": 3,
                "description": "Multiple failed login attempts indicate a possible brute force attack"
            },
            "port_scan": {
                "indicators": ["port scan", "connection attempt", "port"],
                "threshold": 3,
                "description": "Multiple connection attempts to different ports indicate a possible port scan"
            },
            "data_exfiltration": {
                "indicators": ["unusual outbound", "large data transfer", "unexpected traffic"],
                "threshold": 2,
                "description": "Unusual outbound traffic may indicate data exfiltration"
            },
            "lateral_movement": {
                "indicators": ["internal", "privilege escalation", "unauthorized access"],
                "threshold": 2,
                "description": "Activity across multiple internal systems may indicate lateral movement"
            },
            "malware_activity": {
                "indicators": ["malware", "virus", "trojan", "suspicious file", "unusual process"],
                "threshold": 2,
                "description": "Multiple malware-related events indicate active infection"
            }
        }
    
    def find_correlated_threats(self, logs):
        """Analyze logs to find correlated threats"""
        # Skip if not enough logs
        if len(logs) < 2:
            return []
            
        # Sort logs by timestamp
        sorted_logs = sorted(logs, key=lambda x: x.get("timestamp", ""))
        
        # Find time window
        now = datetime.now()
        cutoff_time = now - timedelta(minutes=self.time_window)
        
        # Filter logs within time window
        recent_logs = []
        for log in sorted_logs:
            try:
                log_time = datetime.strptime(log.get("timestamp", now.strftime("%Y-%m-%d %H:%M:%S")), "%Y-%m-%d %H:%M:%S")
                if log_time > cutoff_time:
                    recent_logs.append(log)
            except (ValueError, TypeError):
                continue  # Skip logs with invalid timestamps
        
        # Correlation results
        correlations = []
        
        # Check each attack pattern
        for pattern_name, pattern_info in self.potential_attack_patterns.items():
            # Find logs matching this pattern
            matching_logs = []
            
            for log in recent_logs:
                message = log.get("message", "").lower()
                if any(indicator.lower() in message for indicator in pattern_info["indicators"]):
                    matching_logs.append(log)
            
            # If enough matching logs found, create correlation
            if len(matching_logs) >= pattern_info["threshold"]:
                # Extract IPs if possible
                source_ips = []
                for log in matching_logs:
                    message = log.get("message", "")
                    # Simple IP extraction - can be improved
                    ip_match = re.search(r'IP\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
                    if ip_match:
                        source_ips.append(ip_match.group(1))
                
                correlation = {
                    "pattern_name": pattern_name,
                    "severity": "High" if len(matching_logs) > pattern_info["threshold"] + 1 else "Medium",
                    "description": pattern_info["description"],
                    "matching_logs": len(matching_logs),
                    "first_seen": matching_logs[0].get("timestamp", ""),
                    "last_seen": matching_logs[-1].get("timestamp", ""),
                    "source_ips": list(set(source_ips))
                }
                correlations.append(correlation)
        
        return correlations

# -------------------- Log Source Classes --------------------
class LogSource:
    def get_logs(self, count=5):
        """Base method to get logs - should be implemented by subclasses"""
        return []

class SampleLogSource(LogSource):
    def get_logs(self, count=5):
        """Generate synthetic security logs for testing"""
        log_templates = [
            "Connection from IP {ip} to port {port} ({service})",
            "{result} login attempt for user {user} from IP {ip}",
            "Port scan detected from IP {ip}, scanning ports {port_range}",
            "Unusual {direction} traffic to IP {ip} on port {port}",
            "DNS request to {domain_type} domain {domain}",
            "Firewall {action} connection from {ip} to {target}",
            "System file {file} {action} by user {user}",
            "Unexpected privilege escalation for user {user}",
            "Multiple failed login attempts for user {user} from IP {ip}",
            "Malware detection: {malware_type} found in {file}",
            "Suspicious process {process} started by user {user}",
            "Large data transfer ({size}MB) to external IP {ip}"
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
                file=f"/etc/{random.choice(['passwd', 'shadow', 'hosts', 'config', 'system'])}",
                malware_type=random.choice(["Trojan", "Virus", "Ransomware", "Keylogger"]),
                process=random.choice(["cmd.exe", "powershell.exe", "bash", "python"]),
                size=random.randint(50, 500)
            )
            
            # Create log entry
            log_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source": random.choice(["Firewall", "IDS", "Authentication", "Network", "Antivirus", "HIDS"]),
                "message": log_text
            }
            logs.append(log_entry)
        
        return logs

class FileLogSource(LogSource):
    def __init__(self, file_path=None, last_position=0):
        self.file_path = file_path
        self.last_position = last_position
        
    def get_logs(self, count=5):
        """Get logs from a file"""
        logs = []
        
        if not self.file_path or not os.path.exists(self.file_path):
            return logs
            
        try:
            with open(self.file_path, 'r') as f:
                # Skip to last position
                f.seek(self.last_position)
                
                # Read new lines
                for _ in range(count):
                    line = f.readline().strip()
                    if not line:
                        break
                        
                    # Create log entry
                    log_entry = {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "source": "File",
                        "message": line
                    }
                    logs.append(log_entry)
                
                # Remember position for next time
                self.last_position = f.tell()
        except Exception as e:
            st.error(f"Error reading log file: {str(e)}")
            
        return logs

# -------------------- Initialize Session State --------------------
# Initialize session state
if 'logs' not in st.session_state:
    st.session_state.logs = []

if 'analyzed_logs' not in st.session_state:
    st.session_state.analyzed_logs = []

if 'lm_analyzer' not in st.session_state:
    st.session_state.lm_analyzer = None
    st.session_state.lm_connected = False

if 'log_source' not in st.session_state:
    st.session_state.log_source = SampleLogSource()

if 'monitoring' not in st.session_state:
    st.session_state.monitoring = False

if 'threat_stats' not in st.session_state:
    st.session_state.threat_stats = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "None": 0,
        "Error": 0
    }

# Initialize correlation engine
if 'correlation_engine' not in st.session_state:
    st.session_state.correlation_engine = ThreatCorrelationEngine()

if 'correlated_threats' not in st.session_state:
    st.session_state.correlated_threats = []

# -------------------- Dashboard Layout --------------------
# Dashboard title
st.title("🛡️ AI Threat Detection Dashboard")

# Sidebar for configuration
with st.sidebar:
    # Theme selector
    st.header("Theme Settings")
    theme = st.selectbox("Dashboard Theme", ["Light", "Dark"], index=["Light", "Dark"].index(st.session_state.theme))
    if theme != st.session_state.theme:
        st.session_state.theme = theme
        st.rerun()
    
    st.header("LM Studio Connection")
    api_url = st.text_input("LM Studio API URL", "http://localhost:1234/v1")
    
    # Connect button
    if st.button("Connect to LM Studio"):
        st.session_state.lm_analyzer = LMStudioAnalyzer(api_url=api_url)
        success, message = st.session_state.lm_analyzer.test_connection()
        if success:
            st.session_state.lm_connected = True
            st.success(message)
        else:
            st.error(message)
    
    # Show connection status
    if st.session_state.lm_connected:
        st.success("Connected to LM Studio")
    else:
        st.warning("Not connected to LM Studio")
    
    # Add connection status to sidebar
    if st.session_state.lm_analyzer:
        status_emoji, status_msg = st.session_state.lm_analyzer.get_health_status()
        st.write(f"Status: {status_emoji} {status_msg}")
        
        if st.button("Reset Connection"):
            st.session_state.lm_analyzer.connection_failures = 0
            st.session_state.lm_analyzer.is_healthy = True
            st.success("Connection status reset")
    
    st.header("Log Source Configuration")
    log_source_type = st.selectbox(
        "Log Source", 
        ["Sample", "File"],
        help="Sample: Generate synthetic logs, File: Read from a log file"
    )
    
    # Configure log source based on type
    if log_source_type == "File":
        log_file = st.text_input("Log File Path", "")
        if log_file and os.path.exists(log_file):
            st.session_state.log_source = FileLogSource(file_path=log_file)
            st.success(f"Using log file: {log_file}")
        else:
            if log_file:
                st.error(f"File not found: {log_file}")
            st.session_state.log_source = SampleLogSource()
    else:
        st.session_state.log_source = SampleLogSource()
    
    batch_size = st.slider("Logs per batch", 1, 10, 3)
    
    st.header("Dashboard Settings")
    refresh_rate = st.slider("Refresh Rate (seconds)", 2, 60, 10)
    
    # Correlation settings
    st.header("Correlation Settings")
    correlation_window = st.slider("Correlation Time Window (minutes)", 5, 60, 30)
    st.session_state.correlation_engine.time_window = correlation_window
    
    st.header("Filter Options")
    threat_level = st.multiselect(
        "Threat Level", 
        ["Critical", "High", "Medium", "Low"], 
        default=["Critical", "High"]
    )

# Create dashboard layout
col1, col2 = st.columns([2, 1])

# Main threat display
with col1:
    st.header("Latest Threat Detections")
    threat_container = st.container(height=400)
    
# Stats and metrics
with col2:
    st.header("Threat Statistics")
    stats_container = st.container(height=400)

# Threat correlation section
st.header("Threat Correlations")
correlation_container = st.container(height=300)

# Timeline visualization
timeline_container = st.container(height=400)

# Bottom section for log browser
st.header("Log Analysis Results")
log_browser = st.container(height=300)

# Raw logs section
st.header("Raw Logs (Before Analysis)")
raw_log_container = st.container(height=200)

# Function to analyze logs and update dashboard
def analyze_and_update():
    if not st.session_state.lm_connected:
        st.error("Not connected to LM Studio. Please connect first.")
        return
    
    # Start timing for performance tracking
    start_time = time.time()
    
    # Get new logs
    new_logs = st.session_state.log_source.get_logs(count=batch_size)
    st.session_state.logs.extend(new_logs)
    
    # Process logs with LM Studio
    for log in new_logs:
        try:
            analysis = st.session_state.lm_analyzer.analyze_log(log["message"])
            log_with_analysis = {**log, **analysis}
            
            # Add timestamp for when analysis was completed
            log_with_analysis["analysis_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Update threat stats
            level = log_with_analysis.get("threat_level", "Error")
            if level in st.session_state.threat_stats:
                st.session_state.threat_stats[level] += 1
            
            # Add to analyzed logs
            st.session_state.analyzed_logs.append(log_with_analysis)
        except Exception as e:
            st.error(f"Error analyzing log: {str(e)}")
    
    # Keep only the latest logs
    max_logs = 100
    if len(st.session_state.logs) > max_logs:
        st.session_state.logs = st.session_state.logs[-max_logs:]
    if len(st.session_state.analyzed_logs) > max_logs:
        st.session_state.analyzed_logs = st.session_state.analyzed_logs[-max_logs:]
    
    # Perform correlation analysis
    if len(st.session_state.analyzed_logs) >= 2:
        correlations = st.session_state.correlation_engine.find_correlated_threats(
            st.session_state.analyzed_logs
        )
        
        # Add any new correlations to the list
        for correlation in correlations:
            # Check if this correlation is already in the list
            if not any(c.get("pattern_name") == correlation["pattern_name"] and
                    c.get("first_seen") == correlation["first_seen"]
                    for c in st.session_state.correlated_threats):
                correlation["detection_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                st.session_state.correlated_threats.append(correlation)
        
        # Keep only the most recent correlations
        if len(st.session_state.correlated_threats) > 20:
            st.session_state.correlated_threats = st.session_state.correlated_threats[-20:]
    
    # Save analysis results
    if st.session_state.analyzed_logs:
        try:
            # Get the directory where the current script is located
            current_dir = os.path.dirname(os.path.abspath(__file__))
            # Create a path relative to that directory
            save_path = os.path.join(current_dir, '..', 'data', 'simulated_output.json')
            
            # Create the directory if it doesn't exist
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            
            with open(save_path, 'w') as f:
                json.dump(st.session_state.analyzed_logs, f, indent=2)
        except Exception as e:
            st.error(f"Error saving analysis results: {str(e)}")
    
    # Calculate processing time
    processing_time = time.time() - start_time
    
    # Update the dashboard with new results
    update_dashboard_display(processing_time)

def update_dashboard_display(processing_time):
    """Update all dashboard elements with the latest data"""
    # Update threat display
    with threat_container:
        threat_container.empty()
        
        # Filter logs by threat level
        filtered_logs = [log for log in st.session_state.analyzed_logs 
                      if log.get("is_threat", False) and log.get("threat_level", "None") in threat_level]
        
        if filtered_logs:
            # Sort by severity and time (most severe and recent first)
            severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4, "Error": 5}
            sorted_logs = sorted(filtered_logs[-10:], 
                               key=lambda x: (severity_order.get(x.get("threat_level", "None"), 999), 
                                             -filtered_logs.index(x)))
            
            for log in sorted_logs[:5]:  # Show only the most recent 5 threats
                col1, col2 = st.columns([1, 4])
                with col1:
                    if log["threat_level"] == "Critical":
                        st.error("CRITICAL")
                    elif log["threat_level"] == "High":
                        st.warning("HIGH")
                    elif log["threat_level"] == "Medium":
                        st.info("MEDIUM")
                    else:
                        st.success("LOW")
                
                with col2:
                    st.write(f"**Source:** {log['source']}")
                    st.write(f"**Time:** {log['timestamp']}")
                    st.write(f"**Type:** {log.get('threat_type', 'Unknown')}")
                    st.write(f"**Log:** {log['message']}")
                    st.write(f"**Analysis:** {log.get('explanation', 'No explanation provided')}")
                    st.write(f"**Action:** {log.get('recommended_action', 'No action recommended')}")
                    st.write(f"**Confidence:** {log.get('confidence', 'Medium')}")
                    st.divider()
        else:
            st.info("No threats detected with the current filter settings")
    
    # Update statistics display
    with stats_container:
        stats_container.empty()
        
        if st.session_state.analyzed_logs:
            # Count threats by level
            threat_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0, "Error": 0}
            for log in st.session_state.analyzed_logs:
                level = log.get("threat_level", "None")
                if level in threat_counts:
                    threat_counts[level] += 1
            
            # Create data for chart
            threat_level_data = {
                "Threat Level": list(threat_counts.keys()),
                "Count": list(threat_counts.values())
            }
            threat_df = pd.DataFrame(threat_level_data)
            
            # Create pie chart
            fig = px.pie(
                threat_df, 
                values='Count', 
                names='Threat Level',
                color='Threat Level',
                color_discrete_map={
                    'Critical': 'red',
                    'High': 'orange',
                    'Medium': 'yellow',
                    'Low': 'blue',
                    'None': 'green',
                    'Error': 'gray'
                }
            )
            st.plotly_chart(fig, use_container_width=True)
            
            # Show processing metrics
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Processing Time", f"{processing_time:.2f} seconds")
            with col2:
                st.metric("Total Logs Analyzed", len(st.session_state.analyzed_logs))
        else:
            st.info("No threat data available yet")
    
    # Update correlation display
    with correlation_container:
        correlation_container.empty()
        
        if st.session_state.correlated_threats:
            st.markdown("### Detected Attack Patterns")
            
            for correlation in st.session_state.correlated_threats:
                with st.expander(f"**{correlation['pattern_name'].replace('_', ' ').title()}** - {correlation['severity']} severity"):
                    st.markdown(f"**Description:** {correlation['description']}")
                    st.markdown(f"**First seen:** {correlation['first_seen']}")
                    st.markdown(f"**Last seen:** {correlation['last_seen']}")
                    st.markdown(f"**Matching logs:** {correlation['matching_logs']}")
                    
                    if correlation.get('source_ips'):
                        st.markdown(f"**Source IPs:** {', '.join(correlation['source_ips'])}")
                    
                    st.markdown("---")
                    st.markdown("**Recommended action:** Investigate these related events as they may be part of a coordinated attack.")
        else:
            st.info("No correlated threats detected yet. Correlation requires multiple related logs.")
    
    # Update timeline visualization
    with timeline_container:
        timeline_container.empty()
        
        if st.session_state.correlated_threats and len(st.session_state.analyzed_logs) > 5:
            st.subheader("Attack Timeline")
            
            # Prepare timeline data
            timeline_data = []
            
            # Add individual logs
            for log in st.session_state.analyzed_logs[-20:]:  # Last 20 logs
                if log.get("is_threat", False):
                    try:
                        timeline_data.append({
                            "Time": datetime.strptime(log.get("timestamp", ""), "%Y-%m-%d %H:%M:%S"),
                            "Type": log.get("threat_type", "Unknown"),
                            "Severity": log.get("threat_level", "Low"),
                            "Description": f"Individual log: {log.get('message', '')[:50]}..."
                        })
                    except ValueError:
                        continue  # Skip logs with invalid timestamps
            
            # Add correlated events
            for corr in st.session_state.correlated_threats:
                try:
                    timeline_data.append({
                        "Time": datetime.strptime(corr.get("detection_time", ""), "%Y-%m-%d %H:%M:%S"),
                        "Type": corr.get("pattern_name", "").replace("_", " ").title(),
                        "Severity": corr.get("severity", "Medium"),
                        "Description": f"Correlated attack: {corr.get('description', '')}"
                    })
                except ValueError:
                    continue  # Skip correlations with invalid timestamps
            
            # Only create visualization if we have data
            if timeline_data:
                # Sort by time
                timeline_df = pd.DataFrame(timeline_data)
                timeline_df = timeline_df.sort_values("Time")
                
                # Create color map
                color_map = {
                    "Critical": "red",
                    "High": "orange",
                    "Medium": "yellow",
                    "Low": "blue",
                    "None": "green"
                }
                
                # Create figure
                fig = px.scatter(
                    timeline_df,
                    x="Time",
                    y="Type",
                    color="Severity",
                    color_discrete_map=color_map,
                    hover_data=["Description"],
                    size_max=10,
                    title="Security Event Timeline"
                )
                
                # Customize layout
                fig.update_layout(
                    xaxis_title="Time",
                    yaxis_title="Event Type",
                    height=400
                )
                
                # Show figure
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Not enough data for timeline visualization")
        else:
            st.info("Timeline visualization will appear when correlated threats are detected")
    
    # Update log browser
    with log_browser:
        log_browser.empty()
        if st.session_state.analyzed_logs:
            # Create DataFrame
            log_df = pd.DataFrame(st.session_state.analyzed_logs)
            
            # Format for display
            displayable_cols = ['timestamp', 'source', 'message', 'threat_level', 'threat_type', 'explanation', 'confidence']
            display_df = log_df[displayable_cols] if all(col in log_df.columns for col in displayable_cols) else log_df
            
            # Show DataFrame
            st.dataframe(display_df, use_container_width=True)
        else:
            st.info("No logs collected yet")
    
    # Update raw logs display
    with raw_log_container:
        raw_log_container.empty()
        if st.session_state.logs:
            # Create DataFrame for raw logs
            raw_df = pd.DataFrame(st.session_state.logs)
            st.dataframe(raw_df, use_container_width=True)
        else:
            st.info("No raw logs collected yet")
            
def display_existing_data():
    """Display existing data from session state without reanalysis"""
    # Only update display if we have data to show
    if (st.session_state.analyzed_logs or 
        st.session_state.correlated_threats or 
        st.session_state.logs):
        # Don't pass processing_time for existing data display
        update_dashboard_display(processing_time=0.0)

# IMPORTANT: Call this function on every page load to maintain dashboard state
# This ensures data persists when sidebar options change
display_existing_data()

# Add buttons to control monitoring
col1, col2, col3 = st.columns(3)

with col1:
    if st.button("Analyze Single Batch"):
        with st.spinner("Analyzing logs..."):
            analyze_and_update()

with col2:
    if st.session_state.monitoring:
        if st.button("Stop Monitoring"):
            st.session_state.monitoring = False
            st.success("Monitoring stopped")
    else:
        if st.button("Start Monitoring"):
            st.session_state.monitoring = True

with col3:
    if st.button("Clear All Logs"):
        st.session_state.logs = []
        st.session_state.analyzed_logs = []
        st.session_state.correlated_threats = []
        st.session_state.threat_stats = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "None": 0,
            "Error": 0
        }
        st.success("Logs cleared")

# Create placeholder for monitoring status
monitoring_status = st.empty()

# Update monitoring section
if st.session_state.monitoring:
    monitoring_placeholder = st.empty()
    
    try:
        # Show connection status
        if st.session_state.lm_analyzer:
            status_emoji, status_msg = st.session_state.lm_analyzer.get_health_status()
            monitoring_placeholder.info(f"Monitoring active {status_emoji} - {status_msg} - Next update in {refresh_rate} seconds...")
        else:
            monitoring_placeholder.warning("Monitoring active - LM Studio not connected")
        
        # Process logs (with error handling)
        with st.spinner("Analyzing logs..."):
            analyze_and_update()
            
    except Exception as e:
        # If monitoring fails, don't crash - just show error and continue
        st.error(f"Monitoring error: {str(e)}")
        st.warning("Monitoring will continue with next update...")
    
    # Schedule next update
    time.sleep(1)
    st.rerun()

# Add explanatory information
with st.expander("About this Dashboard"):
    st.write("""
    ## AI Threat Detection Dashboard
    
    This dashboard uses LM Studio to analyze security logs in real-time. The system evaluates each log entry 
    to determine if it represents a security threat and categorizes them by severity.
    
    ### How to use:
    1. Make sure LM Studio is running with its API server enabled
    2. Connect to LM Studio using the sidebar
    3. Choose your log source (Sample or File)
    4. Click "Start Monitoring" for continuous analysis or "Analyze Single Batch" for a one-time analysis
    5. View threat detections, statistics, and detailed log analysis results
    
    ### Features:
    - Real-time log analysis with AI
    - Threat categorization (Critical, High, Medium, Low)
    - Threat type identification
    - Confidence levels for each analysis
    - Recommended actions for detected threats
    - Advanced threat correlation to identify attack patterns
    - Visual timeline of security events
    - Filtering by threat level
    - Dark mode support
    
    ### How it works:
    1. Security logs are collected from your selected source
    2. Each log is sent to LM Studio for AI-powered analysis
    3. The correlation engine identifies related events that may indicate coordinated attacks
    4. Results are processed and displayed in real-time
    5. Dashboard updates automatically with new data
    
    This dashboard is part of a university internship project focused on AI-based security threat detection.
    """)
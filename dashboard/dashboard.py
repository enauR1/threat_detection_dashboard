# dashboard/dashboard.py
import streamlit as st
import pandas as pd
import json
import time
import os
import requests
import re
import random
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go

# Set page configuration
st.set_page_config(
    page_title="AI Threat Detection Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# -------------------- LM Studio Analyzer Class --------------------
class LMStudioAnalyzer:
    def __init__(self, api_url="http://localhost:1234/v1"):
        self.api_url = api_url
        self.cache = {}  # Simple cache for recent analyses
        
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
    
    def analyze_log(self, log_entry):
        """Analyze a log entry using LM Studio API with caching"""
        # Check cache first (simple exact match caching)
        if log_entry in self.cache:
            return self.cache[log_entry]
            
        prompt = f"""
        Analyze the following security log entry to determine if it represents a security threat.
        
        Security log: {log_entry}
        
        Consider the following in your analysis:
        1. Is this a known attack pattern (brute force, SQL injection, etc.)?
        2. What is the potential impact of this activity?
        3. Is this likely a false positive or benign activity?
        
        Categorize the threat level as:
        - Critical: Immediate action required, active compromise likely
        - High: Urgent attention needed, high probability of malicious activity
        - Medium: Suspicious activity that should be investigated
        - Low: Possible concern but limited risk
        - None: Normal or expected activity
        
        Respond ONLY in the following JSON format:
        {{
          "is_threat": true/false,
          "threat_level": "Critical/High/Medium/Low/None",
          "threat_type": "Specific type (e.g., brute force, SQL injection, unauthorized access)",
          "explanation": "Brief explanation of why this is or isn't a threat",
          "recommended_action": "Specific steps to address this threat",
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
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                answer = result['choices'][0]['message']['content']
                
                # Try to extract JSON from the answer
                try:
                    # Find anything that looks like JSON in the answer
                    json_match = re.search(r'\{.*\}', answer, re.DOTALL)
                    if json_match:
                        json_str = json_match.group(0)
                        result = json.loads(json_str)
                    else:
                        # If no JSON found, parse the whole answer
                        result = json.loads(answer)
                        
                    # Cache successful results
                    self.cache[log_entry] = result
                    
                    # Limit cache size
                    if len(self.cache) > 1000:
                        # Remove oldest items
                        for _ in range(100):
                            self.cache.pop(next(iter(self.cache)), None)
                            
                    return result
                except json.JSONDecodeError:
                    # Handle case where model doesn't return valid JSON
                    return {
                        "is_threat": False,
                        "threat_level": "Error",
                        "threat_type": "Error",
                        "explanation": "Failed to parse model response: " + answer[:100] + "...",
                        "recommended_action": "Check model configuration",
                        "confidence": "Low"
                    }
            else:
                return {
                    "is_threat": False,
                    "threat_level": "Error",
                    "threat_type": "Error",
                    "explanation": f"API Error: {response.status_code}",
                    "recommended_action": "Check LM Studio connection",
                    "confidence": "Low"
                }
                
        except Exception as e:
            return {
                "is_threat": False,
                "threat_level": "Error",
                "threat_type": "Error",
                "explanation": f"Exception: {str(e)}",
                "recommended_action": "Check network connection",
                "confidence": "Low"
            }

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

# -------------------- Dashboard Layout --------------------
# Dashboard title
st.title("🛡️ AI Threat Detection Dashboard")

# Sidebar for configuration
with st.sidebar:
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

# Bottom section for log browser
st.header("Log Analysis Results")
log_browser = st.container(height=300)

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

# Enhanced continuous monitoring loop
if st.session_state.monitoring:
    monitoring_placeholder = st.empty()
    
    # Display initial monitoring status
    monitoring_placeholder.info(f"Monitoring active - Next update in {refresh_rate} seconds...")
    
    # Process the first batch
    try:
        with st.spinner("Analyzing logs..."):
            analyze_and_update()
    except Exception as e:
        st.error(f"Error during monitoring: {str(e)}")
        st.session_state.monitoring = False
    
    # Schedule next update
    next_update = datetime.now().timestamp() + refresh_rate
    
    # Add a note about auto-refresh
    st.info("Dashboard will automatically refresh to show new data. If monitoring stops, click 'Start Monitoring' again.")
    
    # We'll use an experimental rerun in a moment
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
    - Visual statistics and trend analysis
    - Filtering by threat level
    
    ### How it works:
    1. Security logs are collected from your selected source
    2. Each log is sent to LM Studio for AI-powered analysis
    3. Results are processed and displayed in real-time
    4. Dashboard updates automatically with new data
    
    This dashboard is part of a university internship project focused on AI-based security threat detection.
    """)
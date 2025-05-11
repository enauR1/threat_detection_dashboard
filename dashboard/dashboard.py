import streamlit as st
import json

st.set_page_config(page_title="Threat Detection Dashboard", layout="wide")

st.title("🛡️ AI Threat Detection Dashboard")

# Load JSON log data
with open("data/simulated_output.json", "r") as f:
    logs = json.load(f)

# Sidebar filters
st.sidebar.header("Filter logs")

severity_filter = st.sidebar.slider("Minimum severity", 0, 10, 0)
threat_types = sorted(list(set(log["threat_type"] for log in logs)))
selected_types = st.sidebar.multiselect("Threat types", threat_types, default=threat_types)

# Filter logs
filtered_logs = [
    log for log in logs
    if log["severity"] >= severity_filter and log["threat_type"] in selected_types
]

# Show stats
st.subheader(f"📊 Showing {len(filtered_logs)} matching log entries")

# Table display
st.dataframe(filtered_logs, use_container_width=True)

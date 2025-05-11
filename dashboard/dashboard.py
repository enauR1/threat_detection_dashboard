# dashboard/dashboard.py
"""
AI Threat Detection Dashboard
-----------------------------
• Live auto-refresh (30 s)
• Sidebar filters (severity slider + threat-type multiselect)
• Color-coded log table
• Pie chart (threat-type distribution)
• Bar chart (severity distribution)
• CSV / JSON download of filtered logs
"""

import json
import os
import streamlit as st
import pandas as pd
import altair as alt
from streamlit_autorefresh import st_autorefresh

# 1. Page & refresh ------------------------------------------------------------
st.set_page_config(page_title="AI Threat Detection Dashboard", layout="wide")
st_autorefresh(interval=30_000, key="live_refresh")  # 30 s auto-refresh
st.title("🛡️  AI Threat Detection Dashboard")

# 2. Load data -----------------------------------------------------------------
DATA_PATH = os.path.join("data", "simulated_output.json")
with open(DATA_PATH, "r") as f:
    log_data = json.load(f)

df = pd.DataFrame(log_data)

# 3. Sidebar filters -----------------------------------------------------------
st.sidebar.header("Filters")

severity_min, severity_max = int(df["severity"].min()), int(df["severity"].max())
min_sev = st.sidebar.slider("Minimum severity", severity_min, severity_max, severity_min)

all_types = sorted(df["threat_type"].unique().tolist())
sel_types = st.sidebar.multiselect("Threat types", all_types, default=all_types)

filtered_df = df[
    (df["severity"] >= min_sev) & (df["threat_type"].isin(sel_types))
].copy()

# 4. Styled DataFrame helper ---------------------------------------------------
def highlight_severity(row):
    sev = row["severity"]
    if sev >= 8:
        color = "#f8d7da"  # critical
    elif sev >= 5:
        color = "#fff3cd"  # high
    elif sev >= 3:
        color = "#d1ecf1"  # medium
    else:
        color = "#d4edda"  # low
    return [f"background-color: {color}"] * len(row)

styled_table = filtered_df.style.apply(highlight_severity, axis=1)

# 5. Display table -------------------------------------------------------------
st.subheader(f"Log Entries - {len(filtered_df)} shown")
st.dataframe(styled_table, use_container_width=True)

# 6. Charts --------------------------------------------------------------------
col1, col2 = st.columns(2)

with col1:
    st.subheader("Threat-Type Distribution")
    pie_df = filtered_df["threat_type"].value_counts().reset_index()
    pie_df.columns = ["Threat Type", "Count"]
    pie = (
        alt.Chart(pie_df)
        .mark_arc(innerRadius=50)
        .encode(
            theta="Count:Q",
            color="Threat Type:N",
            tooltip=["Threat Type", "Count"]
        )
    )
    st.altair_chart(pie, use_container_width=True)

with col2:
    st.subheader("Severity Distribution")
    bar_df = filtered_df["severity"].value_counts().sort_index().reset_index()
    bar_df.columns = ["Severity", "Count"]
    bar = (
        alt.Chart(bar_df)
        .mark_bar()
        .encode(
            x=alt.X("Severity:O", title="Severity"),
            y="Count:Q",
            color="Severity:O",
            tooltip=["Severity", "Count"]
        )
    )
    st.altair_chart(bar, use_container_width=True)

# 7. Download buttons ----------------------------------------------------------
st.subheader("Download Filtered Logs")

csv_bytes = filtered_df.to_csv(index=False).encode()
json_bytes = filtered_df.to_json(orient="records").encode()

col_csv, col_json = st.columns(2)

with col_csv:
    st.download_button(
        "Download CSV",
        data=csv_bytes,
        file_name="filtered_logs.csv",
        mime="text/csv"
    )

with col_json:
    st.download_button(
        "Download JSON",
        data=json_bytes,
        file_name="filtered_logs.json",
        mime="application/json"
    )

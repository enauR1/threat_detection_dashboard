# dashboard/dashboard.py
"""
AI Threat Detection Dashboard  •  JSON‑Array Version (Pandas‑compatible)
-----------------------------------------------------------------------
• Auto‑refresh every 30 s
• Sidebar: severity slider + threat‑type multiselect
• Color‑coded log table
• Pie + bar charts
• CSV / JSON download
"""

from pathlib import Path
import datetime
import json

import streamlit as st
import pandas as pd
import altair as alt
from streamlit_autorefresh import st_autorefresh

# ------------------------------------------------- 1. page + auto‑refresh
st.set_page_config(page_title="AI Threat Detection Dashboard", layout="wide")
st_autorefresh(interval=30_000, limit=None, key="refresh_every_30s")  # 30 s
st.title("🛡️  AI Threat Detection Dashboard")
st.caption(f"Loaded at {datetime.datetime.now().isoformat(timespec='seconds')}")

# ------------------------------------------------- 2. load JSON array
DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "simulated_output.json"

if DATA_PATH.exists():
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        try:
            df = pd.DataFrame(json.load(f))
        except json.JSONDecodeError:
            st.error("Log file is corrupt JSON. Delete or fix the file then restart.")
            st.stop()
else:
    st.info("No log file found yet. Start log_streamer.py to generate logs.")
    st.stop()

# ------------------------------------------------- 3. sidebar filters
st.sidebar.header("Filters")

sev_min, sev_max = int(df["severity"].min()), int(df["severity"].max())
min_sev = st.sidebar.slider("Minimum severity", sev_min, sev_max, sev_min)

all_types = sorted(df["threat_type"].unique())
sel_types = st.sidebar.multiselect("Threat types", all_types, default=all_types)

filtered_df = df[
    (df["severity"] >= min_sev) & (df["threat_type"].isin(sel_types))
].copy()

# ------------------------------------------------- 4. style helper
def highlight(row):
    sev = row["severity"]
    if sev >= 8:
        c = "#f8d7da"
    elif sev >= 5:
        c = "#fff3cd"
    elif sev >= 3:
        c = "#d1ecf1"
    else:
        c = "#d4edda"
    return [f"background-color: {c}"] * len(row)

# ------------------------------------------------- 5. table
st.subheader(f"Log Entries – {len(filtered_df)} shown")
st.dataframe(filtered_df.style.apply(highlight, axis=1), use_container_width=True)

# ------------------------------------------------- 6. charts
col1, col2 = st.columns(2)

with col1:
    st.subheader("Threat‑Type Distribution")
    pie_df = (
        filtered_df["threat_type"]
        .value_counts()
        .reset_index()           # compatible with older pandas
    )
    pie_df.columns = ["Threat Type", "Count"]
    st.altair_chart(
        alt.Chart(pie_df)
        .mark_arc(innerRadius=50)
        .encode(
            theta="Count:Q",
            color="Threat Type:N",
            tooltip=["Threat Type", "Count"],
        ),
        use_container_width=True,
    )

with col2:
    st.subheader("Severity Distribution")
    bar_df = (
        filtered_df["severity"]
        .value_counts()
        .sort_index()
        .reset_index()
    )
    bar_df.columns = ["Severity", "Count"]
    st.altair_chart(
        alt.Chart(bar_df)
        .mark_bar()
        .encode(
            x="Severity:O",
            y="Count:Q",
            color="Severity:O",
            tooltip=["Severity", "Count"],
        ),
        use_container_width=True,
    )

# ------------------------------------------------- 7. download buttons
st.subheader("Download Filtered Logs")

csv_data  = filtered_df.to_csv(index=False).encode()
json_data = filtered_df.to_json(orient="records").encode()

col_csv, col_json = st.columns(2)
with col_csv:
    st.download_button("Download CSV", csv_data,  "filtered_logs.csv",  "text/csv")
with col_json:
    st.download_button("Download JSON", json_data, "filtered_logs.json", "application/json")

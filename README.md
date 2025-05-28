# 🛡️ AI Threat Detection Dashboard

A live-updating Streamlit app that ingests IDS / firewall logs, classifies threats, and visualises them with interactive filters and charts.  
Built as part of an AI Prompt-Engineer internship to showcase AI-assisted cybersecurity analytics.

## ✨ Features

| Category      | Highlights                                                                                         |
|---------------|-----------------------------------------------------------------------------------------------------|
| **Live feed** | Auto-refresh every 30 s to simulate incoming logs                                                   |
| **Filtering** | Sidebar severity slider (0-10) and multiselect for threat types                                     |
| **Table**     | Color-coded rows by severity (Critical → red · High → yellow · Medium → blue · Low → green)         |
| **Charts**    | Pie chart (threat-type distribution) · Bar chart (severity counts)                                  |
| **Downloads** | One-click export of filtered logs as **CSV** or **JSON**                                            |
| **Extensible**| Ready for GPT explanations, CVE look-ups, analyst notes, live log streaming, etc.                   |

## 🗂️ Project Structure
```
threat_detection_dashboard/
├─ data/
│  └─ simulated_output.json        # Current log dataset
├─ dashboard/
│  └─ dashboard.py                 # Streamlit app
├─ requirements.txt                # Python dependencies
└─ README.md                       # You are here
```

## 🛠️ Installation

```bash
pip install -r requirements.txt
```

## ▶️ Running Locally

```bash
streamlit run dashboard/dashboard.py
```

Then open **http://localhost:8501** in your browser.

## Notes

- Make sure LM Studio is running with its API server enabled (default port: 1234)
- The dashboard saves analyzed logs to `data/simulated_output.json`
- Dark mode ensures all elements remain visible
- The UI automatically adjusts to screen size

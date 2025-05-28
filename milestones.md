# 🛡️ AI Threat Detection Dashboard

A live‑updating Streamlit app that ingests IDS / firewall logs, classifies threats, and visualises them with interactive filters and charts.  
Built as part of an AI Prompt‑Engineer internship to showcase AI‑assisted cybersecurity analytics.

---

## 🚀 Demo

| Hosting          | URL                                                                                                                     |
|------------------|-------------------------------------------------------------------------------------------------------------------------|
| Streamlit Cloud  | <https://enauR1-threat-detection-dashboard.streamlit.app> 

---

## ✨ Features

| Category      | Highlights                                                                                         |
|---------------|-----------------------------------------------------------------------------------------------------|
| **Live feed** | Auto‑refresh every 30 s to simulate incoming logs                                                   |
| **Filtering** | Sidebar severity slider (0–10) and multiselect for threat types                                     |
| **Table**     | Color‑coded rows by severity (Critical → red · High → yellow · Medium → blue · Low → green)         |
| **Charts**    | Pie chart (threat‑type distribution) · Bar chart (severity counts)                                  |
| **Downloads** | One‑click export of filtered logs as **CSV** or **JSON**                                            |
| **Extensible**| Ready for GPT explanations, CVE look‑ups, analyst notes, live log streaming, etc.                   |

---

## 🗂️ Project Structure
```
threat_detection_dashboard/
├─ data/
│  └─ simulated_output.json        # Current log dataset
├─ dashboard/
│  └─ dashboard.py                 # Streamlit app
├─ src/
│  └─ log_analyzer.py              # Rule‑based log classifier
├─ milestones.md                   # 70‑h roadmap
├─ activity_log.md                 # Weekly internship log
└─ README.md                       # You are here
```

---

## 🛠️ Installation

```bash
git clone https://github.com/enauR1/threat_detection_dashboard.git
cd threat_detection_dashboard


---

## ▶️ Running Locally

```bash
streamlit run dashboard/dashboard.py
```

Then open **http://localhost:8501** in your browser.

---

## 🌐 Deploying to Streamlit Cloud

1. Push this repo (already done) to **GitHub**.  
2. Log in to <https://streamlit.io/cloud> and click **New app**.  
3. Select **enauR1/threat_detection_dashboard** and set the main file to `dashboard/dashboard.py`.  
4. Click **Deploy** – your public URL (shown above) goes live.

---

## 🔮 Planned Enhancements
- GPT‑4 explanations for suspicious logs
- CVE correlation via NVD API with mitigation guidance
- Analyst note‑taking and incident workflow
- Live log generator & smooth scrolling “war‑room” view
- Dark/light theme toggle and overall UI polish

See **`milestones.md`** for the full 70‑hour roadmap.

---

## 👥 Contributing

Pull requests welcome! Fork, create a feature branch, commit descriptive messages, and open a PR.

---

## 📝 License
MIT © 2025 Patrick Ruane
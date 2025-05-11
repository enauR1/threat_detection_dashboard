
---

# 🧾 Internship Log – Week 1

**Dates:** May 7 – May 13, 2025

---

### 📅 May 5, 2025

**Total Hours Worked:** 3

---

**Tasks Completed:**

* Researched three capstone projects
* Finalized decisions for three projects
* Used ChatGPT and Deepseek to generate detailed descriptions of each capstone project
* Created weekly breakdowns and structured reports for deliverables, software/resources used, and skills gained

---

### 📅 May 8, 2025

**Total Hours Worked:** 3.5

---

**Tasks Completed:**

* Created structured folder system for local project development
* Generated 10 simulated firewall/IDS log entries
* Ran prompt test on log #1 (SSH brute-force)

  * Output: Identified correctly as brute-force, rated severity 6/10, gave strong mitigation advice
* Ran prompt test on log #2 (normal HTTP traffic)

  * Output: Correctly marked as non-suspicious, severity 0/10, with passive recommendations
* Ran prompt test on a batch of 8 logs

  * Output: Structured table identifying suspicious entries, threat types, and mitigation strategies
  * Confirmed ability to handle multi-log triage and prioritize incidents
* Ran prompt test #4 to test structured JSON output

  * Output: AI returned clean JSON for a suspicious SNMP log with proper severity and classification

✅ Validated prompt for API automation in next development phase

---

**🧠 Observations & Lessons Learned:**

* Prompt format greatly affects response clarity — adding structure improves accuracy
* Batch prompts are effective and scalable; useful for triage use cases
* JSON output will make integration into Python pipeline and Streamlit dashboard seamless
* GitHub can be deferred until end-of-week push to focus on progress

---

**📌 Next Steps (Tomorrow):**
Begin Phase 2:

* Build Python script to:

  * Read logs from file
  * Send each line to LLM using finalized prompt
  * Parse and save structured output (e.g., JSON or DataFrame)
* Archive all successful prompt versions
* Start designing initial Streamlit dashboard layout (basic table + severity filter)

---

### 📅 May 9, 2025

**Total Hours Worked:** 4

---

**Tasks Completed:**

* Watched instructional videos and tutorials on Visual Studio Code and basic Python scripting to build foundational understanding for the project
* Installed and explored VS Code interface, extensions (including JSON formatting), and project navigation tools
* Learned about `.json` file handling, Python indentation rules, and terminal usage inside VS Code
* Created and initialized GitHub repository for the “AI-Driven Threat Detection Dashboard” project
* Practiced formatting and validating JSON data in preparation for log analysis and UI integration

---

**Note:**
Time was primarily focused on learning and environment setup. These steps were essential for becoming comfortable with the tools required to build, test, and maintain the AI-driven cybersecurity dashboard.

---

### 📅 May 10, 2025

**Total Hours Worked:** 4

---

**Tasks Completed:**

* Generated 10 additional diverse simulated firewall/IDS log entries to expand the project’s testing dataset (`sample_logs_batch2.txt`)
* Used ChatGPT (GPT-4o) to analyze all 10 log entries in a single batch using a structured prompt for threat classification, severity scoring, and recommended responses
* Reviewed and validated the AI-generated output for consistency and realism
* Saved the structured results in a well-formatted JSON file (`log_analysis_results_batch2.json`) for future backend processing and dashboard display
* Created and organized project folders using Visual Studio Code, including `/data/` for storing logs and results
* Verified functionality of JSON formatting tools and began working comfortably within VS Code
* Troubleshot and resolved Python installation and PATH configuration issues on Windows (1.5 hours)
* Verified successful Python installation in VS Code and terminal environments
* Created `/src/` subfolder and added initial script file (`log_analyzer.py`) for log analysis
* Updated the Python script to simulate AI-based threat classification using random logic
* Corrected broken relative paths in file references to align with project structure
* Successfully ran the Python script to read sample logs and write a structured JSON output file (`simulated_output.json`)
* Validated output structure and ensured script output could be used for future dashboard integration
* Continued using and gaining familiarity with VS Code’s folder management, terminal, and JSON editing tools

---

### 📅 May 11–12, 2025

**Total Hours Worked:** 4

---

**Tasks Completed:**

* Refined and restructured the log analysis Python script (`log_analyzer.py`) to more accurately simulate AI-powered threat classification
* Rebuilt rule-based classification logic to identify threats based on both `DPT` port numbers and key phrases in the log message (`MSG`)
* Added proper handling for common attack vectors including SSH brute force, RDP login attempts, SMB probing, Telnet, FTP, and SNMP scans
* Implemented fallback handling for DNS, HTTP, HTTPS, and benign web crawler traffic
* Enhanced threat detection output with specific severity levels and actionable recommendations
* Validated accuracy of the final `simulated_output.json` file and confirmed alignment with intended classifications
* Debugged minor print formatting issues and improved the quality and realism of the output for use in a future dashboard

---

### 📅 May 11, 2025

**Total Hours Worked:** 6.5

---

**Tasks Completed:**


| Area                                | Work Completed                                                                                                                                                                                                                                                                                                                                                                                          |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Streamlit Dashboard (front‑end)** | • Built a clean **dashboard/dashboard.py** from scratch.<br> – Page config + 30 s auto‑refresh.<br> – Sidebar severity slider & threat‑type multiselect.<br> – Color‑coded table (Styler) plus pie‑ and bar‑charts.<br> – Download buttons for filtered logs (CSV / JSON).<br> – Compatible with older pandas versions (removed `names=` argument).                                                     |
| **Log Generation Script**           | • Created a simplified **src/log\_streamer.py** that writes fully‑structured test logs to **data/simulated\_output.json** every 15 s.<br> – Fixed absolute‑path logic so it always targets the project’s `/data` folder.<br> – Replaced deprecated `datetime.utcnow()` with `datetime.now(timezone.utc)` to eliminate warnings.<br> – Verified console output (“• appended”) and confirmed file growth. |
| **Troubleshooting / Debugging**     | • Resolved mismatched file paths (`live_logs.jsonl` vs `simulated_output.json`).<br>• Diagnosed silent output by adding diagnostic prints.<br>• Fixed pandas compatibility error (`reset_index(names=…)`).<br>• Ensured Streamlit refreshes successfully and shows updated counts.                                                                                                                      |
| **Project Direction & Planning**    | • Stepped back to clarify ultimate goal: **AI‑augmented SOC dashboard** that ingests raw logs, classifies & explains them via an LLM, and presents results in real time.<br>• Outlined remaining milestones (rule‑based real‑time analyzer → LLM integration → polish → deployment).                                                                                                                    |
| **Housekeeping**                    | • Updated code comments, removed unused imports, and confirmed folder structure in version control.                                                                                                                                                                                                                                                                                                     |
Outstanding / Next Up

Insert analysis layer – first rule‑based, then LM Studio LLM, so the dashboard ingests raw logs instead of pre‑classified ones.

Add keyword search box and timeline sorting to the UI.

Begin setting up LM Studio endpoint for local LLM testing.
# Tag Audit Tool

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/) 
[![Streamlit](https://img.shields.io/badge/Streamlit-App-red.svg)](https://streamlit.io/) 
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A **Streamlit-based HAR analyzer** for auditing pre-consent requests, cookies, and tag chains — with **Diff Mode** to isolate what happens when individual tags are enabled.  
Built for **consent compliance auditing** (GDPR, CCPA) and **GTM tag troubleshooting**.

---

## ✨ Features

- 📂 **Upload HAR files** (from Chrome, Edge, Firefox DevTools)
- 🏷️ **Automatic request categorization** with color-coded rows:
  - **XHR** (purple), **JS** (amber), **CSS** (blue), **Img** (green), **Media** (pink), **Other** (gray), **Errors** (red)
- 🛡️ **Consent compliance checks**:
  - Detect pre-consent requests (scripts fired before user action)
  - Flag policy violations & high-risk activity
  - Identify cookies dropped before consent
  - Trace tag chains (e.g., GTM → DoubleClick → Ads)
- 📊 **Exports**:
  - CSV (raw requests)
  - Excel (colored rows + legend tab)
  - PDF (colored, print-friendly)
  - Compliance XLSX/PDF (summary reports)
  - One-page breakdown PDF (executive summary)
  - Evidence Pack ZIP (HAR + all reports + policy.yml snapshot)
- 🧩 **Policy.yml support**:
  - Allow/deny rules for domains, categories, and purposes
- 🔄 **Diff Mode**:
  - Compare **Baseline HAR** (tags paused) vs **Test HAR** (one tag enabled)
  - Export reports showing only what changed:
    - Requests vs Baseline (Added)
    - Cookies vs Baseline (Added)
    - Tag Chains vs Baseline (Added)

---

## 🚀 Installation

Clone the repo and install dependencies:

```bash
git clone https://github.com/curthayman/tag-audit-tool.git
cd tag-audit-tool
pip install -r requirements.txt
```
## ▶️ Usage

Run the Streamlit app:

```streamlit run har_viewer.py```

Then open your browser (default: http://localhost:8501).
# Standard Workflow
1.	Export a HAR
Chrome/Edge/Firefox → DevTools → Network tab → ⋯ → Save all as HAR
2. Upload HAR in the sidebar
3.	Browse requests & violations in the main viewer
4.	Export reports (CSV, Excel, PDF, Evidence Pack)

# Diff Mode Workflow

For auditing individual GTM tags:
1.	Pause all tags in GTM → Preview → export HAR → baseline.har
2.	Enable one tag → Preview → export HAR → tagname.har
3.	Upload both files in Diff Mode
4.	Export Diff PDF/XLSX to see only what changed

## 📂 Project Structure

```
├── har_viewer.py        # Main Streamlit app
├── requirements.txt     # Dependencies
├── policy.yml           # Example compliance policy
├── README.md            # Documentation
└── screenshots/         # Example UI screenshots
```
⚖️ Compliance Use Case

This tool helps companies prove tags are not firing before consent.
By analyzing HARs pre- and post-consent (or baseline vs test tags), you can generate audit-grade evidence for GDPR/CCPA compliance.

✅ Identify violations (red rows)

✅ Detect cookies set before consent

✅ Trace tag chains and piggybacking behavior

✅ Export Evidence Pack ZIP for auditors & legal

## 🔮 Roadmap

- CLI mode for bulk HAR scanning
- Cookie diff with expiry/domain insights
- Visual tag chain graphs
- Docker & Streamlit Cloud deployment templates

## 📜 License

MIT License – use freely in your projects.
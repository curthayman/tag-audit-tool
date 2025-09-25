# Tag-Audit Tool (HAR Analyzer)

A **Streamlit** web app for auditing HAR (HTTP Archive) files with a focus on **consent compliance**.  
It detects **pre-consent** requests, classifies **tags & cookies** (with a built-in policy that marks common Google surfaces as **Essential**), visualizes **tag chains**, and exports **CSV / Excel / PDF** reports. Includes a **Diff Mode** for comparing “baseline” vs “test” HARs (perfect for GTM tag enablement testing).

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.36%2B-FF4B4B?logo=streamlit&logoColor=white)
![Pandas](https://img.shields.io/badge/Pandas-2.2%2B-150458?logo=pandas&logoColor=white)
![ReportLab](https://img.shields.io/badge/ReportLab-4.1%2B-orange)
![XlsxWriter](https://img.shields.io/badge/XlsxWriter-3.2%2B-44B78B)
![PyYAML](https://img.shields.io/badge/PyYAML-6.0%2B-yellow)
![Pillow](https://img.shields.io/badge/Pillow-10.3%2B-green)

---

## ✨ Highlights

- **Single & Diff Modes**
  - Upload one HAR, or compare **Baseline (all tags paused)** vs **Test (tag enabled)**.
- **Consent Boundary**
  - Adjustable “Seq #” cutoff; anything **before** boundary is **pre-consent**.
- **Built-in Policy (toggle)**
  - Common **Google Analytics / Tag Manager / Ads / Platform** domains & cookies are classified **Essential** out of the box (toggle in sidebar).
  - Everything else defaults to **Non-Essential** unless it matches a rule.
- **Requests Table**
  - Columns: `Seq #, Name (URL), Status, Type, Category, PolicyCat, Essential, PreConsent, Violation, Started at, Size, Time`.
  - **Violation** = `PreConsent==True` **AND** `Essential==False`.
- **Cookies (3 sources)**
  - Response **Set-Cookie** headers.
  - **Inferred** from request `Cookie` headers (when browsers redact response cookies).
  - **Heuristic JS** scans (e.g., `document.cookie="name=…"`, `setCookie('name',…)`).
- **Tag Chains + Top Parents**
  - Builds **parent→child** relationships using initiator/stack or `Referer`.
  - Robust lookup by **full URL AND host** (host+URL matching) to keep chains accurate.
  - “Top Parents” ranks scripts that spawn the most children & violations.
- **Coloring**
  - Streamlit tables and Excel: category shading; **red** for violations; **amber** for **pre-consent but Essential** (allowed by policy).
  - PDF export shades **Violation** rows red and pre-consent Essential rows amber in Cookies table.
- **Exports**
  - **CSV** (requests only).
  - **Excel**: multi-sheet (`HAR`, `Cookies - Summary`, `Tag Chains`, `Top Parents`, `Legend`) with colors.
  - **PDF**: concise, landscape, colored tables for requests & cookies.
- **Chrome/Edge HAR Cookie Warning**
  - HARs from those browsers often **redact Cookie headers**; the UI warns and relies on inferred/JS heuristics if needed.

---

## 📦 Installation

```bash
git clone https://github.com/curthayman/tag-audit-tool.git
cd tag-audit-tool
pip install -r requirements.txt
```

```requirements.txt` (summary): `streamlit`, `pandas`, `numpy`, `python-dateutil`, `pytz`, `reportlab`, `XlsxWriter`, `PyYAML`, `Pillow`.```

---

## ▶️ Run

```bash
streamlit run har_viewer.py
```

- App opens at http://localhost:8501
- In the **sidebar**:
  - Toggle **Diff Mode** if you want to compare two HARs.
  - **Use built-in Google Essential policy** (ON by default).
  - Set **Consent Boundary (Seq #)**. If kept huge, the app tries to estimate it.

---

## 🧭 Workflow

### Single HAR
1. Export a HAR: **DevTools → Network → ⋯ → Save all as HAR** (tip: enable “Preserve log”).
2. Upload the file in the sidebar.
3. Adjust **Consent Boundary** to when the user actually accepted consent.
4. Review:
   - **Requests**: red = **pre-consent & Non-Essential** (violations).
   - **Cookies**: from Set-Cookie, inferred request Cookie, and heuristic JS writes.
   - **Tag Chains**: which parent script loaded which child; pre-consent & violations highlighted.
   - **Top Parents**: who’s spawning the most children/violations.

### Diff Mode (Baseline vs Test)
- Baseline HAR: all tags **paused** in GTM.
- Test HAR: **enable one tag**, record again.
- The app shows **Requests: Added vs Baseline**, **Cookies: Added vs Baseline**, plus **Tag Chains (Added)** filtered to only children that came in with the added requests (using **URL+host** keys).

---

## 🧩 How Classification Works

- **URL/Domain rules**: If request host matches a known suffix (e.g., `googletagmanager.com`), it’s assigned `PolicyCat="Tag Manager"` and `Essential=True`.
- **Cookie rules**: Cookie name glob patterns (e.g., `_ga`, `_ga_*`, `__Secure-*`) or cookie domain suffixes map to a `PolicyCat` and `Essential`.
- **Built-in policy** is **enabled by default**. Toggle it off in the sidebar if you want a strict/neutral view.
- Anything not matching a rule is `PolicyCat="Unknown"` and `Essential=False` by default.

> Want to change defaults? Edit the two lists in `har_viewer.py`:
> - `DEFAULT_POLICY_DOMAINS` (domain suffix, category, essential)
> - `DEFAULT_POLICY_COOKIES` (cookie name/glob, category, essential)

---

## 🎨 Colors & Meanings

- **Requests (table & Excel)**
  - Category colors (JS/CSS/XHR/Img/Media/Other/Error).
  - **Red row** = **Violation** = (PreConsent=True & Essential=False).
- **Cookies**
  - **Red row** = violation (pre-consent & non-essential).
  - **Amber row** = **pre-consent, but Essential** (allowed by policy).
- **PDF**
  - Requests: violation rows shaded red.
  - Cookies: violations red; pre-consent essential amber.

Legend is included as an Excel tab.

---

## 📤 Exports

- **CSV**: `har_export.csv` (or `diff_requests_added.csv`).
- **Excel** (`.xlsx`):
  - `HAR`: requests with policy columns and row coloring.
  - `Cookies - Summary`: combined sources (Set-Cookie / Inferred / JS Heuristic), policy columns, coloring.
  - `Tag Chains`: parent→child edges, with policy & consent flags (colored).
  - `Top Parents`: parent summary (count, pre-consent count, violations, min seq).
  - `Legend`.
- **PDF**:
  - Landscape report with colored rows and soft-wrapped URLs.

---

## 🧪 Tips for Accurate Cookie Evidence

- **Firefox** HARs usually include `Set-Cookie` details.  
  Chrome/Edge often **redact** Cookie headers in HAR files (you’ll see a warning in the app).  
  If you must use Chrome/Edge, the app still attempts to infer cookies via:
  - request `Cookie` headers, and
  - heuristic scans for JS cookie writes in downloaded scripts.

For the strongest evidence, use **Firefox** *or* a proxy capture (mitmproxy/Fiddler/Charles).

---

## 🔍 Troubleshooting

- **“Why are all these Google rows red?”**  
  Make sure **Use built-in Google Essential policy** is **ON**. If OFF, everything not matching your own rules is treated as non-essential.
- **No cookies in report**  
  Likely a Chrome/Edge HAR with redactions. Try **Firefox** or rely on **Diff Mode** + **Tag Chains** to show what loads when a tag is enabled.
- **Excel says “URL exceeds maximum length”**  
  The app writes with `XlsxWriter` and disables automatic URL detection to avoid this. You’re covered.
- **PDF truncates long URLs**  
  We insert wrap points and allow soft-wrapping; if you still have massive URLs, use the Excel export for full detail.

---

## 🗂️ Project Structure

```
.
├── har_viewer.py         # Main Streamlit app (single + diff + exports)
├── requirements.txt      # Dependencies
├── README.md             # This file
└── Screenshot.png        # Optional UI screenshot
```

---

## 🛡️ What Counts as a Violation?

A row is a **violation** when:
- It occurs **before** the **Consent Boundary** (i.e., `Seq # < boundary`), **and**
- Its **Essential** flag is **False** (per policy rules).

**Adjust the boundary** to the exact point the user clicked “Accept” in your capture.

---

## 📅 Roadmap (nice-to-haves)

- Import policy from YAML and write back updated rules
- First-party vs third-party clarity per page host
- Bulk CLI for folders of HAR files

---

## 📜 License

MIT — use freely. Contributions welcome!

# har_viewer.py
# Full-featured HAR viewer & consent compliance scanner with Diff Mode (Differences vs Baseline)

import io
import json
import re
import zipfile
import string
from datetime import datetime
from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse, parse_qs

import pandas as pd
import streamlit as st

from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, A4, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer

# Excel export engine
import xlsxwriter  # noqa: F401

# For safe HTML escaping in PDFs
from html import escape as html_escape

# Optional YAML for policy
try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None

# -------------------- TOGGLE: Diff Mode (enabled) --------------------
ENABLE_DIFF_MODE = True

# -------------------- Interpretation Guide --------------------
INTERPRET_GUIDE = """# Consent Compliance Report – How to Read

This report analyzes a HAR (HTTP Archive) to check whether **scripts, tags, or cookies are firing before user consent** is collected.

---

## 1) Status Summary
- **Total** – number of requests captured in the HAR.
- **Pre-consent** – how many fired **before** a consent signal was seen.
- **Violations** – non-essential requests (ads, analytics, marketing, social) that ran before consent.
- **PASS/FAIL** – fails if any high-risk policy violations were detected.

---

## 2) Main Request Table
- **Seq #** – order of execution (lower = earlier).
- **Name** – request URL (soft-wrapped in PDFs).
- **Category** – JS, CSS, Img, XHR, Other, etc.
- **Purpose** – inferred: Analytics, Ads, Social, Heatmap, Marketing, TagMgr, CMP, Other.
- **Party** – 1P vs 3P (based on site domain).
- **PreConsent** – TRUE if fired before consent.
- **Violation** – TRUE if non-essential + PreConsent=TRUE.
- **HighRisk** – policy-sensitive (e.g., block_until_consent or strict mode).
- **Rule** – policy.yml pattern that matched.

---

## 3) Violation Colors
- 🔴 **Red rows** – High-Risk requests that fired **before consent**.
- 🟢 **Green** – Allowed (post-consent or allowlisted).
- 🟣 **Purple** – Tag Manager/container scripts (may cascade).
- ⚫ **Gray** – First-party / essential utilities.
- Other colors = resource type context (JS/CSS/Img/etc.).

---

## 4) Tag Chains
Who fired what: **Parent (initiator) → Child** with Purpose, Count, PreConsent %, FirstSeq. Use this to prove **piggybacking**.

---

## 5) Cookies set before consent
Cookie name, purpose, domain, first sequence, and times set.

---

## 6) Policy (policy.yml)
- **allow**: strictly necessary allow-list.
- **block_until_consent**: must not run before consent.
- **purpose_overrides**: set purpose for URL patterns or hosts.
- **cookie_overrides**: set purpose for cookie names.

---

## 7) Evidence Pack (ZIP)
All exports, original HAR, tag-chain JSON, cookie dump, and a interpretation guide.
"""

# -------------------- Categories & colors --------------------
CATEGORY_ORDER = ["All", "XHR", "JS", "CSS", "Img", "Media", "Other", "Errors", "High-Risk"]

CATEGORY_COLORS = {
    "XHR":   "#6D5DD3",
    "JS":    "#E3B341",
    "CSS":   "#3BA3FF",
    "Img":   "#27C2A0",
    "Media": "#D3558E",
    "Other": "#7A8898",
    "Errors":"#E2544B",
}
FALLBACK_COLOR = "#7A8898"

PURPOSE_COLORS = {
    "Analytics": "#34a853",
    "Ads": "#ea4335",
    "Social": "#4285f4",
    "Heatmap": "#fbbc05",
    "Marketing": "#9c27b0",
    "TagMgr": "#5e6ad2",
    "CMP": "#00bcd4",
    "Other": "#7A8898",
}

PURPOSE_MAP: Dict[str, List[str]] = {
    "Analytics": [
        "google-analytics.com","analytics.google.com","/g/collect","stats.g.doubleclick.net",
        "clarity.ms","mixpanel.com","cdn.segment.com","segment.io","segment.com","plausible.io",
        "hs-analytics.net","hs-scripts.com","matomo","quantserve.com","omtrdc.net",
        "snowplow","newrelic.com","datadoghq","loggly.com","hotjar.com","fullstory.com",
    ],
    "Ads": [
        "doubleclick.net","googlesyndication.com","adservice.google","googleadservices.com",
        "facebook.com/tr","connect.facebook.net","ads.linkedin.com","snap.licdn.com",
        "tiktok.com","adsrvr.org","crwdcntrl.net","taboola.com","outbrain.com","adroll.com",
        "bing.com","bat.bing.com"
    ],
    "Social": [
        "connect.facebook.net","platform.twitter.com","staticxx.facebook.com",
        "linkedin.com/li/track","snap.licdn.com","instagram.com","assets.pinterest.com"
    ],
    "Heatmap": ["hotjar.com","static.hotjar.com","script.hotjar.com","fullstory.com","mouseflow.com","crazyegg.com"],
    "Marketing": [
        "hubspot.com","hs-scripts.com","pardot.com","marketo.net","intercom.io",
        "drift.com","mailchimp.com","onesignal.com","braze.com","branch.io"
    ],
    "TagMgr": ["googletagmanager.com","tealiumiq.com","adobedtm.com","ensighten.com","tags.tiqcdn.com","assets.adobedtm.com"],
    "CMP": ["onetrust","osano","cookiebot","consentmanager","didomi","sourcepoint","trustarc","iubenda","cookieyes","consensu.org"],
}

CONSENT_COOKIES = [
    "OptanonConsent","OptanonAlertBoxClosed","cookieyes-consent","euconsent-v2",
    "didomi_token","didomi_prefs","sp_consent","sp_choice","cmplz_consent_status",
    "Osano_consentmanager","osano_consentmanager","cookieconsent_status","cc_cookie",
]

COOKIE_PURPOSE = {
    r"(^|_)ga($|_|-)": "Analytics",
    r"(^|_)gid$": "Analytics",
    r"(^|_)gac_": "Analytics",
    r"(^|_)gat": "Analytics",
    r"(^|_)gcl_": "Marketing",
    r"(^|_)fbp$": "Marketing",
    r"(^|_)fr$": "Marketing",
    r"(^|_)uet": "Marketing",
    r"(^|_)li_": "Marketing",
    r"(^|_)tt_": "Marketing",
    r"(^|_)twq": "Marketing",
    r"(^|_)scid$": "Marketing",
    r"(^|_)hubspotutk$": "Marketing",
    r"(^|_)__hstc$": "Marketing",
    r"(^|_)__hssc$": "Marketing",
    r"(^|_)clck$": "Analytics",
    r"(^|_)clsk$": "Analytics",
    r"(^|_)hj": "Analytics",
    r"(^|_)ajs_": "Analytics",
    r"(^|_)mp_": "Analytics",
    r"(^|_)dd_": "Analytics",
    r"(^|_)NRAGENT$": "Analytics",
}

# -------------------- Soft-wrap helper for PDFs (SOFT HYPHEN) --------------------
def _soft_wrap_text(s: str, max_len: int = 800) -> str:
    if s is None:
        return ""
    s = str(s)
    SH = "\u00AD"
    s = re.sub(r"([\/\?\&\=\:\#\.\_\-])", r"\1" + SH, s)
    s = re.sub(r"([A-Za-z0-9]{12})(?=[A-Za-z0-9])", r"\1" + SH, s)
    if len(s) > max_len:
        s = s[: max_len - 1] + "…"
    s = "".join(ch for ch in s if ord(ch) >= 0x20)
    return s

# -------------------- Helpers --------------------
def human_size(bytes_val: int) -> str:
    if bytes_val is None or bytes_val < 0:
        return "-"
    units = ["B", "kB", "MB", "GB", "TB"]
    size = float(bytes_val); i = 0
    while size >= 1024 and i < len(units) - 1:
        size /= 1024.0; i += 1
    return f"{size:.1f}{units[i]}" if i > 0 else f"{int(size)}{units[i]}"

def parse_datetime(dt_str: str) -> Tuple[str, float]:
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        ts_ms = dt.timestamp() * 1000.0
        disp = dt.astimezone().strftime("%I:%M:%S %p").lstrip("0")
        return disp, ts_ms
    except Exception:
        return "-", 0.0

def infer_category(mime: str, url: str, method: str, status: int) -> str:
    if isinstance(status, int) and status >= 400:
        return "Errors"
    mime = (mime or "").lower()
    url = (url or "").lower()
    if "xhr" in mime or "json" in mime:
        return "XHR"
    if mime.startswith("text/javascript") or mime.endswith("/javascript") or url.endswith(".js"):
        return "JS"
    if mime.startswith("text/css") or url.endswith(".css"):
        return "CSS"
    if any(url.endswith(ext) for ext in (".png",".jpg",".jpeg",".gif",".webp",".svg",".ico")) or "image/" in mime:
        return "Img"
    if any(x in mime for x in ("video/", "audio/")) or any(ext in url for ext in (".mp4",".webm",".mp3",".wav",".m4a",".mov",".mkv",".ogg",".ogv")):
        return "Media"
    return "Other"

def infer_purpose(url: str) -> str:
    u = (url or "").lower()
    for purpose, needles in PURPOSE_MAP.items():
        for n in needles:
            if n in u:
                return purpose
    return "Other"

def host_from_url(url: str) -> str:
    try:
        return urlparse(url).netloc or ""
    except Exception:
        return ""

def parse_set_cookie_headers(res: Dict[str, Any]) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for h in res.get("headers", []) or []:
        if (h.get("name") or "").lower() != "set-cookie":
            continue
        val = h.get("value") or ""
        m = re.match(r"^\s*([^=;\s]+)\s*=", val)
        if not m:
            continue
        name = m.group(1)
        mdom = re.search(r"(?i)\bdomain=([^;,\s]+)", val)
        domain = mdom.group(1) if mdom else ""
        out.append((name, domain))
    return out

def collect_response_cookies(res: Dict[str, Any], fallback_host: str) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    for c in res.get("cookies", []) or []:
        name = c.get("name") or ""
        domain = c.get("domain") or fallback_host
        if name:
            pairs.append((name, domain))
    pairs.extend(parse_set_cookie_headers(res))
    seen = set(); uniq: List[Tuple[str, str]] = []
    for name, dom in pairs:
        key = (name, dom or fallback_host)
        if key in seen: continue
        seen.add(key)
        uniq.append((name, dom or fallback_host))
    return uniq

def classify_cookie(name: str) -> str:
    for pat, label in COOKIE_PURPOSE.items():
        if re.search(pat, name, flags=re.I):
            return label
    return "Unknown"

def has_gcm_hint(url: str) -> bool:
    try:
        q = parse_qs(urlparse(url).query)
        return any(k in q for k in ("gcs","gcd","npa","gclid"))
    except Exception:
        return False

def etld1(host: str) -> str:
    host = (host or "").split(":")[0]
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host

# -------------------- HAR parsing --------------------
def _initiator_url_from_har(entry: dict) -> str:
    try:
        init = entry.get("_initiator") or entry.get("initiator") or {}
        stack = init.get("stack") or {}
        frames = stack.get("callFrames") or []
        for cf in frames:
            u = (cf.get("url") or "").strip()
            if u and not u.startswith("chrome-extension://"):
                return u
        if isinstance(init, dict):
            u = (init.get("url") or "").strip()
            if u:
                return u
    except Exception:
        pass
    try:
        for h in (entry.get("request", {}) or {}).get("headers", []) or []:
            if (h.get("name") or "").lower() == "referer":
                v = (h.get("value") or "").strip()
                if v:
                    return v
    except Exception:
        pass
    return ""

def extract_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    req = entry.get("request", {}) or {}
    res = entry.get("response", {}) or {}
    content = res.get("content", {}) or {}
    mime = content.get("mimeType") or res.get("mimeType") or ""
    url = req.get("url", "") or ""
    status = res.get("status", 0)
    started_str = entry.get("startedDateTime", "") or ""
    started_disp, started_ms = parse_datetime(started_str)

    body_size = res.get("bodySize", None)
    transfer_size = res.get("_transferSize", None)
    content_size = content.get("size", None)
    size_guess = next((v for v in (transfer_size, body_size, content_size) if isinstance(v, int)), None)

    cat = infer_category(mime, url, req.get("method", ""), status)
    purpose = infer_purpose(url)
    host = host_from_url(url)

    initiator_url = _initiator_url_from_har(entry)
    initiator_host = host_from_url(initiator_url) if initiator_url else ""

    cookie_pairs = collect_response_cookies(res, host)
    cookie_names = [n for (n, _d) in cookie_pairs]

    return {
        "Seq #": 0,
        "Name": url,
        "Host": host,
        "InitiatorURL": initiator_url,
        "InitiatorHost": initiator_host,
        "Status": status,
        "Type": mime or "-",
        "Started at": started_disp,
        "Started_ms": started_ms,
        "Size": human_size(size_guess) if size_guess is not None else "-",
        "Time": f"{int(round(entry.get('time', 0)))}ms",
        "Category": cat,
        "Purpose": purpose,
        "ColorHex": CATEGORY_COLORS.get(cat, FALLBACK_COLOR),
        "PurposeColor": PURPOSE_COLORS.get(purpose, PURPOSE_COLORS["Other"]),
        "HasConsentCookie": any((n in CONSENT_COOKIES) for n in cookie_names),
        "CookiesSet": cookie_pairs,
        "CookiesSetNames": ";".join(cookie_names),
        "CookiePurposeHint": ";".join(sorted({classify_cookie(n) for n in cookie_names if n})),
        "ConsentModeHint": has_gcm_hint(url),
        "RawTimeMs": entry.get("time", 0),
        "SizeBytes": size_guess if (isinstance(size_guess, int) and size_guess >= 0) else None,
        "Started_ts": started_str,
    }

def har_to_df(har_obj: Dict[str, Any]) -> pd.DataFrame:
    entries = (har_obj or {}).get("log", {}).get("entries", []) or []
    rows = [extract_entry(e) for e in entries]
    df = pd.DataFrame(rows)
    if len(df):
        df = df.sort_values(by=["Started_ms","RawTimeMs"], kind="stable").reset_index(drop=True)
        df["Seq #"] = range(1, len(df) + 1)
    return df

# -------------------- Site domain, party, filters --------------------
def site_domain_from_har(df: pd.DataFrame) -> str:
    try:
        from urllib.parse import urlparse as _u
        htmls = df[(df["Status"] == 200) & df["Type"].str.contains("text/html", na=False)]
        if len(htmls):
            return etld1(_u(htmls.iloc[0]["Name"]).netloc)
        return etld1(_u(df.iloc[0]["Name"]).netloc)
    except Exception:
        return ""

def mark_party(df: pd.DataFrame) -> pd.DataFrame:
    dom = site_domain_from_har(df)
    df = df.copy()
    def _party(h: str) -> str:
        if not dom:
            return "Unknown"
        return "1P" if etld1(h).endswith(dom) else "3P"
    df["Party"] = df["Host"].apply(_party)
    return df

def filter_df(df: pd.DataFrame, category: str) -> pd.DataFrame:
    if category == "All":
        return df
    if category == "High-Risk":
        return df[df["HighRisk"] == True]  # noqa: E712
    return df[df["Category"] == category]

# -------------------- Consent window & flags --------------------
def detect_consent_time_ms(df: pd.DataFrame) -> Tuple[bool, float]:
    consent_rows = df[df["HasConsentCookie"] == True]  # noqa: E712
    if len(consent_rows):
        return True, float(consent_rows["Started_ms"].min())
    return False, float("inf")

def mark_preconsent(df: pd.DataFrame, assume_no_consent_if_unknown: bool) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    df = df.copy()
    found, consent_ms = detect_consent_time_ms(df)
    page_start_ms = float(df["Started_ms"].min()) if len(df) else 0.0
    if not found:
        df["PreConsent"] = True if assume_no_consent_if_unknown else False
    else:
        df["PreConsent"] = df["Started_ms"] < consent_ms
    non_essential = df["Purpose"].isin(["Analytics","Ads","Social","Heatmap","Marketing"])
    df["Violation"] = df["PreConsent"] & non_essential
    meta = {
        "has_consent": found,
        "consent_ms": None if not found else consent_ms,
        "page_start_ms": page_start_ms,
        "preconsent_window_ms": None if not found else max(0, consent_ms - page_start_ms),
    }
    return df, meta

# -------------------- Rules engine --------------------
DEFAULT_RULES = {
    "allow": [],
    "block_until_consent": [],
    "purpose_overrides": {},
    "cookie_overrides": {},
}

def load_rules_from_text(text: str) -> Dict[str, Any]:
    if not yaml:
        return DEFAULT_RULES.copy()
    try:
        data = yaml.safe_load(text) or {}
        for k in DEFAULT_RULES:
            data.setdefault(k, DEFAULT_RULES[k])
        return data
    except Exception:
        return DEFAULT_RULES.copy()

def match_any(url: str, patterns: List[str]) -> str | None:
    for pat in patterns or []:
        try:
            if re.search(pat, url, flags=re.I):
                return pat
        except re.error:
            continue
    return None

def apply_policy(df: pd.DataFrame, rules: Dict[str, Any], strict_mode: bool) -> pd.DataFrame:
    df = df.copy()

    # Purpose overrides for requests
    for pat, purpose in (rules.get("purpose_overrides") or {}).items():
        try:
            mask = df["Name"].str.contains(pat, case=False, regex=True, na=False)
            df.loc[mask, "Purpose"] = purpose
        except re.error:
            continue

    # Cookie purpose overrides
    if "cookie_overrides" in rules:
        def _cookie_hint(names: str) -> str:
            parts = (names or "").split(";")
            labels = set()
            for n in parts:
                n = n.strip()
                if not n: continue
                lab = None
                for pat, pv in rules["cookie_overrides"].items():
                    try:
                        if re.search(pat, n, flags=re.I):
                            lab = pv; break
                    except re.error:
                        continue
                if not lab:
                    lab = classify_cookie(n)
                labels.add(lab)
            return ";".join(sorted([l for l in labels if l]))
        df["CookiePurposeHint"] = df["CookiesSetNames"].apply(_cookie_hint)

    hit_allow = df["Name"].apply(lambda u: match_any(u, rules.get("allow")))
    hit_block = df["Name"].apply(lambda u: match_any(u, rules.get("block_until_consent")))

    df["Rule"] = hit_allow.combine_first(hit_block).fillna("")

    # HighRisk:
    df["HighRisk"] = (
        (df["PreConsent"] & hit_block.notna()) |
        (strict_mode & df["PreConsent"] & (df["Party"] == "3P") & hit_allow.isna())
    )

    # Allowed:
    df["Allowed"] = (
        hit_allow.notna() |
        (~df["PreConsent"]) |
        (hit_block.isna() & (~(strict_mode & (df["Party"] == "3P"))))
    )
    return df

# -------------------- Cookies (pre-consent summary) --------------------
def preconsent_cookie_summary(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    seen_first: Dict[Tuple[str, str], Tuple[int, float]] = {}
    counts: Dict[Tuple[str, str], int] = {}
    purposes: Dict[Tuple[str, str], str] = {}

    for _, r in df[df["PreConsent"] == True].iterrows():  # noqa: E712
        pairs: List[Tuple[str, str]] = r.get("CookiesSet", []) or []
        for name, dom in pairs:
            if not name: continue
            if name in CONSENT_COOKIES:
                continue
            key = (name, dom or r.get("Host", ""))
            counts[key] = counts.get(key, 0) + 1
            if key not in seen_first or r["Started_ms"] < seen_first[key][1]:
                seen_first[key] = (int(r["Seq #"]), r["Started_ms"])
            purposes[key] = purposes.get(key, classify_cookie(name))

    out = []
    for (name, dom), cnt in sorted(counts.items(), key=lambda x: (x[0][0].lower(), x[0][1])):
        seq = seen_first[(name, dom)][0] if (name, dom) in seen_first else ""
        out.append({"Cookie": name, "Purpose": purposes.get((name, dom), "Unknown"), "First Seq #": seq, "Domain": dom, "Times Set": cnt})
    return pd.DataFrame(out)

# -------------------- Tag Chains --------------------
def build_tag_graph(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    rows = []
    for _, r in df.iterrows():
        parent = (r.get("InitiatorHost") or "").strip()
        child = (r.get("Host") or "").strip()
        if not parent or not child:
            continue
        rows.append({
            "Parent": parent,
            "Child": child,
            "Seq #": int(r["Seq #"]),
            "PreConsent": bool(r["PreConsent"]),
            "Purpose": r.get("Purpose") or "Other"
        })

    edges_df = pd.DataFrame(rows)
    if edges_df.empty:
        return edges_df, edges_df

    agg = (
        edges_df
        .assign(PreConsentCount=lambda d: d["PreConsent"].astype(int))
        .groupby(["Parent", "Child", "Purpose"], as_index=False)
        .agg(Count=("Child", "size"), PreConsent=("PreConsentCount", "sum"), FirstSeq=("Seq #", "min"))
        .sort_values(["PreConsent", "Count", "FirstSeq"], ascending=[False, False, True])
    )
    return edges_df, agg

# -------------------- PDF helpers --------------------
def _pdf_cell_style(styles):
    return ParagraphStyle(
        "cell",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
        spaceAfter=0,
        spaceBefore=0,
        wordWrap="CJK",
        allowWidowsOrphans=1,
        splitLongWords=True,
    )

# -------------------- Exports: Generic PDF --------------------
def make_pdf(df: pd.DataFrame, title: str = "HAR Table Export") -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=24, rightMargin=24, topMargin=24, bottomMargin=24)
    styles = getSampleStyleSheet(); cell_style = _pdf_cell_style(styles)
    elems: List[Any] = []

    elems.append(Paragraph(title, styles["Heading2"]))
    elems.append(Spacer(1, 6))

    legend_data = [["Category", "Color"]] + [[c, ""] for c in ["XHR","JS","CSS","Img","Media","Other","Errors"]]
    legend = Table(legend_data, colWidths=[80, 60])
    ts = TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.black),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,0), 9),
        ("BOX", (0,0), (-1,-1), 0.25, colors.HexColor("#2A2F34")),
        ("GRID", (0,0), (-1,-1), 0.25, colors.HexColor("#2A2F34")),
        ("FONTSIZE", (0,1), (-1,-1), 8),
    ])
    for i, cat in enumerate(["XHR","JS","CSS","Img","Media","Other","Errors"], start=1):
        ts.add("BACKGROUND", (1,i), (1,i), colors.HexColor(CATEGORY_COLORS.get(cat, FALLBACK_COLOR)))
    legend.setStyle(ts)
    elems.append(legend)
    elems.append(Spacer(1, 10))

    cols = ["Seq #","Name","Status","Type","Started at","Size","Time","Category","Purpose","Party","PreConsent","Violation","HighRisk","Rule"]
    data = [cols]
    for _, row in df[cols].iterrows():
        data.append([
            str(row["Seq #"]),
            Paragraph(html_escape(_soft_wrap_text(row["Name"])), cell_style),
            str(row["Status"]),
            Paragraph(html_escape(_soft_wrap_text(row["Type"], max_len=200)), cell_style),
            str(row["Started at"]),
            str(row["Size"]),
            str(row["Time"]),
            str(row["Category"]),
            str(row["Purpose"]),
            str(row["Party"]),
            str(row["PreConsent"]),
            str(row["Violation"]),
            str(row["HighRisk"]),
            str(row["Rule"]),
        ])

    col_widths = [36, None, 42, 56, 56, 44, 44, 56, 58, 36, 56, 44, 44, 56]
    table = Table(data, repeatRows=1, colWidths=col_widths)
    base = TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.black),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,0), 10),
        ("GRID", (0,0), (-1,-1), 0.25, colors.HexColor("#2A2F34")),
        ("FONTSIZE", (0,1), (-1,-1), 8),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("ALIGN", (0,1), (0,-1), "CENTER"),
        ("LEFTPADDING", (0,1), (0,-1), 4),
        ("RIGHTPADDING", (0,1), (0,-1), 4),
        ("TEXTCOLOR", (0,1), (-1,-1), colors.HexColor("#0b0f14")),
    ])
    for i, cat in enumerate(df["Category"].tolist(), start=1):
        base.add("BACKGROUND", (0,i), (-1,i), colors.HexColor(CATEGORY_COLORS.get(cat, FALLBACK_COLOR)))
    table.setStyle(base)

    elems.append(table)
    doc.build(elems)
    buf.seek(0)
    return buf.read()

# -------------------- Exports: Excel (colored) --------------------
def make_xlsx(df: pd.DataFrame, title: str = "HAR Export") -> bytes:
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter", engine_kwargs={"options": {"strings_to_urls": False}}) as writer:
        cols = ["Seq #","Name","Status","Type","Started at","Size","Time","Category","Purpose","Party","PreConsent","Violation","HighRisk","Rule","CookiesSetNames"]
        df_x = df[cols].copy()

        def _trim_cell(val, lim=32760):
            if isinstance(val, str) and len(val) > lim:
                return val[:lim - 1] + "…"
            return val
        for c in df_x.select_dtypes(include="object").columns:
            df_x[c] = df_x[c].map(_trim_cell)

        df_x.to_excel(writer, sheet_name="HAR", index=False, startrow=1)
        wb = writer.book; ws = writer.sheets["HAR"]

        title_fmt = wb.add_format({"bold": True, "font_size": 14})
        ws.write(0, 0, title, title_fmt)

        header_fmt = wb.add_format({"bold": True, "bg_color": "#000000", "font_color": "#FFFFFF", "border": 1})
        for i, col in enumerate(df_x.columns):
            ws.write(1, i, col, header_fmt)

        widths = [8, 90, 8, 24, 14, 10, 10, 12, 14, 8, 12, 10, 10, 24, 26]
        for i, w in enumerate(widths):
            ws.set_column(i, i, w)

        ws.freeze_panes(2, 0)
        ws.autofilter(1, 0, 1 + len(df_x), len(df_x.columns) - 1)

        # Row coloring
        wb_fmt_cache = {}
        def fmt_for(cat: str):
            if cat not in wb_fmt_cache:
                wb_fmt_cache[cat] = wb.add_format({"bg_color": CATEGORY_COLORS.get(cat, FALLBACK_COLOR), "font_color": "#0b0f14"})
            return wb_fmt_cache[cat]
        start_row = 2
        for r, cat in enumerate(df["Category"].tolist()):
            ws.set_row(start_row + r, None, fmt_for(cat))

        # Legend
        legend = wb.add_worksheet("Legend")
        legend.write_row(0, 0, ["Category", "Color"], header_fmt)
        for i, cat in enumerate(["XHR","JS","CSS","Img","Media","Other","Errors"], start=1):
            legend.write(i, 0, cat)
            cell_fmt = wb.add_format({"bg_color": CATEGORY_COLORS.get(cat, FALLBACK_COLOR)})
            legend.write(i, 1, "", cell_fmt)
        legend.set_column(0, 0, 16); legend.set_column(1, 1, 12)

        # Tag Chains sheet (Top 15)
        try:
            edges_df, chains = build_tag_graph(df)
            if chains.empty:
                pd.DataFrame([{"Info": "No initiator information found in HAR."}]).to_excel(
                    writer, sheet_name="Tag Chains", index=False
                )
            else:
                cols_tc = ["Parent", "Child", "Purpose", "Count", "PreConsent", "FirstSeq"]
                top_tc = chains[cols_tc].head(15)
                top_tc.to_excel(writer, sheet_name="Tag Chains", index=False)

                ws_tc = writer.sheets["Tag Chains"]
                header_fmt2 = wb.add_format({"bold": True, "bg_color": "#000000", "font_color": "#FFFFFF", "border": 1})
                for i, col in enumerate(cols_tc):
                    ws_tc.write(0, i, col, header_fmt2)

                ws_tc.set_column(0, 0, 40)
                ws_tc.set_column(1, 1, 44)
                ws_tc.set_column(2, 2, 14)
                ws_tc.set_column(3, 5, 12)
        except Exception:
            pass

    output.seek(0)
    return output.read()

# -------------------- Compliance summary & One-Pager --------------------
def compliance_summary(df: pd.DataFrame, meta: Dict[str, Any]) -> Dict[str, Any]:
    total = len(df)
    pre = int(df["PreConsent"].sum())
    violations = df[df["Violation"] == True]  # noqa: E712
    highrisk = df[df["HighRisk"] == True]     # noqa: E712
    vcount = len(violations); hcount = len(highrisk)
    status = "PASS" if hcount == 0 else "FAIL"

    top_domains = (
        highrisk["Name"].str.extract(r"^(?:https?://)?([^/]+)", expand=False)
        .fillna("").value_counts().head(10).to_dict()
    )
    purpose_counts = highrisk["Purpose"].value_counts().to_dict()
    third_party_pre = df[(df["PreConsent"] == True) & (df["Party"] == "3P")]  # noqa: E712
    third_by_domain = third_party_pre["Host"].value_counts().head(15).to_dict()

    return {
        "total_requests": total,
        "preconsent_requests": pre,
        "violation_count": vcount,
        "highrisk_count": hcount,
        "status": status,
        "top_highrisk_domains": top_domains,
        "highrisk_purposes": purpose_counts,
        "preconsent_3p_domains": third_by_domain,
        "consent_window_ms": meta.get("preconsent_window_ms"),
        "has_consent": meta.get("has_consent"),
    }

def make_breakdown_pdf(summary: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter,
                            leftMargin=36, rightMargin=36,
                            topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    elems = []

    status = summary.get("status", "UNKNOWN")
    color = "red" if status == "FAIL" else "green"
    window = summary.get("consent_window_ms")
    window_txt = "Unknown" if window is None else f"{window/1000:.2f}s"

    text = f"""
    <b>Compliance Report – One Page Breakdown</b>

    <b>Overall Verdict:</b> Status = <font color="{color}">{status}</font>

    <b>Key Numbers:</b>
    - Total requests: {summary.get('total_requests')}
    - Pre-consent requests: {summary.get('preconsent_requests')}
    - Violations (generic): {summary.get('violation_count')}
    - High-Risk (policy): {summary.get('highrisk_count')}
    - Pre-consent window: {window_txt}

    <b>Interpretation:</b>
    Non-essential requests that fired before consent are flagged. High-Risk are policy-flagged pre-consent requests.

    <b>Sheets included:</b>
    - High-Risk, PreConsent Cookies, Tag Chains.

    <b>Next Steps:</b>
    - Block Tag Manager/marketing/analytics until consent.
    - Use Consent Mode (ad_storage='denied', analytics_storage='denied').
    - Retest aiming for Status = PASS with 0 High-Risk.
    """
    for para in text.strip().split("\n\n"):
        elems.append(Paragraph(para.strip(), styles["Normal"]))
        elems.append(Spacer(1, 12))

    doc.build(elems)
    buf.seek(0)
    return buf.read()

# -------------------- Compliance PDF --------------------
def make_report_pdf(df: pd.DataFrame, meta: Dict[str, Any], title: str = "Consent Compliance Report") -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=24, rightMargin=24, topMargin=24, bottomMargin=24)
    styles = getSampleStyleSheet(); cell_style = _pdf_cell_style(styles)
    elems: List[Any] = []

    summ = compliance_summary(df, meta)
    window = summ["consent_window_ms"]
    window_txt = "Unknown" if window is None else f"{window/1000:.2f}s"

    elems.append(Paragraph(title, styles["Heading2"]))
    elems.append(Paragraph(
        f"Status: <b>{summ['status']}</b> · Total: {summ['total_requests']} · Pre-consent: {summ['preconsent_requests']} "
        f"· Violations: {summ['violation_count']} · High-Risk: <b>{summ['highrisk_count']}</b> · Pre-consent window: <b>{window_txt}</b>",
        styles["Normal"]
    ))
    elems.append(Spacer(1, 6))
    elems.append(Paragraph(
        "<b>Explanation:</b> Rows highlighted in <font color='white' bgcolor='red'>RED</font> are non-essential or policy-blocked requests "
        "that fired <b>before user consent was stored</b> (High-Risk).", styles["Normal"]
    ))
    elems.append(Spacer(1, 8))

    # Cookies set before consent
    cookies_df = preconsent_cookie_summary(df)
    elems.append(Paragraph("<b>Cookies set before consent</b>", styles["Heading4"]))
    if cookies_df.empty:
        elems.append(Paragraph("None detected.", styles["Normal"]))
    else:
        ccols = ["Cookie","Purpose","First Seq #","Domain","Times Set"]
        data_c = [ccols] + cookies_df[ccols].astype(str).values.tolist()
        table_c = Table(data_c, colWidths=[180, 80, 60, 240, 60])
        style_c = TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.black),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,0), 9),
            ("GRID", (0,0), (-1,-1), 0.25, colors.HexColor("#2A2F34")),
            ("FONTSIZE", (0,1), (-1,-1), 8),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
            ("LEFTPADDING", (0,0), (-1,-1), 6),
            ("RIGHTPADDING", (0,0), (-1,-1), 6),
            ("ALIGN", (2,1), (2,-1), "CENTER"),
            ("ALIGN", (4,1), (4,-1), "CENTER"),
        ])
        table_c.setStyle(style_c)
        elems.append(table_c)
    elems.append(Spacer(1, 8))

    # 3P Pre-consent by domain
    elems.append(Paragraph("<b>Third-party requests before consent (Top domains)</b>", styles["Heading4"]))
    third = summ["preconsent_3p_domains"]
    if not third:
        elems.append(Paragraph("None detected.", styles["Normal"]))
    else:
        ddata = [["Domain", "Count"]] + [[k, str(v)] for k, v in third.items()]
        dtable = Table(ddata, colWidths=[300, 60])
        dtable.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.black),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("GRID", (0,0), (-1,-1), 0.25, colors.HexColor("#2A2F34")),
            ("FONTSIZE", (0,0), (-1,0), 9),
            ("FONTSIZE", (0,1), (-1,-1), 8),
        ]))
        elems.append(dtable)
    elems.append(Spacer(1, 8))

    # Tag chains (parent -> child)
    elems.append(Paragraph("<b>Tag Chains (Top)</b>", styles["Heading4"]))
    edges_df, chains = build_tag_graph(df)
    if chains.empty:
        elems.append(Paragraph("No initiator information found in HAR.", styles["Normal"]))
    else:
        top = chains.head(15)
        ccols = ["Parent", "Child", "Purpose", "Count", "PreConsent", "FirstSeq"]
        data_g = [ccols] + top[ccols].astype(str).values.tolist()
        table_g = Table(data_g, colWidths=[200, 220, 80, 48, 72, 50])
        table_g.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.black),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,0), 9),
            ("GRID", (0,0), (-1,-1), 0.25, colors.HexColor("#2A2F34")),
            ("FONTSIZE", (0,1), (-1,-1), 8),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
            ("LEFTPADDING", (0,0), (-1,-1), 6),
            ("RIGHTPADDING", (0,0), (-1,-1), 6),
            ("ALIGN", (3,1), (4,-1), "CENTER"),
            ("ALIGN", (5,1), (5,-1), "CENTER"),
        ]))
        elems.append(table_g)
    elems.append(Spacer(1, 10))

    # High-Risk table
    viol = df[df["HighRisk"] == True]  # noqa: E712
    cols = ["Seq #","Name","Status","Type","Started at","Category","Purpose","Party","Rule"]

    data = [cols]
    if viol.empty:
        data.append(["", "No high-risk requests detected.", "", "", "", "", "", "", ""])
    else:
        for _, row in viol[cols].iterrows():
            data.append([
                str(row["Seq #"]),
                Paragraph(html_escape(_soft_wrap_text(row["Name"])), cell_style),
                str(row["Status"]),
                Paragraph(html_escape(_soft_wrap_text(row["Type"], max_len=200)), cell_style),
                str(row["Started at"]),
                str(row["Category"]),
                str(row["Purpose"]),
                str(row["Party"]),
                str(row["Rule"]),
            ])

    col_widths = [32, None, 36, 46, 52, 52, 52, 30, 52]
    table = Table(data, repeatRows=1, colWidths=col_widths)
    base = TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.black),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#2A2F34")),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("ALIGN", (0, 1), (0, -1), "CENTER"),
            ("LEFTPADDING", (0, 1), (0, -1), 4),
            ("RIGHTPADDING", (0, 1), (0, -1), 4),
        ]
    )
    if not viol.empty:
        for i in range(1, len(data)):
            base.add("BACKGROUND", (0, i), (-1, i), colors.red)
            base.add("TEXTCOLOR", (0, i), (-1, i), colors.white)
    table.setStyle(base)
    elems.append(table)

    doc.build(elems)
    buf.seek(0)
    return buf.read()

# -------------------- Compliance XLSX --------------------
def make_report_xlsx(df: pd.DataFrame, meta: Dict[str, Any], title: str = "Consent Compliance Report") -> bytes:
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter", engine_kwargs={"options": {"strings_to_urls": False}}) as writer:
        wb = writer.book

        summ = compliance_summary(df, meta)
        ws = wb.add_worksheet("Summary")
        hfmt = wb.add_format({"bold": True})
        ws.write(0, 0, title, wb.add_format({"bold": True, "font_size": 14}))

        explanation = (
            "Explanation: Rows highlighted in RED in the 'High-Risk' sheet are non-essential or policy-blocked "
            "requests that fired BEFORE user consent was stored."
        )
        wrap = wb.add_format({"text_wrap": True})
        ws.write(1, 0, explanation, wrap); ws.set_row(1, 48)

        window = summ["consent_window_ms"]
        window_txt = "Unknown" if window is None else f"{window/1000:.2f}s"

        for i, (k, v) in enumerate([
            ("Status", summ["status"]),
            ("Total requests", summ["total_requests"]),
            ("Pre-consent requests", summ["preconsent_requests"]),
            ("Violations (generic)", summ["violation_count"]),
            ("High-Risk (policy)", summ["highrisk_count"]),
            ("Pre-consent window", window_txt),
        ], start=3):
            ws.write(i, 0, k, hfmt); ws.write(i, 1, v)

        ws.write(10, 0, "3P pre-consent (top domains)", hfmt)
        r = 11
        for dom, cnt in summ["preconsent_3p_domains"].items():
            ws.write(r, 0, dom); ws.write(r, 1, cnt); r += 1

        ws.write(10, 3, "High-Risk purposes", hfmt)
        r2 = 11
        for p, cnt in summ["highrisk_purposes"].items():
            ws.write(r2, 3, p); ws.write(r2, 4, cnt); r2 += 1

        ws.set_column(0, 0, 44); ws.set_column(1, 1, 16); ws.set_column(3, 3, 24); ws.set_column(4, 4, 12)

        # High-Risk sheet
        viol = df[df["HighRisk"] == True]  # noqa: E712
        cols = ["Seq #","Name","Status","Type","Started at","Category","Purpose","Party","Rule"]
        if viol.empty:
            pd.DataFrame([{"Info":"No high-risk requests detected."}]).to_excel(writer, sheet_name="High-Risk", index=False)
        else:
            viol[cols].to_excel(writer, sheet_name="High-Risk", index=False)
            ws2 = writer.sheets["High-Risk"]
            start_row = 1
            red_fmt = wb.add_format({"bg_color": "#FF0000", "font_color": "#FFFFFF"})
            for i in range(len(viol)):
                ws2.set_row(start_row + i, None, red_fmt)
            ws2.set_column(0, 0, 8); ws2.set_column(1, 1, 90); ws2.set_column(2, 8, 16)

        # Pre-consent cookies sheet
        cookies_df = preconsent_cookie_summary(df)
        if cookies_df.empty:
            pd.DataFrame([{"Cookie": "None detected"}]).to_excel(writer, sheet_name="PreConsent Cookies", index=False)
        else:
            cols = ["Cookie","Purpose","First Seq #","Domain","Times Set"]
            cookies_df[cols].to_excel(writer, sheet_name="PreConsent Cookies", index=False)
            ws3 = writer.sheets["PreConsent Cookies"]
            ws3.set_column(0, 0, 34); ws3.set_column(1, 1, 14); ws3.set_column(2, 2, 12); ws3.set_column(3, 3, 40); ws3.set_column(4, 4, 12)

        # Tag Chains sheet (TOP 15)
        edges_df, chains = build_tag_graph(df)
        if chains.empty:
            pd.DataFrame([{"Info": "No initiator information found in HAR."}]).to_excel(
                writer, sheet_name="Tag Chains", index=False
            )
        else:
            cols_tc = ["Parent", "Child", "Purpose", "Count", "PreConsent", "FirstSeq"]
            top_tc = chains[cols_tc].head(15)
            top_tc.to_excel(writer, sheet_name="Tag Chains", index=False)
            ws_tc = writer.sheets["Tag Chains"]
            header_fmt = wb.add_format({"bold": True, "bg_color": "#000000", "font_color": "#FFFFFF", "border": 1})
            for i, col in enumerate(cols_tc):
                ws_tc.write(0, i, col, header_fmt)
            ws_tc.set_column(0, 0, 40); ws_tc.set_column(1, 1, 44)
            ws_tc.set_column(2, 2, 14); ws_tc.set_column(3, 5, 12)

    output.seek(0)
    return output.read()

# -------------------- Evidence pack --------------------
def make_evidence_zip(har_bytes: bytes, rules_text: str, df: pd.DataFrame, meta: Dict[str, Any]) -> bytes:
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, "w", compression=zipfile.ZIP_DEFLATED) as z:
        # Originals & policy
        z.writestr("evidence/original.har", har_bytes if isinstance(har_bytes, (bytes, bytearray)) else har_bytes.encode("utf-8", "ignore"))
        if rules_text:
            z.writestr("evidence/policy.yml", rules_text)

        # Reports
        z.writestr("reports/compliance.pdf", make_report_pdf(df, meta))
        z.writestr("reports/compliance.xlsx", make_report_xlsx(df, meta))

        # Summaries
        summ = compliance_summary(df, meta)
        z.writestr("snapshot/summary.json", json.dumps(summ, indent=2))

        # One-page breakdown PDF
        try:
            z.writestr("reports/breakdown.pdf", make_breakdown_pdf(summ))
        except Exception:
            pass

        # Data dumps
        try:
            csv_cols = ["Seq #","Name","Host","InitiatorHost","Status","Type","Started at","Size","Time","Category","Purpose","Party","PreConsent","Violation","HighRisk","Rule","CookiesSetNames"]
            z.writestr("data/requests.csv", df[csv_cols].to_csv(index=False))
        except Exception:
            pass
        try:
            cookies_df = preconsent_cookie_summary(df)
            z.writestr("data/preconsent_cookies.json", cookies_df.to_json(orient="records"))
        except Exception:
            pass

        # Tag graph JSON
        try:
            edges_df, chains = build_tag_graph(df)
            z.writestr("graph/tag_chains.json", edges_df.to_json(orient="records"))
            z.writestr("graph/tag_chains_agg.json", chains.to_json(orient="records"))
        except Exception:
            pass

        # Interpretation guide
        z.writestr("INTERPRET_REPORT.md", INTERPRET_GUIDE)

    mem.seek(0)
    return mem.read()

# -------------------- Processing Helper --------------------
def process_har(har_bytes: bytes, policy_text: str, assume_no_consent_if_unknown: bool, strict_mode: bool) -> tuple[pd.DataFrame, Dict[str, Any]]:
    try:
        har_json = json.loads(har_bytes.decode("utf-8", "ignore"))
    except Exception as e:
        raise ValueError(f"Invalid HAR: {e}")
    df = har_to_df(har_json)
    if df.empty:
        return df, {"has_consent": False, "preconsent_window_ms": None}
    df, meta = mark_preconsent(df, assume_no_consent_if_unknown)
    df = mark_party(df)
    rules = load_rules_from_text(policy_text) if policy_text else DEFAULT_RULES.copy()
    df = apply_policy(df, rules, strict_mode=strict_mode)
    return df, meta

# -------------------- Diff utilities --------------------
def diff_requests(test_df: pd.DataFrame, base_df: pd.DataFrame) -> pd.DataFrame:
    base_urls = set(base_df["Name"].astype(str).unique())
    is_new = ~test_df["Name"].astype(str).isin(base_urls)
    new_df = test_df[is_new].copy()
    return new_df.sort_values(["Seq #"])

def diff_cookies(test_df: pd.DataFrame, base_df: pd.DataFrame) -> pd.DataFrame:
    t = preconsent_cookie_summary(test_df); b = preconsent_cookie_summary(base_df)
    if t.empty:
        return t
    if b.empty:
        return t
    keys_b = set(zip(b["Cookie"], b["Domain"]))
    mask = [(r["Cookie"], r["Domain"]) not in keys_b for _, r in t.iterrows()]
    return t[mask].reset_index(drop=True)

def diff_tag_chains(test_df: pd.DataFrame, base_df: pd.DataFrame) -> pd.DataFrame:
    _, agg_t = build_tag_graph(test_df)
    _, agg_b = build_tag_graph(base_df)
    if agg_t.empty:
        return agg_t
    if agg_b.empty:
        return agg_t
    keys_b = set((r.Parent, r.Child, r.Purpose) for r in agg_b.itertuples(index=False))
    rows = [r for r in agg_t.itertuples(index=False) if (r.Parent, r.Child, r.Purpose) not in keys_b]
    return pd.DataFrame(rows, columns=agg_t.columns)

# -------------------- Diff Exports --------------------
def make_diff_pdf(new_req: pd.DataFrame, new_cookies: pd.DataFrame, new_chains: pd.DataFrame, tag_name: str = "Differences vs Baseline") -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=24,rightMargin=24,topMargin=24,bottomMargin=24)
    styles = getSampleStyleSheet(); cell_style = _pdf_cell_style(styles); elems = []
    elems.append(Paragraph(f"HAR Diff Report – {tag_name}", styles["Heading2"]))
    elems.append(Paragraph("This report shows differences between a baseline HAR (all tags paused) and a test HAR (one tag enabled).", styles["Normal"]))
    elems.append(Spacer(1,8))

    elems.append(Paragraph("<b>Requests – Differences vs Baseline</b>", styles["Heading4"]))
    if new_req.empty:
        elems.append(Paragraph("No added requests detected.", styles["Normal"]))
    else:
        cols=["Seq #","Name","Status","Type","Category","Purpose","Party","PreConsent","Violation","HighRisk","Rule"]
        data=[cols]
        for _,row in new_req[cols].iterrows():
            data.append([str(row["Seq #"]),
                         Paragraph(html_escape(_soft_wrap_text(row["Name"])), cell_style),
                         str(row["Status"]), Paragraph(html_escape(_soft_wrap_text(row["Type"],200)), cell_style),
                         str(row["Category"]), str(row["Purpose"]), str(row["Party"]),
                         str(row["PreConsent"]), str(row["Violation"]), str(row["HighRisk"]), str(row["Rule"])])
        table=Table(data, repeatRows=1, colWidths=[32,None,40,56,56,60,40,56,48,48,56])
        table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.black),("TEXTCOLOR",(0,0),(-1,0),colors.white),
                                   ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,0),10),
                                   ("GRID",(0,0),(-1,-1),0.25,colors.HexColor("#2A2F34")),("FONTSIZE",(0,1),(-1,-1),8),
                                   ("VALIGN",(0,0),(-1,-1),"MIDDLE"),("LEFTPADDING",(0,0),(-1,-1),6),("RIGHTPADDING",(0,0),(-1,-1),6)]))
        elems.append(table)
    elems.append(Spacer(1,8))

    elems.append(Paragraph("<b>Pre-consent Cookies – Differences vs Baseline</b>", styles["Heading4"]))
    if new_cookies is None or new_cookies.empty:
        elems.append(Paragraph("None detected.", styles["Normal"]))
    else:
        ccols=["Cookie","Purpose","First Seq #","Domain","Times Set"]
        data_c=[ccols]+new_cookies[ccols].astype(str).values.tolist()
        table_c=Table(data_c, colWidths=[180,80,60,240,60])
        table_c.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.black),("TEXTCOLOR",(0,0),(-1,0),colors.white),
                                     ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,0),9),
                                     ("GRID",(0,0),(-1,-1),0.25,colors.HexColor("#2A2F34")),("FONTSIZE",(0,1),(-1,-1),8)]))
        elems.append(table_c)
    elems.append(Spacer(1,8))

    elems.append(Paragraph("<b>Tag Chains – Differences vs Baseline</b>", styles["Heading4"]))
    if new_chains is None or new_chains.empty:
        elems.append(Paragraph("No added parent→child tag edges detected.", styles["Normal"]))
    else:
        cols_tc=["Parent","Child","Purpose","Count","PreConsent","FirstSeq"]
        top=new_chains[cols_tc].head(20)
        data_g=[cols_tc]+top.astype(str).values.tolist()
        table_g=Table(data_g, colWidths=[200,220,80,48,72,50])
        table_g.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.black),("TEXTCOLOR",(0,0),(-1,0),colors.white),
                                     ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,0),9),
                                     ("GRID",(0,0),(-1,-1),0.25,colors.HexColor("#2A2F34")),("FONTSIZE",(0,1),(-1,-1),8)]))
        elems.append(table_g)

    doc.build(elems); buf.seek(0); return buf.read()

def make_diff_xlsx(new_req: pd.DataFrame, new_cookies: pd.DataFrame, new_chains: pd.DataFrame, title: str = "HAR Diff Report") -> bytes:
    output=io.BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter", engine_kwargs={"options":{"strings_to_urls":False}}) as writer:
        wb=writer.book
        ws=wb.add_worksheet("Summary")
        ws.write(0,0,title, wb.add_format({"bold":True,"font_size":14}))
        ws.write(2,0,"Requests: Added vs Baseline", wb.add_format({"bold":True}))
        ws.write(2,1,0 if new_req is None else len(new_req))
        ws.write(3,0,"Pre-consent Cookies: Added vs Baseline", wb.add_format({"bold":True}))
        ws.write(3,1,0 if (new_cookies is None or new_cookies.empty) else len(new_cookies))
        ws.write(4,0,"Tag Chains: Added vs Baseline", wb.add_format({"bold":True}))
        ws.write(4,1,0 if (new_chains is None or new_chains.empty) else len(new_chains))

        if new_req is None or new_req.empty:
            pd.DataFrame([{"Info":"No added requests."}]).to_excel(writer, sheet_name="Requests vs Baseline (Added)", index=False)
        else:
            cols=["Seq #","Name","Status","Type","Category","Purpose","Party","PreConsent","Violation","HighRisk","Rule"]
            new_req[cols].to_excel(writer, sheet_name="Requests vs Baseline (Added)", index=False)
            ws1=writer.sheets["Requests vs Baseline (Added)"]; ws1.set_column(0,0,8); ws1.set_column(1,1,90); ws1.set_column(2,10,16)

        if new_cookies is None or new_cookies.empty:
            pd.DataFrame([{"Info":"No added cookies."}]).to_excel(writer, sheet_name="Cookies vs Baseline (Added)", index=False)
        else:
            cols=["Cookie","Purpose","First Seq #","Domain","Times Set"]
            new_cookies[cols].to_excel(writer, sheet_name="Cookies vs Baseline (Added)", index=False)
            ws2=writer.sheets["Cookies vs Baseline (Added)"]; ws2.set_column(0,0,34); ws2.set_column(1,1,14); ws2.set_column(2,2,12); ws2.set_column(3,3,40); ws2.set_column(4,4,12)

        if new_chains is None or new_chains.empty:
            pd.DataFrame([{"Info":"No added tag chains."}]).to_excel(writer, sheet_name="Tag Chains vs Baseline (Added)", index=False)
        else:
            cols_tc=["Parent","Child","Purpose","Count","PreConsent","FirstSeq"]
            new_chains[cols_tc].to_excel(writer, sheet_name="Tag Chains vs Baseline (Added)", index=False)
            ws3=writer.sheets["Tag Chains vs Baseline (Added)"]; ws3.set_column(0,0,40); ws3.set_column(1,1,44); ws3.set_column(2,2,14); ws3.set_column(3,5,12)
    output.seek(0); return output.read()

# -------------------- Streamlit UI --------------------
st.set_page_config(page_title="HAR File Viewer", layout="wide")

st.markdown(
    """
    <style>
      .block-container { padding-top: 1rem; }
      .legend-chip { display:inline-block; padding:4px 8px; border-radius:999px; color:#0b0f14; font-weight:600; margin-right:6px; }
      .stDataFrame table { font-size: 12px; }
    </style>
    """,
    unsafe_allow_html=True
)

st.title("HAR File Viewer")

with st.expander("📖 View Guide – How to interpret this report", expanded=False):
    st.markdown(INTERPRET_GUIDE)

with st.sidebar:
    st.header("Load HAR")
    uploaded = st.file_uploader("Upload a .har file", type=["har"])
    st.caption("Export a HAR from DevTools → Network → ⋯ → Save all as HAR")

    st.markdown("### Compliance Options")
    assume_no_consent_if_unknown = st.checkbox("Assume NO consent if none detected", value=True)
    strict_mode = st.checkbox("Strict mode (all 3P blocked pre-consent unless allowlisted)", value=True)

    st.markdown("### Policy (YAML)")
    policy_file = st.file_uploader("policy.yml (optional)", type=["yml", "yaml"], help="Keys: allow, block_until_consent, purpose_overrides, cookie_overrides")
    policy_text = policy_file.read().decode("utf-8", "ignore") if policy_file else ""

    st.markdown("### Export Results")

with st.sidebar:
    st.markdown("---")
    st.header("Diff Mode (Optional)")
    base_har = st.file_uploader("Baseline HAR (all tags paused)", type=["har"], key="baseline_har")
    test_har = st.file_uploader("Test HAR (one tag enabled)", type=["har"], key="test_har")
    tag_label = st.text_input("Label for this comparison (e.g., 'Google Ads Remarketing')", value="Differences vs Baseline")

# Guard
if uploaded is None and (base_har is None or test_har is None):
    st.info("Upload a HAR file to get started. For Diff Mode, upload both a Baseline and a Test HAR.")
    st.stop()

# ---------- Single HAR mode ----------
if uploaded is not None and not (base_har and test_har):
    raw_har_bytes = uploaded.read()
    try:
        df, meta = process_har(raw_har_bytes, policy_text, assume_no_consent_if_unknown, strict_mode)
    except Exception as e:
        st.error(f"Failed to read HAR: {e}")
        st.stop()

    if df.empty:
        st.warning("No entries found in this HAR.")
        st.stop()

    # Category filter chips
    st.subheader("Requests")
    cols_btn = st.columns(len(CATEGORY_ORDER))
    clicked = None
    for i, c in enumerate(CATEGORY_ORDER):
        if c == "All":
            count = len(df)
        elif c == "High-Risk":
            count = int(df["HighRisk"].sum())
        else:
            count = int((df["Category"] == c).sum())
        if cols_btn[i].button(f"{c} ({count})", use_container_width=True, key=f"cat_{c}"):
            clicked = c
    if "cat_selected" not in st.session_state:
        st.session_state["cat_selected"] = "All"
    if clicked:
        st.session_state["cat_selected"] = clicked
    selected = st.session_state["cat_selected"]

    filtered = filter_df(df, selected)

    legend_html = " ".join(
        f'<span class="legend-chip" style="background:{CATEGORY_COLORS.get(cat, FALLBACK_COLOR)};">{cat}</span>'
        for cat in ["XHR","JS","CSS","Img","Media","Other","Errors"]
    )
    st.markdown(f"**Legend:** {legend_html}", unsafe_allow_html=True)

    window = meta.get("preconsent_window_ms")
    window_txt = "Unknown" if window is None else f"{window/1000:.2f}s"
    st.caption(f"Showing **{len(filtered)}** of **{len(df)}** · Category: **{selected}** · Pre-consent window: **{window_txt}**")

    # Sidebar exports for single HAR
    with st.sidebar:
        csv_cols = ["Seq #","Name","Host","Status","Type","Started at","Size","Time","Category","Purpose","Party","PreConsent","Violation","HighRisk","Rule","CookiePurposeHint","ConsentModeHint","CookiesSetNames","ColorHex","InitiatorHost"]
        st.download_button("⬇️ CSV (no colors)", data=filtered[csv_cols].to_csv(index=False).encode("utf-8"),
                           file_name="har_export.csv", mime="text/csv", key="dl_csv_single")

        st.download_button("⬇️ Excel (colored)", data=make_xlsx(filtered, title=f"HAR Export – {selected}"),
                           file_name="har_export.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", key="dl_xlsx_single")

        st.download_button("⬇️ PDF (colored)", data=make_pdf(filtered, title=f"HAR Export – {selected}"),
                           file_name="har_export.pdf", mime="application/pdf", key="dl_pdf_single")

        st.markdown("---")
        st.download_button("🛡️ Compliance XLSX", data=make_report_xlsx(df, meta, title="Consent Compliance Report"),
                           file_name="compliance_report.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", key="dl_comp_xlsx")

        st.download_button("🛡️ Compliance PDF", data=make_report_pdf(df, meta, title="Consent Compliance Report"),
                           file_name="compliance_report.pdf", mime="application/pdf", key="dl_comp_pdf")

        try:
            onepager_bytes = make_breakdown_pdf(compliance_summary(df, meta))
            st.download_button("🧾 One-Page Breakdown (PDF)", data=onepager_bytes,
                               file_name="compliance_breakdown.pdf", mime="application/pdf", key="dl_onepager")
        except Exception as e:
            st.caption(f"One-pager unavailable: {e}")

        try:
            st.download_button("📦 Evidence Pack (.zip)", data=make_evidence_zip(raw_har_bytes, policy_text, df, meta),
                               file_name="evidence_pack.zip", mime="application/zip", key="dl_evidence_zip")
        except Exception as e:
            st.caption(f"Evidence pack unavailable: {e}")

    # Styled table
    show_cols = [
        "Seq #","Name","InitiatorHost","Status","Type","Started at","Size","Time",
        "Category","Purpose","Party","PreConsent","Violation","HighRisk","Rule","ColorHex","CookiePurposeHint"
    ]
    show_df = filtered[show_cols].copy()
    row_colors = show_df["ColorHex"].copy()
    display_df = show_df.drop(columns=["ColorHex"])

    def apply_row_colors(s: pd.Series):
        col = row_colors.loc[s.name]
        is_hr = str(display_df.loc[s.name, "HighRisk"]) == "True"
        txt_color = "#FFFFFF" if is_hr and selected == "High-Risk" else "#0b0f14"
        return [f"background-color: {col}; color: {txt_color};"] * len(s)

    st.dataframe(display_df.style.apply(apply_row_colors, axis=1), use_container_width=True, hide_index=True)

# ---------- Diff Mode ----------
if base_har is not None and test_har is not None:
    try:
        base_df, base_meta = process_har(base_har.read(), policy_text, assume_no_consent_if_unknown, strict_mode)
        test_df, test_meta = process_har(test_har.read(), policy_text, assume_no_consent_if_unknown, strict_mode)
    except Exception as e:
        st.error(f"Failed to process one of the HAR files: {e}")
        st.stop()

    if base_df.empty or test_df.empty:
        st.warning("One of the HAR files has no entries.")
    else:
        new_req = diff_requests(test_df, base_df)
        new_cookies = diff_cookies(test_df, base_df)
        new_chains = diff_tag_chains(test_df, base_df)

        st.markdown("---")
        st.header(f"🔍 Diff Mode — {tag_label}")

        st.subheader("Requests: Added vs Baseline")
        if new_req.empty:
            st.info("No added requests detected.")
        else:
            st.dataframe(new_req[["Seq #","Name","Status","Type","Category","Purpose","Party","PreConsent","Violation","HighRisk","Rule"]],
                         use_container_width=True)

        st.subheader("Pre-consent Cookies: Added vs Baseline")
        if new_cookies is None or new_cookies.empty:
            st.info("No added pre-consent cookies detected.")
        else:
            st.dataframe(new_cookies, use_container_width=True)

        st.subheader("Tag Chains: Added vs Baseline")
        if new_chains is None or new_chains.empty:
            st.info("No added parent→child tag edges detected.")
        else:
            st.dataframe(new_chains[["Parent","Child","Purpose","Count","PreConsent","FirstSeq"]], use_container_width=True)

        # Downloads for Diff
        with st.sidebar:
            st.markdown("---")
            st.markdown("### Diff Exports")
            st.download_button("⬇️ Diff PDF", data=make_diff_pdf(new_req, new_cookies, new_chains, tag_label or "Differences vs Baseline"),
                               file_name="diff_report.pdf", mime="application/pdf", key="dl_diff_pdf")
            st.download_button("⬇️ Diff XLSX", data=make_diff_xlsx(new_req, new_cookies, new_chains, "HAR Diff Report"),
                               file_name="diff_report.xlsx",
                               mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", key="dl_diff_xlsx")
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAR Viewer / Tag Audit Tool – consolidated build
- Single + Diff modes
- Consent boundary
- Robust cookies (Set-Cookie, request Cookie, heuristic JS writes)
- Built-in policy (Google surfaces marked Essential) + toggle
- Tag Chains + Top Parents
- CSV / Excel (colored, multi-sheet) / PDF (colored)
- Hardened initiator/referrer parsing, Chrome HAR cookie warning
"""

import io
import json
import re
import string
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import urlparse

import pandas as pd
import streamlit as st
from dateutil import parser as dateparser
from pandas.io.formats.style import Styler

# PDF export
from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

# =============================== UI CONFIG ===============================
st.set_page_config(page_title="Tag Audit Tool (HAR Analyzer)", layout="wide")

CATEGORY_COLORS = {
    "JS": "#FFC107",       # amber
    "CSS": "#42A5F5",      # blue
    "XHR": "#AB47BC",      # purple
    "Img": "#66BB6A",      # green
    "Media": "#EC407A",    # pink
    "Other": "#B0BEC5",    # gray
    "Error": "#EF5350",    # red
}
VIOLATION_COLOR = "#F44336"        # red (hard violation)
PRECONSENT_FILL = "#FFE082"        # amber fill for pre-consent but essential (cookies/tag-chains)

# =============================== BASIC HELPERS ===============================
def _host_of(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""

def _etype(entry) -> str:
    try:
        mime = (entry.get("response", {}).get("content", {}) or {}).get("mimeType", "")
        if mime:
            return mime
    except Exception:
        pass
    try:
        return entry.get("_resourceType") or entry.get("resourceType") or ""
    except Exception:
        return ""

def _category(entry) -> str:
    t = (_etype(entry) or "").lower()
    url = (entry.get("request", {}) or {}).get("url", "") or ""
    if "javascript" in t or url.lower().endswith(".js"):
        return "JS"
    if "css" in t or url.lower().endswith(".css"):
        return "CSS"
    if "image" in t or any(url.lower().endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico"]):
        return "Img"
    if "audio" in t or "video" in t:
        return "Media"
    if "json" in t or "xhr" in t or "fetch" in t:
        return "XHR"
    try:
        if int(entry.get("response", {}).get("status", 200)) >= 400:
            return "Error"
    except Exception:
        pass
    return "Other"

def estimate_consent_boundary(entries) -> int:
    # crude heuristic; user can override
    for i, e in enumerate(entries, start=1):
        u = (e.get("request", {}) or {}).get("url", "").lower()
        if any(k in u for k in ["consent", "onetrust", "one-trust", "didomi", "trustarc"]):
            return max(5, i + 1)
    return len(entries) + 1

# =============================== BUILT-IN POLICY ===============================
# Domain rules: tuple(domain_suffix, category, essential)
DEFAULT_POLICY_DOMAINS: list[tuple[str, str, bool]] = [
    # Analytics / Tag Manager
    ("google-analytics.com", "Analytics", True),
    ("www.google-analytics.com", "Analytics", True),
    ("analytics.google.com", "Analytics", True),
    ("googletagmanager.com", "Tag Manager", True),
    ("www.googletagmanager.com", "Tag Manager", True),
    ("ssl.google-analytics.com", "Analytics", True),
    # Google Ads / DoubleClick (per your org policy: treat as Essential)
    ("doubleclick.net", "Advertising", True),
    ("googlesyndication.com", "Advertising", True),
    ("pagead2.googlesyndication.com", "Advertising", True),
    ("googleadservices.com", "Advertising", True),
    ("adservice.google.com", "Advertising", True),
    ("stats.g.doubleclick.net", "Advertising", True),
    # Platform/static
    ("gstatic.com", "Platform", True),
    ("google.com", "Platform", True),
]

# Cookie rules: tuple(cookie_name_or_glob, category, essential)
DEFAULT_POLICY_COOKIES: list[tuple[str, str, bool]] = [
    ("_ga", "Analytics", True),
    ("_ga_*", "Analytics", True),
    ("_gid", "Analytics", True),
    ("_gcl_au", "Advertising", True),
    ("IDE", "Advertising", True),
    ("1P_JAR", "Advertising", True),
    ("NID", "Advertising", True),
    ("SID", "Platform", True),
    ("HSID", "Platform", True),
    ("SIDCC", "Platform", True),
    ("__Secure-*", "Platform", True),
]

@dataclass(frozen=True)
class PolicyHit:
    category: str
    essential: bool
    source: str

class Policy:
    def __init__(self):
        self.domain_rules: list[tuple[str, str, bool, str]] = []  # (suffix, cat, essential, source)
        self.cookie_rules: list[tuple[str, str, bool, str]] = []  # (glob, cat, essential, source)

    def load_builtins(self, enable=True):
        if not enable:
            return
        for s, c, e in DEFAULT_POLICY_DOMAINS:
            self.domain_rules.append((s.lower().lstrip("."), c, bool(e), f"builtin:domain:{s}"))
        for p, c, e in DEFAULT_POLICY_COOKIES:
            self.cookie_rules.append((p.lower(), c, bool(e), f"builtin:cookie:{p}"))

    @staticmethod
    def _match_glob(name: str, pattern: str) -> bool:
        name = (name or "").lower()
        pattern = (pattern or "").lower()
        if pattern.endswith("*"):
            return name.startswith(pattern[:-1])
        return name == pattern

    @staticmethod
    def _host(url: str) -> str:
        try:
            return urlparse(url).hostname or ""
        except Exception:
            return ""

    @lru_cache(maxsize=8192)
    def classify_url(self, url: str) -> PolicyHit | None:
        host = self._host(url).lower()
        for suffix, cat, essential, src in self.domain_rules:
            if host.endswith(suffix):
                return PolicyHit(cat, essential, src)
        return None

    @lru_cache(maxsize=8192)
    def classify_cookie(self, name: str, domain: str) -> PolicyHit | None:
        for pat, cat, essential, src in self.cookie_rules:
            if self._match_glob(name, pat):
                return PolicyHit(cat, essential, src)
        d = (domain or "").lower()
        for suffix, cat, essential, src in self.domain_rules:
            if d.endswith(suffix):
                return PolicyHit(cat, essential, src)
        return None

# =============================== HAR CREATOR WARNING ===============================
def har_creator(har_json: dict) -> tuple[str, str]:
    c = (har_json or {}).get("log", {}).get("creator", {}) or {}
    return str(c.get("name", "") or ""), str(c.get("version", "") or "")

def maybe_warn_har_creator(har_json: dict):
    name, ver = har_creator(har_json)
    if not name:
        return
    if name.lower().startswith(("chrome", "edge", "chromium")) or "devtools" in name.lower():
        st.warning(
            f"This HAR was created by {name} {ver}. Chrome/Edge often redact Cookie headers in HAR. "
            "Prefer Firefox for full cookie evidence, or capture via a proxy (mitmproxy/Fiddler)."
        )
    else:
        st.caption(f"HAR creator: {name} {ver}")

# =============================== HEADERS / COOKIES ===============================
def _har_headers(entry, section="response"):
    try:
        headers = entry.get(section, {}).get("headers", []) or []
        out = []
        for h in headers:
            if isinstance(h, dict):
                name = h.get("name") or h.get("Name") or h.get("key") or h.get("Key")
                value = h.get("value") or h.get("Value") or ""
                if name is not None:
                    out.append({"name": str(name), "value": str(value)})
        return out
    except Exception:
        return []

def _iter_set_cookie_values(entry):
    # Header
    for h in _har_headers(entry, "response"):
        if str(h.get("name", "")).lower() == "set-cookie" and h.get("value"):
            for line in str(h["value"]).replace("\r", "").split("\n"):
                line = line.strip()
                if line:
                    yield line
    # Structured cookies (some HARs include this)
    try:
        rc = entry.get("response", {}).get("cookies", []) or []
        for c in rc:
            name = c.get("name")
            val = c.get("value", "")
            if not name:
                continue
            parts = [f"{name}={val}"]
            if c.get("domain"): parts.append(f"Domain={c['domain']}")
            if c.get("path"): parts.append(f"Path={c['path']}")
            if c.get("httpOnly"): parts.append("HttpOnly")
            if c.get("secure"): parts.append("Secure")
            if c.get("expires"): parts.append(f"Expires={c['expires']}")
            yield "; ".join(parts)
    except Exception:
        pass

def _parse_set_cookie_line(line):
    # quick parse; resilient to weird attrs
    name, value, attrs = "", "", {}
    try:
        head = line.split(";", 1)[0]
        if "=" in head:
            name, value = head.split("=", 1)
            name = name.strip(); value = value.strip()
    except Exception:
        pass
    lower = (line or "").lower()
    m = re.search(r";\s*domain=([^;]+)", lower)
    if m: attrs["domain"] = m.group(1).strip()
    m = re.search(r";\s*path=([^;]+)", lower)
    if m: attrs["path"] = m.group(1).strip()
    attrs["secure"] = "secure" in lower
    attrs["httponly"] = "httponly" in lower
    return name, value, attrs

def _iter_request_cookie_names(entry):
    try:
        for h in _har_headers(entry, "request"):
            if str(h.get("name", "")).lower() == "cookie" and h.get("value"):
                for p in str(h["value"]).split(";"):
                    p = p.strip()
                    if "=" in p:
                        n, _ = p.split("=", 1)
                        yield n.strip()
    except Exception:
        return

def _heuristic_js_cookie_names(entry):
    # detect `document.cookie="name=...";` or setCookie('name',...)
    text = (entry.get("response", {}).get("content", {}) or {}).get("text", "") or ""
    if not text:
        return []
    names = set()
    for m in re.finditer(r"document\s*\.\s*cookie\s*=\s*([\"'])(?P<kv>[^\"']+)\1", text, re.I):
        kv = m.group("kv")
        n = kv.split("=", 1)[0].strip()
        if n:
            names.add(n)
    for m in re.finditer(r"\bset[_]?cookie\s*\(\s*([\"'])(?P<name>[^\"']+)\1\s*,", text, re.I):
        n = m.group("name").strip()
        if n:
            names.add(n)
    return list(names)

# =============================== REQUESTS DF ===============================
def har_to_df(har_json: dict, policy: Policy, consent_seq: int) -> pd.DataFrame:
    log = (har_json or {}).get("log", {}) or {}
    entries = log.get("entries", []) or []
    rows = []
    for i, e in enumerate(entries, start=1):
        req = e.get("request", {}) or {}
        res = e.get("response", {}) or {}
        url = req.get("url", "") or ""
        status = res.get("status", 0) or 0
        cat = _category(e)
        # policy
        hit = policy.classify_url(url)
        if hit:
            policy_cat, essential, policy_src = hit.category, hit.essential, hit.source
        else:
            # fallback heuristic category; treat non-essential by default
            policy_cat, essential, policy_src = "Unknown", False, "heuristic"

        pre = i < int(consent_seq)
        violation = pre and (not essential)

        started = e.get("startedDateTime")
        if started:
            try:
                started = dateparser.parse(started).strftime("%H:%M:%S.%f")[:-3]
            except Exception:
                pass

        rows.append({
            "Seq #": i,
            "Name": url,
            "Status": status,
            "Type": _etype(e) or "",
            "Category": cat,
            "PolicyCat": policy_cat,
            "Essential": essential,
            "PolicySource": policy_src,
            "PreConsent": pre,
            "Violation": violation,
            "Started at": started or "",
            "Size": res.get("bodySize", 0) or 0,
            "Time": (e.get("time") or 0) or 0,
        })
    return pd.DataFrame(rows)

# =============================== COOKIES DF (merged sources) ===============================
def harvest_cookies(har_json: dict, policy: Policy, consent_seq: int) -> pd.DataFrame:
    entries = (har_json or {}).get("log", {}).get("entries", []) or []
    rows = []
    seen = set()  # (name, domain)
    for idx, e in enumerate(entries, start=1):
        url = (e.get("request", {}) or {}).get("url", "")
        host = _host_of(url)
        # response Set-Cookie
        for line in _iter_set_cookie_values(e):
            name, _value, attrs = _parse_set_cookie_line(line)
            if not name:
                continue
            domain = attrs.get("domain") or host
            hit = policy.classify_cookie(name, domain)
            if hit:
                cat, essential, src = hit.category, hit.essential, hit.source
            else:
                cat, essential, src = "Unknown", False, "heuristic"
            key = (name, domain)
            if key not in seen:
                seen.add(key)
                pre = idx < int(consent_seq)
                rows.append({
                    "Cookie": name, "Domain": domain,
                    "PolicyCat": cat, "Essential": essential, "PolicySource": src,
                    "First Seq #": idx, "Times Set": 1,
                    "Secure": attrs.get("secure", False), "HttpOnly": attrs.get("httponly", False),
                    "PreConsent": pre,
                    "Violation": pre and (not essential),
                    "Source": "Set-Cookie (response)",
                })
    return pd.DataFrame(rows)

def infer_client_cookies(har_json: dict, policy: Policy, consent_seq: int) -> pd.DataFrame:
    entries = (har_json or {}).get("log", {}).get("entries", []) or []
    rows, seen = [], set()
    for idx, e in enumerate(entries, start=1):
        url = (e.get("request", {}) or {}).get("url", "")
        host = _host_of(url)
        for name in _iter_request_cookie_names(e):
            key = (name, host)
            if key in seen:
                continue
            seen.add(key)
            hit = policy.classify_cookie(name, host)
            if hit: cat, essential, src = hit.category, hit.essential, hit.source
            else:   cat, essential, src = "Unknown", False, "heuristic"
            pre = idx < int(consent_seq)
            rows.append({
                "Cookie": name, "Domain": host,
                "PolicyCat": cat, "Essential": essential, "PolicySource": src,
                "First Seq #": idx, "Times Set": 1,
                "Secure": False, "HttpOnly": False,
                "PreConsent": pre, "Violation": pre and (not essential),
                "Source": "Inferred (request)",
            })
    return pd.DataFrame(rows)

def infer_js_cookie_writes(har_json: dict, policy: Policy, consent_seq: int) -> pd.DataFrame:
    entries = (har_json or {}).get("log", {}).get("entries", []) or []
    rows, seen = [], set()
    for idx, e in enumerate(entries, start=1):
        url = (e.get("request", {}) or {}).get("url", "")
        host = _host_of(url)
        for name in _heuristic_js_cookie_names(e):
            key = (name, host)
            if key in seen:
                continue
            seen.add(key)
            hit = policy.classify_cookie(name, host)
            if hit: cat, essential, src = hit.category, hit.essential, hit.source
            else:   cat, essential, src = "Unknown", False, "heuristic"
            pre = idx < int(consent_seq)
            rows.append({
                "Cookie": name, "Domain": host,
                "PolicyCat": cat, "Essential": essential, "PolicySource": src,
                "First Seq #": idx, "Times Set": 1,
                "Secure": False, "HttpOnly": False,
                "PreConsent": pre, "Violation": pre and (not essential),
                "Source": "Heuristic (JS)",
            })
    return pd.DataFrame(rows)

def dedup(primary: pd.DataFrame, secondary: pd.DataFrame) -> pd.DataFrame:
    if primary is None or primary.empty:
        return secondary.copy() if secondary is not None else pd.DataFrame()
    if secondary is None or secondary.empty:
        return primary.copy()
    key = ["Cookie", "Domain"]
    pkeys = set(map(tuple, primary[key].astype(str).values.tolist()))
    keep = ~secondary[key].astype(str).apply(tuple, axis=1).isin(pkeys)
    return pd.concat([primary, secondary.loc[keep]], ignore_index=True)

# =============================== DIFF HELPERS ===============================
def diff_requests(df_base: pd.DataFrame, df_test: pd.DataFrame) -> pd.DataFrame:
    if df_test is None or df_test.empty:
        return pd.DataFrame()
    if df_base is None or df_base.empty:
        return df_test.copy()
    base = set(df_base["Name"].astype(str))
    mask = ~df_test["Name"].astype(str).isin(base)
    return df_test.loc[mask].reset_index(drop=True)

def diff_cookies(df_base: pd.DataFrame, df_test: pd.DataFrame) -> pd.DataFrame:
    if df_test is None or df_test.empty:
        return pd.DataFrame()
    if df_base is None or df_base.empty:
        return df_test.copy()
    key = ["Cookie", "Domain"]
    base = set(map(tuple, df_base[key].astype(str).values.tolist()))
    mask = ~df_test[key].astype(str).apply(tuple, axis=1).isin(base)
    return df_test.loc[mask].reset_index(drop=True)

# =============================== TAG CHAINS ===============================
def _har_headers_request(entry):
    return _har_headers(entry, "request")

def _initiator_url(entry) -> str | None:
    """Try to pull the parent/initiator URL safely."""
    init = entry.get("_initiator") or entry.get("initiator")
    try:
        if isinstance(init, dict):
            if "url" in init and init["url"]:
                return init["url"]
            stack = init.get("stack")
            # walk devtools stack
            def walk_stack(s):
                if not s or not isinstance(s, dict):
                    return None
                frames = s.get("callFrames") or []
                for fr in frames or []:
                    u = fr.get("url")
                    if u:
                        return u
                frames = s.get("frames") or []
                for fr in frames or []:
                    u = fr.get("url")
                    if u:
                        return u
                p = s.get("parent")
                if p and isinstance(p, dict):
                    return walk_stack(p)
                return None
            u = walk_stack(stack)
            if u:
                return u
    except Exception:
        pass
    # referer header fallback
    for h in _har_headers_request(entry):
        if str(h.get("name", "")).lower() == "referer" and h.get("value"):
            return h["value"]
    return None

def build_tag_chains(har_json: dict, df_requests: pd.DataFrame) -> pd.DataFrame:
    """
    Build a parent→child table using initiator/referrer signals.
    Looks up children against df_requests by BOTH full URL and host, so
    we can still classify even if one side uses host-only and the other uses full URL.
    """
    entries = (har_json or {}).get("log", {}).get("entries", []) or []

    # Build a map we can hit by URL and by host
    req_by_key: dict[str, pd.Series] = {}
    for _, r in df_requests.iterrows():
        url = str(r.get("Name", ""))
        if not url:
            continue
        host = _host_of(url) or ""
        req_by_key[url] = r
        if host:
            req_by_key[host] = r  # allow host lookups

    rows = []
    for e in entries:
        child_url = (e.get("request", {}) or {}).get("url", "")
        if not child_url:
            continue

        parent_url = _initiator_url(e)
        if not parent_url:
            continue

        # Try exact URL first, then host fallback
        child = req_by_key.get(child_url)
        if child is None:
            child = req_by_key.get(_host_of(child_url) or "")

        if child is None:
            # Not in the filtered df; still emit a minimal row (unclassified)
            rows.append({
                "Parent": _host_of(parent_url) or parent_url,
                "Child": _host_of(child_url) or child_url,
                "PolicyCat": "Unknown",
                "Essential": False,
                "PreConsent": False,
                "Violation": False,
                "FirstSeqChild": None,
            })
            continue

        # child is a Series (a row from df_requests)
        rows.append({
            "Parent": _host_of(parent_url) or parent_url,
            "Child": _host_of(child_url) or child_url,
            "PolicyCat": child.get("PolicyCat", "Unknown"),
            "Essential": bool(child.get("Essential", False)),
            "PreConsent": bool(child.get("PreConsent", False)),
            "Violation": bool(child.get("Violation", False)),
            "FirstSeqChild": int(child.get("Seq #", 0) or 0),
        })

    if not rows:
        return pd.DataFrame(columns=[
            "Parent", "Child", "PolicyCat", "Essential", "PreConsent", "Violation", "FirstSeqChild"
        ])

    df = pd.DataFrame(rows)
    df = df.sort_values(
        ["Violation", "PreConsent", "Parent", "Child"],
        ascending=[False, False, True, True]
    ).reset_index(drop=True)
    return df

def top_parents_summary(tag_chains_df: pd.DataFrame) -> pd.DataFrame:
    if tag_chains_df is None or tag_chains_df.empty:
        return pd.DataFrame(columns=["Parent","Count","PreConsent","Violations","FirstSeqMin"])
    agg = (tag_chains_df
           .groupby("Parent")
           .agg(Count=("Child","count"),
                PreConsent=("PreConsent","sum"),
                Violations=("Violation","sum"),
                FirstSeqMin=("FirstSeqChild","min"))
           .reset_index()
           .sort_values(["Violations","PreConsent","Count"], ascending=[False,False,False]))
    return agg

# =============================== STYLING ===============================
def _hex_to_rgb(hex_color: str):
    h = hex_color.lstrip("#")
    if len(h) == 3:
        h = "".join(ch*2 for ch in h)
    r = int(h[0:2], 16); g = int(h[2:4], 16); b = int(h[4:6], 16)
    return r, g, b

def _contrast_text_for(bg_hex: str) -> str:
    try:
        r, g, b = _hex_to_rgb(bg_hex)
        lum = 0.2126*(r/255) + 0.7152*(g/255) + 0.0722*(b/255)
        return "#000000" if lum > 0.6 else "#FFFFFF"
    except Exception:
        return "#000000"

def color_for_row(row):
    if row.get("Violation", False):
        return VIOLATION_COLOR
    return CATEGORY_COLORS.get(str(row.get("Category","")), "#ECEFF1")

def style_dataframe(df: pd.DataFrame) -> Styler:
    if df.empty:
        return df.style
    def style_rows(s: pd.Series):
        bg = color_for_row(s.to_dict())
        fg = _contrast_text_for(bg)
        return [f"background-color: {bg}; color: {fg};"] * len(s)
    return df.style.apply(style_rows, axis=1)

# =============================== EXPORTS ===============================
def to_csv_bytes(df: pd.DataFrame) -> bytes:
    return df.to_csv(index=False).encode("utf-8")

def _safe_sheet(name: str) -> str:
    bad = set('[]:*?/\\')
    safe = "".join('_' if ch in bad else ch for ch in (name or "Sheet"))
    safe = safe.strip().strip("'")
    return safe[:31] or "Sheet"

def to_xlsx_bytes(df: pd.DataFrame,
                  cookies: pd.DataFrame | None,
                  tag_chains: pd.DataFrame | None,
                  top_parents: pd.DataFrame | None,
                  title="HAR Export") -> bytes:
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter", engine_kwargs={"options":{"strings_to_urls": False}}) as writer:
        wb = writer.book
        header_fmt = wb.add_format({"bold": True, "bg_color": "#000000", "font_color":"#FFFFFF"})

        # HAR sheet
        sh = _safe_sheet("HAR")
        df.to_excel(writer, sheet_name=sh, index=False, startrow=1)
        ws = writer.sheets[sh]
        ws.write(0, 0, title, wb.add_format({"bold": True}))
        for i, col in enumerate(df.columns):
            ws.write(1, i, col, header_fmt)
        widths = {"Seq #":8,"Name":90,"Status":10,"Type":28,"Category":12,"PolicyCat":16,"Essential":10,
                  "PreConsent":12,"Violation":10,"Started at":16,"Size":10,"Time":10,"PolicySource":18}
        for i, col in enumerate(df.columns):
            ws.set_column(i, i, widths.get(col, 14))
        # row fills
        for r in range(2, 2+len(df)):
            viol = bool(df.iloc[r-2].get("Violation", False))
            bg = VIOLATION_COLOR if viol else CATEGORY_COLORS.get(df.iloc[r-2].get("Category",""), "#ECEFF1")
            ws.set_row(r, None, wb.add_format({"bg_color": bg}))

        # Legend
        leg = _safe_sheet("Legend")
        ws2 = wb.add_worksheet(leg)
        ws2.write_row(0, 0, ["Key", "Color / Meaning"])
        i = 1
        for k, v in CATEGORY_COLORS.items():
            ws2.write_row(i, 0, [k, v])
            ws2.set_row(i, None, wb.add_format({"bg_color": v}))
            i += 1
        ws2.write_row(i+1, 0, ["Violation rows", VIOLATION_COLOR])
        ws2.set_row(i+1, None, wb.add_format({"bg_color": VIOLATION_COLOR}))
        ws2.write_row(i+2, 0, ["Pre-consent (Essential)", PRECONSENT_FILL])
        ws2.set_row(i+2, None, wb.add_format({"bg_color": PRECONSENT_FILL}))

        # Cookies
        if cookies is not None and not cookies.empty:
            csh = _safe_sheet("Cookies - Summary")
            cookies.to_excel(writer, sheet_name=csh, index=False, startrow=1)
            ws3 = writer.sheets[csh]
            for i, col in enumerate(cookies.columns):
                ws3.write(1, i, col, header_fmt)
            cwidths = {"Cookie":34,"Domain":44,"PolicyCat":16,"Essential":10,"First Seq #":12,
                       "Times Set":12,"Secure":10,"HttpOnly":10,"PreConsent":12,"Violation":10,"Source":18,"PolicySource":18}
            for i, col in enumerate(cookies.columns):
                ws3.set_column(i, i, cwidths.get(col, 16))
            # color: red violations; amber for pre-consent (essential)
            for r in range(2, 2+len(cookies)):
                row = cookies.iloc[r-2]
                if bool(row.get("Violation", False)):
                    ws3.set_row(r, None, wb.add_format({"bg_color": VIOLATION_COLOR}))
                elif bool(row.get("PreConsent", False)):
                    ws3.set_row(r, None, wb.add_format({"bg_color": PRECONSENT_FILL}))

        # Tag Chains
        if tag_chains is not None and not tag_chains.empty:
            tsh = _safe_sheet("Tag Chains")
            tag_chains.to_excel(writer, sheet_name=tsh, index=False, startrow=1)
            ws4 = writer.sheets[tsh]
            for i, col in enumerate(tag_chains.columns):
                ws4.write(1, i, col, header_fmt)
            twidths = {"Parent":34,"Child":44,"PolicyCat":16,"Essential":10,"PreConsent":12,"Violation":10,"FirstSeqChild":12}
            for i, col in enumerate(tag_chains.columns):
                ws4.set_column(i, i, twidths.get(col, 16))
            for r in range(2, 2+len(tag_chains)):
                row = tag_chains.iloc[r-2]
                if bool(row.get("Violation", False)):
                    ws4.set_row(r, None, wb.add_format({"bg_color": VIOLATION_COLOR}))
                elif bool(row.get("PreConsent", False)):
                    ws4.set_row(r, None, wb.add_format({"bg_color": PRECONSENT_FILL}))

        # Top Parents
        if top_parents is not None and not top_parents.empty:
            psh = _safe_sheet("Top Parents")
            top_parents.to_excel(writer, sheet_name=psh, index=False, startrow=1)
            ws5 = writer.sheets[psh]
            for i, col in enumerate(top_parents.columns):
                ws5.write(1, i, col, header_fmt)
            ws5.set_column(0, 0, 34)
            ws5.set_column(1, 1, 10)
            ws5.set_column(2, 2, 12)
            ws5.set_column(3, 3, 12)
            ws5.set_column(4, 4, 12)
    return output.getvalue()

# PDF helpers
_ZWSP = "\u200b"
def _soft_wrap_text(s: str, max_len: int = 1200) -> str:
    if s is None:
        return ""
    s = str(s)
    if len(s) > max_len:
        s = s[: max_len - 1] + "…"
    s = re.sub(r"([\/\?\&\=\.\:\-\_\~\#\,])", r"\1" + _ZWSP, s)
    s = re.sub(r"([A-Fa-f0-9]{20})(?=[A-Fa-f0-9])", r"\1" + _ZWSP, s)
    s = "".join(ch for ch in s if ch in string.printable or ord(ch) >= 0x20)
    return s

def _pdf_table(data, col_widths):
    tbl = Table(data, repeatRows=1, colWidths=col_widths)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.black),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,0), 9),
        ("GRID", (0,0), (-1,-1), 0.25, colors.HexColor("#2A2F34")),
        ("FONTSIZE", (0,1), (-1,-1), 8),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
    ]))
    return tbl

def to_pdf_bytes(df: pd.DataFrame, cookies_df: pd.DataFrame | None, title="HAR Export – Report") -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4),
                            leftMargin=24, rightMargin=24, topMargin=24, bottomMargin=24)
    styles = getSampleStyleSheet()
    cell_style = ParagraphStyle("cell", parent=styles["BodyText"], fontSize=8, leading=11, wordWrap="CJK", splitLongWords=True)

    elems = []
    elems.append(Paragraph(title, styles["Heading2"]))
    elems.append(Spacer(1, 6))

    vcount = int(df["Violation"].sum()) if not df.empty and "Violation" in df.columns else 0
    elems.append(Paragraph(f"Violations detected: <b>{vcount}</b>", styles["Normal"]))
    elems.append(Spacer(1, 8))

    # Requests table
    cols = ["Seq #","Name","Status","Type","Category","PolicyCat","Essential","PreConsent","Violation"]
    if not df.empty:
        header = cols
        chunk = 20
        for start in range(0, len(df), chunk):
            part = df.iloc[start:start+chunk].copy()
            data = [header]
            for _, r in part.iterrows():
                name = Paragraph(_soft_wrap_text(str(r["Name"])), cell_style)
                typ = Paragraph(_soft_wrap_text(str(r.get("Type","")), 200), cell_style)
                data.append([
                    str(r["Seq #"]), name, str(r["Status"]), typ,
                    str(r["Category"]), str(r["PolicyCat"]), str(r["Essential"]),
                    str(r["PreConsent"]), str(r["Violation"])
                ])
            tbl = _pdf_table(data, [32, None, 36, 60, 60, 64, 50, 60, 50])
            # color rows (red = violation)
            for ridx in range(1, len(data)):
                row = part.iloc[ridx-1]
                if bool(row.get("Violation", False)):
                    tbl.setStyle(TableStyle([("BACKGROUND", (0, ridx), (-1, ridx), colors.HexColor(VIOLATION_COLOR))]))
            elems.append(tbl)
    else:
        elems.append(Paragraph("No requests parsed.", styles["Italic"]))
    elems.append(Spacer(1, 8))

    # Cookies
    elems.append(Paragraph("Cookies", styles["Heading4"]))
    if cookies_df is None or cookies_df.empty:
        elems.append(Paragraph("No cookies detected (or redacted by browser export).", styles["Normal"]))
    else:
        ccols = ["Cookie","Domain","PolicyCat","Essential","First Seq #","PreConsent","Violation","Source"]
        chunk = 26
        for start in range(0, len(cookies_df), chunk):
            ck = cookies_df.iloc[start:start+chunk].copy()
            data_c = [ccols] + ck[ccols].astype(str).values.tolist()
            tbl = _pdf_table(data_c, [160, 180, 80, 60, 60, 60, 60, 80])
            for ridx in range(1, len(data_c)):
                row = ck.iloc[ridx-1]
                if bool(row.get("Violation", False)):
                    tbl.setStyle(TableStyle([("BACKGROUND", (0, ridx), (-1, ridx), colors.HexColor(VIOLATION_COLOR))]))
                elif bool(row.get("PreConsent", False)):
                    tbl.setStyle(TableStyle([("BACKGROUND", (0, ridx), (-1, ridx), colors.HexColor(PRECONSENT_FILL))]))
            elems.append(tbl)

    doc.build(elems)
    return buf.getvalue()

# =============================== UI ===============================
st.title("Tag Audit Tool (HAR Analyzer)")

with st.sidebar:
    st.markdown("**Export a HAR from DevTools → Network → ⋯ → Save all as HAR**")
    st.markdown("Upload a single HAR, or enable Diff Mode to compare **Baseline** vs **Test**.")
    st.divider()
    diff_mode = st.checkbox("Diff Mode (Baseline vs Test)", value=False)
    baseline = None
    test = None
    if diff_mode:
        baseline = st.file_uploader("Baseline HAR (all tags paused)", type=["har"], key="baseline_har")
        test = st.file_uploader("Test HAR (tag enabled)", type=["har"], key="test_har")
    else:
        har_file = st.file_uploader("HAR file", type=["har"], key="single_har")

    st.divider()
    use_builtin_policy = st.checkbox("Use built-in Google Essential policy", value=True,
                                     help="Marks common Google domains & cookies as Essential by default.")
    st.caption("Consent boundary decides what counts as **pre-consent** (Seq # < boundary).")
    consent_seq_ui = st.number_input("Consent Boundary (Seq #)", min_value=1, value=999999, step=1)

    st.divider()
    exp_csv = st.empty()
    exp_xlsx = st.empty()
    exp_pdf = st.empty()

def load_har(file) -> dict:
    if not file:
        return {}
    try:
        raw = file.read()
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="ignore")
        return json.loads(raw)
    except Exception:
        try:
            file.seek(0)
            return json.load(file)
        except Exception:
            return {}

# =============================== FLOW ===============================
if not diff_mode:
    if 'har_file' in locals() and har_file:
        har_json = load_har(har_file)
        maybe_warn_har_creator(har_json)

        entries = (har_json or {}).get("log", {}).get("entries", []) or []
        boundary = consent_seq_ui if consent_seq_ui < 999999 else estimate_consent_boundary(entries)

        # policy
        POLICY = Policy()
        POLICY.load_builtins(enable=use_builtin_policy)

        # requests
        df = har_to_df(har_json, POLICY, boundary)

        # cookies (merge sources)
        cookies = harvest_cookies(har_json, POLICY, boundary)
        cookies = dedup(cookies, infer_client_cookies(har_json, POLICY, boundary))
        cookies = dedup(cookies, infer_js_cookie_writes(har_json, POLICY, boundary))

        # tag chains + summary
        chains = build_tag_chains(har_json, df)
        parents = top_parents_summary(chains)

        st.subheader("Requests")
        st.caption(f"{len(df)} requests parsed · Consent boundary: {boundary} · Violations = Pre-consent & Non-Essential")
        st.dataframe(style_dataframe(df), use_container_width=True, hide_index=True)

        st.subheader("Cookies")
        st.dataframe(cookies, use_container_width=True, hide_index=True)

        st.subheader("Tag Chains")
        st.dataframe(chains, use_container_width=True, hide_index=True)

        st.subheader("Top Parents")
        st.dataframe(parents, use_container_width=True, hide_index=True)

        # exports
        csv_bytes = to_csv_bytes(df)
        xlsx_bytes = to_xlsx_bytes(df, cookies, chains, parents, title="HAR Export (Single)")
        pdf_bytes = to_pdf_bytes(df, cookies, title="HAR Export – Single")

        with st.sidebar:
            exp_csv.download_button("CSV (no colors)", data=csv_bytes, file_name="har_export.csv", mime="text/csv")
            exp_xlsx.download_button("Excel (colored)", data=xlsx_bytes, file_name="har_export.xlsx",
                                     mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            exp_pdf.download_button("PDF (colored)", data=pdf_bytes, file_name="har_export.pdf", mime="application/pdf")
else:
    if baseline and test:
        har_base = load_har(baseline)
        har_test = load_har(test)

        maybe_warn_har_creator(har_base)
        maybe_warn_har_creator(har_test)

        entries_test = (har_test or {}).get("log", {}).get("entries", []) or []
        boundary = consent_seq_ui if consent_seq_ui < 999999 else estimate_consent_boundary(entries_test)

        # policy
        POLICY = Policy()
        POLICY.load_builtins(enable=use_builtin_policy)

        # requests
        df_base = har_to_df(har_base, POLICY, boundary)
        df_test = har_to_df(har_test, POLICY, boundary)
        df_added = diff_requests(df_base, df_test)

        # cookies (merge) + diff
        cookies_base = harvest_cookies(har_base, POLICY, boundary)
        cookies_base = dedup(cookies_base, infer_client_cookies(har_base, POLICY, boundary))
        cookies_base = dedup(cookies_base, infer_js_cookie_writes(har_base, POLICY, boundary))

        cookies_test = harvest_cookies(har_test, POLICY, boundary)
        cookies_test = dedup(cookies_test, infer_client_cookies(har_test, POLICY, boundary))
        cookies_test = dedup(cookies_test, infer_js_cookie_writes(har_test, POLICY, boundary))

        cookies_added = diff_cookies(cookies_base, cookies_test)

        # chains from TEST (context for added) + host/URL match filter
        chains_test = build_tag_chains(har_test, df_test)
        added_urls = set(df_added["Name"].astype(str))
        added_hosts = { _host_of(u) or u for u in added_urls }
        child_keys = added_urls | added_hosts
        if not chains_test.empty:
            chains_added = chains_test[chains_test["Child"].isin(child_keys)].reset_index(drop=True)
        else:
            chains_added = chains_test

        parents_added = top_parents_summary(chains_added)

        st.subheader("Requests: Added vs Baseline")
        st.caption(f"Baseline={len(df_base)} · Test={len(df_test)} · Added={len(df_added)} · Consent boundary: {boundary} · Violations = Pre-consent & Non-Essential")
        st.dataframe(style_dataframe(df_added), use_container_width=True, hide_index=True)

        st.subheader("Cookies: Added vs Baseline")
        st.dataframe(cookies_added, use_container_width=True, hide_index=True)

        st.subheader("Tag Chains (Added)")
        st.dataframe(chains_added, use_container_width=True, hide_index=True)

        st.subheader("Top Parents (Added)")
        st.dataframe(parents_added, use_container_width=True, hide_index=True)

        # exports
        csv_bytes = to_csv_bytes(df_added)
        xlsx_bytes = to_xlsx_bytes(df_added, cookies_added, chains_added, parents_added, title="Diff Report – Added vs Baseline")
        pdf_bytes = to_pdf_bytes(df_added, cookies_added, title="Diff Report – Added vs Baseline")

        with st.sidebar:
            exp_csv.download_button("CSV (no colors) – Diff", data=csv_bytes, file_name="diff_requests_added.csv", mime="text/csv")
            exp_xlsx.download_button("Excel (colored) – Diff", data=xlsx_bytes, file_name="diff_report.xlsx",
                                     mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            exp_pdf.download_button("PDF (colored) – Diff", data=pdf_bytes, file_name="diff_report.pdf", mime="application/pdf")
    else:
        st.info("Upload **both** Baseline and Test HAR files to view the diff.")
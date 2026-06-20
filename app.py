import streamlit as st
import sys, os

sys.path.insert(0, os.path.dirname(__file__))

from backend.identity_resolver import IdentityResolver
from backend.risk_engine import RiskEngine
from backend.anomaly_detection import AnomalyDetectionEngine

# ── Page Config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="IdentityLens AI — Enterprise Security Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Dark SOC Master CSS ────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=Roboto+Mono:wght@400;500&display=swap');

/* ─── CSS Variables (Dark SOC Palette) ───────── */
:root {
    --bg-primary:     #0F172A;
    --bg-secondary:   #1E293B;
    --bg-tertiary:    #243044;
    --card-bg:        rgba(30,41,59,0.8);
    --card-border:    rgba(148,163,184,0.12);
    --card-hover:     rgba(148,163,184,0.18);
    --glass-bg:       rgba(15,23,42,0.6);
    --accent:         #3B82F6;
    --accent-glow:    rgba(59,130,246,0.25);
    --accent-dark:    #2563EB;
    --critical:       #EF4444;
    --critical-glow:  rgba(239,68,68,0.25);
    --high:           #F97316;
    --high-glow:      rgba(249,115,22,0.25);
    --medium:         #EAB308;
    --medium-glow:    rgba(234,179,8,0.25);
    --low:            #22C55E;
    --low-glow:       rgba(34,197,94,0.25);
    --text-primary:   #F1F5F9;
    --text-secondary: #94A3B8;
    --text-muted:     #64748B;
    --border:         rgba(148,163,184,0.1);
    --border-strong:  rgba(148,163,184,0.2);
    --shadow-sm:      0 1px 3px rgba(0,0,0,0.4);
    --shadow-md:      0 4px 20px rgba(0,0,0,0.5);
    --shadow-lg:      0 8px 40px rgba(0,0,0,0.6);
    --radius:         8px;
    --radius-md:      12px;
    --radius-lg:      16px;
    --font:           'Inter', -apple-system, sans-serif;
    --font-mono:      'Roboto Mono', monospace;
}

/* ─── Reset ─────────────────────────── */
*, *::before, *::after { box-sizing: border-box; }

html, body, [class*="css"], .stApp {
    font-family: var(--font) !important;
    background: var(--bg-primary) !important;
    color: var(--text-primary) !important;
}

/* ─── Hide Streamlit chrome ─────────── */
#MainMenu, footer, header,
[data-testid="stToolbar"],
[data-testid="collapsedControl"],
[data-testid="stSidebarCollapseButton"] {
    visibility: hidden !important;
    height: 0 !important;
    display: none !important;
    width: 0 !important;
}

/* ─── Layout ────────────────────────── */
.stApp { background: var(--bg-primary) !important; }
.main .block-container {
    padding: 0 !important;
    max-width: 100% !important;
}

/* ─── Sidebar (sign-out only) ───────── */
[data-testid="stSidebar"] {
    background: var(--bg-secondary) !important;
    border-right: 1px solid var(--card-border) !important;
}
[data-testid="stSidebar"] button {
    color: var(--text-secondary) !important;
}

/* ─── Scrollbar ─────────────────────── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: var(--bg-primary); }
::-webkit-scrollbar-thumb { background: var(--bg-tertiary); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--accent); }

/* ════════════════════════════════════
   UTILITY / ANIMATIONS
   ════════════════════════════════════ */
@keyframes pulse-dot {
    0%,100%{ opacity:1; transform:scale(1); }
    50%{ opacity:0.4; transform:scale(1.5); }
}
@keyframes blink {
    0%,100%{ opacity:1; }
    50%{ opacity:0.3; }
}
@keyframes fadeSlideUp {
    from{ opacity:0; transform:translateY(14px); }
    to{ opacity:1; transform:translateY(0); }
}
@keyframes shimmer {
    0%{ background-position:200% center; }
    100%{ background-position:-200% center; }
}
@keyframes glow-pulse {
    0%,100%{ box-shadow: 0 0 8px var(--accent-glow); }
    50%{ box-shadow: 0 0 20px var(--accent-glow), 0 0 40px var(--accent-glow); }
}
@keyframes count-up {
    from{ opacity:0; transform:translateY(8px); }
    to{ opacity:1; transform:translateY(0); }
}
@keyframes skeleton {
    0%{ background-position:-200px 0; }
    100%{ background-position:calc(200px + 100%) 0; }
}

/* Skeleton loader */
.skeleton {
    background: linear-gradient(90deg,
        var(--bg-secondary) 25%,
        var(--bg-tertiary) 50%,
        var(--bg-secondary) 75%);
    background-size: 200px 100%;
    animation: skeleton 1.5s infinite;
    border-radius: var(--radius);
}

/* Live dot */
.live-dot {
    width: 7px; height: 7px;
    border-radius: 50%;
    background: var(--low);
    display: inline-block;
    animation: pulse-dot 2s infinite;
    flex-shrink: 0;
}
.live-dot.red { background: var(--critical); }
.live-dot.orange { background: var(--high); }
.live-dot.blue { background: var(--accent); }

/* ════════════════════════════════════
   TOP UTILITY BAR
   ════════════════════════════════════ */
.il-utility-bar {
    background: #080E1A;
    padding: 0 2rem;
    height: 32px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: 0.68rem;
    color: var(--text-muted);
    border-bottom: 1px solid var(--border);
}
.il-util-left, .il-util-right {
    display: flex; align-items: center; gap: 1.2rem;
}
.il-util-link {
    color: var(--text-muted);
    text-decoration: none;
    font-size: 0.68rem;
    cursor: pointer;
    transition: color 0.15s;
}
.il-util-link:hover { color: var(--text-secondary); }

/* ════════════════════════════════════
   NAVIGATION BAR
   ════════════════════════════════════ */
.il-brand {
    display: flex; align-items: center;
    gap: 0.75rem; flex-shrink: 0;
    padding-left: 2rem;
}
.il-logo {
    width: 36px; height: 36px;
    background: linear-gradient(135deg, var(--accent), #1D4ED8);
    border-radius: 10px;
    display: grid; place-items: center;
    font-size: 1.1rem;
    box-shadow: 0 0 16px var(--accent-glow);
}
.il-brand-text { display: flex; flex-direction: column; }
.il-brand-name {
    font-size: 0.82rem; font-weight: 800;
    color: var(--text-primary);
    letter-spacing: 0.3px; line-height: 1.1;
}
.il-brand-sub {
    font-size: 0.6rem; color: var(--text-muted);
    font-weight: 400; letter-spacing: 0.2px;
}

/* Nav bar wrapper */
[data-testid="stHorizontalBlock"]:has(> [data-testid="column"] .il-brand) {
    background: rgba(8,14,26,0.95) !important;
    backdrop-filter: blur(20px) !important;
    border-bottom: 1px solid var(--border) !important;
    box-shadow: 0 2px 20px rgba(0,0,0,0.4) !important;
    padding: 0 !important;
    height: 64px !important;
    align-items: center !important;
    margin-bottom: 0 !important;
    position: sticky !important;
    top: 0 !important;
    z-index: 100 !important;
}
[data-testid="stHorizontalBlock"]:has(> [data-testid="column"] .il-brand) > [data-testid="column"] {
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
}
[data-testid="stHorizontalBlock"]:has(> [data-testid="column"] .il-brand) > [data-testid="column"]:first-child {
    justify-content: flex-start !important;
}
[data-testid="stHorizontalBlock"]:has(> [data-testid="column"] .il-brand) > [data-testid="column"]:last-child {
    justify-content: flex-end !important;
    padding-right: 2rem !important;
}

/* Nav links */
[data-testid="stPageLink-NavLink"] {
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    height: 64px !important;
    text-decoration: none !important;
    color: var(--text-muted) !important;
    font-size: 0.78rem !important;
    font-weight: 500 !important;
    border-bottom: 2px solid transparent !important;
    border-radius: 0 !important;
    background: transparent !important;
    padding: 0 0.25rem !important;
    margin: 0 !important;
    width: 100% !important;
    transition: all 0.2s ease !important;
    letter-spacing: 0.2px !important;
}
[data-testid="stPageLink-NavLink"]:hover {
    color: var(--text-primary) !important;
    border-bottom-color: var(--accent) !important;
    background: rgba(59,130,246,0.05) !important;
}
[data-testid="stPageLink-NavLink"][data-active="true"],
[data-testid="stPageLink-NavLink"][aria-current="page"] {
    color: var(--accent) !important;
    font-weight: 600 !important;
    border-bottom-color: var(--accent) !important;
    background: rgba(59,130,246,0.08) !important;
}

/* User chip */
.il-user-chip {
    display: flex; align-items: center; gap: 0.5rem;
    padding: 0.3rem 0.75rem;
    border: 1px solid var(--border-strong);
    border-radius: 100px;
    font-size: 0.75rem; color: var(--text-secondary);
    cursor: pointer;
    transition: all 0.2s;
    background: var(--card-bg);
}
.il-user-chip:hover {
    border-color: var(--accent);
    color: var(--text-primary);
    box-shadow: 0 0 12px var(--accent-glow);
}
.il-user-avatar {
    width: 24px; height: 24px;
    background: linear-gradient(135deg, var(--accent), #1D4ED8);
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 0.62rem; font-weight: 700; color: white;
    flex-shrink: 0;
}

/* ════════════════════════════════════
   STATS BAR
   ════════════════════════════════════ */
.il-stats-bar {
    background: rgba(8,14,26,0.8);
    backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--border);
    padding: 0.5rem 2rem;
    display: flex;
    align-items: center;
    gap: 0;
}
.il-stat {
    display: flex; align-items: center; gap: 0.5rem;
    padding: 0 1.25rem 0 0;
    margin-right: 1.25rem;
    border-right: 1px solid var(--border);
    font-size: 0.75rem;
}
.il-stat:last-of-type { border-right: none; }
.il-stat-label { color: var(--text-muted); font-weight: 400; }
.il-stat-value { color: var(--text-primary); font-weight: 700; }
.il-stat-value.red   { color: var(--critical); }
.il-stat-value.orange{ color: var(--high); }
.il-stat-value.green { color: var(--low); }
.il-stat-value.blue  { color: var(--accent); }

/* ════════════════════════════════════
   GLOBAL PAGE CONTENT
   ════════════════════════════════════ */
.il-page { padding: 1.75rem 2rem 3rem; max-width: 1440px; margin: 0 auto; }

/* Page header */
.il-page-header {
    display: flex; align-items: flex-start; justify-content: space-between;
    flex-wrap: wrap; gap: 1rem;
    margin-bottom: 1.75rem;
    padding-bottom: 1.2rem;
    border-bottom: 1px solid var(--border);
}
.il-page-eyebrow {
    font-size: 0.65rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: 1.5px; color: var(--accent); margin-bottom: 0.3rem;
}
.il-page-title {
    font-size: 1.5rem; font-weight: 800; color: var(--text-primary);
    letter-spacing: -0.5px; margin: 0 0 0.25rem; line-height: 1.2;
}
.il-page-desc {
    font-size: 0.85rem; color: var(--text-secondary); margin: 0; font-weight: 400;
}

/* ════════════════════════════════════
   GLASSMORPHISM CARDS
   ════════════════════════════════════ */
.glass-card {
    background: var(--card-bg);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border: 1px solid var(--card-border);
    border-radius: var(--radius-md);
    padding: 1.25rem 1.4rem;
    box-shadow: var(--shadow-md);
    transition: all 0.25s ease;
    animation: fadeSlideUp 0.4s ease both;
}
.glass-card:hover {
    border-color: var(--card-hover);
    box-shadow: var(--shadow-lg);
    transform: translateY(-1px);
}

/* KPI Card */
.kpi-card {
    background: var(--card-bg);
    backdrop-filter: blur(20px);
    border: 1px solid var(--card-border);
    border-radius: var(--radius-md);
    padding: 1.2rem 1.3rem;
    box-shadow: var(--shadow-md);
    transition: all 0.3s ease;
    animation: fadeSlideUp 0.4s ease both;
    position: relative; overflow: hidden;
}
.kpi-card::before {
    content: '';
    position: absolute; left: 0; top: 0; bottom: 0;
    width: 3px; border-radius: 3px 0 0 3px;
    background: var(--accent);
}
.kpi-card.critical::before { background: var(--critical); box-shadow: 0 0 12px var(--critical-glow); }
.kpi-card.high::before    { background: var(--high);     box-shadow: 0 0 12px var(--high-glow); }
.kpi-card.medium::before  { background: var(--medium);   box-shadow: 0 0 12px var(--medium-glow); }
.kpi-card.low::before     { background: var(--low);      box-shadow: 0 0 12px var(--low-glow); }
.kpi-card.accent::before  { background: var(--accent);   box-shadow: 0 0 12px var(--accent-glow); }
.kpi-card:hover {
    border-color: var(--card-hover);
    box-shadow: var(--shadow-lg);
    transform: translateY(-2px);
}
.kpi-card:hover.critical { box-shadow: var(--shadow-lg), 0 0 20px var(--critical-glow); }
.kpi-card:hover.high     { box-shadow: var(--shadow-lg), 0 0 20px var(--high-glow); }
.kpi-card:hover.accent   { box-shadow: var(--shadow-lg), 0 0 20px var(--accent-glow); }
.kpi-card:hover.low      { box-shadow: var(--shadow-lg), 0 0 20px var(--low-glow); }

.kpi-label {
    font-size: 0.65rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: 1.2px; color: var(--text-muted); margin-bottom: 0.5rem;
}
.kpi-value {
    font-size: 2rem; font-weight: 800; color: var(--text-primary);
    letter-spacing: -1px; line-height: 1;
    animation: count-up 0.5s ease both;
}
.kpi-value.critical { color: var(--critical); }
.kpi-value.high     { color: var(--high); }
.kpi-value.medium   { color: var(--medium); }
.kpi-value.low      { color: var(--low); }
.kpi-value.accent   { color: var(--accent); }
.kpi-sub {
    font-size: 0.7rem; color: var(--text-muted);
    margin-top: 0.4rem; line-height: 1.4;
}
.kpi-icon {
    position: absolute; right: 1rem; top: 50%;
    transform: translateY(-50%);
    font-size: 2rem; opacity: 0.08;
}

/* ════════════════════════════════════
   STREAMLIT METRIC OVERRIDE (dark)
   ════════════════════════════════════ */
div[data-testid="stMetric"] {
    background: var(--card-bg) !important;
    backdrop-filter: blur(20px) !important;
    border: 1px solid var(--card-border) !important;
    border-radius: var(--radius-md) !important;
    padding: 1.2rem 1.3rem !important;
    box-shadow: var(--shadow-md) !important;
    transition: all 0.25s ease !important;
    position: relative; overflow: hidden;
}
div[data-testid="stMetric"]::before {
    content: '';
    position: absolute;
    left: 0; top: 0; bottom: 0;
    width: 3px;
    background: var(--accent);
}
div[data-testid="stMetric"]:hover {
    box-shadow: var(--shadow-lg), 0 0 20px var(--accent-glow) !important;
    transform: translateY(-1px);
    border-color: var(--card-hover) !important;
}
div[data-testid="stMetric"] label {
    color: var(--text-muted) !important;
    font-size: 0.65rem !important;
    font-weight: 700 !important;
    letter-spacing: 1.2px !important;
    text-transform: uppercase !important;
}
div[data-testid="stMetricValue"] {
    color: var(--text-primary) !important;
    font-size: 1.85rem !important;
    font-weight: 800 !important;
    letter-spacing: -0.8px !important;
}
div[data-testid="stMetricDelta"] { font-size: 0.75rem !important; }

/* ════════════════════════════════════
   SECTION DIVIDERS
   ════════════════════════════════════ */
.il-section {
    display: flex; align-items: center; gap: 0.75rem;
    margin: 2rem 0 1rem;
}
.il-section h2, .il-section h3 {
    font-size: 0.9rem !important; font-weight: 700 !important;
    color: var(--text-primary) !important; margin: 0 !important;
    white-space: nowrap;
}
.il-section::after {
    content: ''; flex: 1; height: 1px; background: var(--border);
}
.section-title h2 {
    font-size: 0.9rem; font-weight: 700; color: var(--text-primary);
    margin: 1.6rem 0 0.8rem;
    padding-bottom: 0.4rem;
    border-bottom: 1px solid var(--border);
    display: inline-block;
}

/* ════════════════════════════════════
   BADGES
   ════════════════════════════════════ */
.badge {
    display: inline-flex; align-items: center;
    padding: 0.18rem 0.6rem;
    border-radius: 100px; font-size: 0.65rem; font-weight: 700; letter-spacing: 0.5px;
    text-transform: uppercase;
}
.badge-critical {
    background: rgba(239,68,68,0.12); color: var(--critical);
    border: 1px solid rgba(239,68,68,0.25);
}
.badge-high {
    background: rgba(249,115,22,0.12); color: var(--high);
    border: 1px solid rgba(249,115,22,0.25);
}
.badge-medium {
    background: rgba(234,179,8,0.12); color: var(--medium);
    border: 1px solid rgba(234,179,8,0.25);
}
.badge-low {
    background: rgba(34,197,94,0.12); color: var(--low);
    border: 1px solid rgba(34,197,94,0.25);
}
.badge-info {
    background: rgba(59,130,246,0.12); color: var(--accent);
    border: 1px solid rgba(59,130,246,0.25);
}
.badge-purple {
    background: rgba(139,92,246,0.12); color: #8B5CF6;
    border: 1px solid rgba(139,92,246,0.25);
}

/* ════════════════════════════════════
   TABLES / DATAFRAME
   ════════════════════════════════════ */
.stDataFrame {
    border-radius: var(--radius-md) !important;
    overflow: hidden !important;
    border: 1px solid var(--card-border) !important;
    box-shadow: var(--shadow-md) !important;
}
.stDataFrame iframe {
    background: var(--bg-secondary) !important;
}

/* ════════════════════════════════════
   BUTTONS
   ════════════════════════════════════ */
.stButton > button {
    border-radius: var(--radius) !important;
    font-weight: 600 !important;
    font-size: 0.8rem !important;
    letter-spacing: 0.3px !important;
    transition: all 0.2s ease !important;
    font-family: var(--font) !important;
}
.stButton > button[kind="primary"] {
    background: linear-gradient(135deg, var(--accent), var(--accent-dark)) !important;
    color: white !important;
    border: none !important;
    box-shadow: 0 0 16px var(--accent-glow) !important;
}
.stButton > button[kind="primary"]:hover {
    box-shadow: 0 0 24px var(--accent-glow), 0 4px 12px rgba(0,0,0,0.3) !important;
    transform: translateY(-1px) !important;
}
.stButton > button[kind="secondary"] {
    background: var(--bg-secondary) !important;
    border: 1px solid var(--border-strong) !important;
    color: var(--text-secondary) !important;
}
.stButton > button[kind="secondary"]:hover {
    border-color: var(--accent) !important;
    color: var(--accent) !important;
    box-shadow: 0 0 12px var(--accent-glow) !important;
}

/* ════════════════════════════════════
   INPUTS / SELECTS
   ════════════════════════════════════ */
.stTextInput > div > div > input,
.stSelectbox > div > div,
.stMultiSelect > div > div {
    background: var(--bg-secondary) !important;
    border: 1px solid var(--border-strong) !important;
    border-radius: var(--radius) !important;
    color: var(--text-primary) !important;
    font-size: 0.875rem !important;
    font-family: var(--font) !important;
}
.stTextInput > div > div > input:focus {
    border-color: var(--accent) !important;
    box-shadow: 0 0 0 3px var(--accent-glow) !important;
}
div[data-testid="InputInstructions"] { display: none !important; }

/* ════════════════════════════════════
   TABS
   ════════════════════════════════════ */
.stTabs [data-baseweb="tab-list"] {
    background: var(--bg-secondary) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius) !important;
    padding: 3px !important;
    gap: 2px !important;
    width: fit-content !important;
}
.stTabs [data-baseweb="tab"] {
    background: transparent !important;
    border-radius: 6px !important;
    font-size: 0.8rem !important;
    font-weight: 500 !important;
    color: var(--text-muted) !important;
    padding: 0.35rem 1rem !important;
    font-family: var(--font) !important;
}
.stTabs [aria-selected="true"] {
    background: var(--accent) !important;
    color: white !important;
    font-weight: 600 !important;
    box-shadow: 0 0 12px var(--accent-glow) !important;
}
[data-baseweb="tab-panel"] {
    background: transparent !important;
}

/* ════════════════════════════════════
   EXPANDER
   ════════════════════════════════════ */
[data-testid="stExpander"] {
    background: var(--card-bg) !important;
    border: 1px solid var(--card-border) !important;
    border-radius: var(--radius-md) !important;
    box-shadow: var(--shadow-md) !important;
}
[data-testid="stExpander"] summary {
    color: var(--text-secondary) !important;
}

/* ════════════════════════════════════
   ALERTS
   ════════════════════════════════════ */
.stAlert { border-radius: var(--radius) !important; }
[data-testid="stAlert"] {
    background: rgba(30,41,59,0.8) !important;
    border-radius: var(--radius) !important;
}

/* Success, info, warning, error overrides */
div[data-testid="stAlert"][data-type="success"] {
    border: 1px solid rgba(34,197,94,0.3) !important;
    background: rgba(34,197,94,0.08) !important;
    color: var(--low) !important;
}
div[data-testid="stAlert"][data-type="error"] {
    border: 1px solid rgba(239,68,68,0.3) !important;
    background: rgba(239,68,68,0.08) !important;
    color: var(--critical) !important;
}
div[data-testid="stAlert"][data-type="warning"] {
    border: 1px solid rgba(249,115,22,0.3) !important;
    background: rgba(249,115,22,0.08) !important;
    color: var(--high) !important;
}
div[data-testid="stAlert"][data-type="info"] {
    border: 1px solid rgba(59,130,246,0.3) !important;
    background: rgba(59,130,246,0.08) !important;
    color: var(--accent) !important;
}

/* ════════════════════════════════════
   DIVIDER
   ════════════════════════════════════ */
hr, .stDivider hr {
    border: none !important;
    height: 1px !important;
    background: var(--border) !important;
    margin: 1.5rem 0 !important;
}

/* ════════════════════════════════════
   PROGRESS BAR
   ════════════════════════════════════ */
.stProgress > div > div > div {
    background: linear-gradient(90deg, var(--accent), #1D4ED8) !important;
    box-shadow: 0 0 8px var(--accent-glow) !important;
    border-radius: 4px !important;
}
.stProgress > div > div {
    background: var(--bg-secondary) !important;
    border-radius: 4px !important;
}

/* ════════════════════════════════════
   SPINNER
   ════════════════════════════════════ */
[data-testid="stSpinner"] > div {
    border-color: var(--accent) transparent transparent transparent !important;
}

/* ════════════════════════════════════
   CHART WRAPPER
   ════════════════════════════════════ */
.chart-wrapper {
    background: var(--card-bg);
    backdrop-filter: blur(20px);
    border: 1px solid var(--card-border);
    border-radius: var(--radius-md);
    padding: 1rem 1rem 0.5rem;
    box-shadow: var(--shadow-md);
    transition: all 0.25s ease;
    animation: fadeSlideUp 0.4s ease both;
}
.chart-wrapper:hover {
    border-color: var(--card-hover);
    box-shadow: var(--shadow-lg);
}
.chart-title {
    font-size: 0.75rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: 1px; color: var(--text-muted);
    margin-bottom: 0.25rem;
}

/* ════════════════════════════════════
   INSIGHT BANNERS
   ════════════════════════════════════ */
.insight-banner {
    background: linear-gradient(90deg, rgba(239,68,68,0.06), rgba(30,41,59,0));
    border-left: 3px solid var(--critical);
    border-radius: 0 8px 8px 0;
    padding: 0.65rem 1rem; margin: 0.75rem 0;
    font-size: 0.83rem; color: var(--text-secondary); line-height: 1.5;
}
.insight-banner.blue {
    background: linear-gradient(90deg, rgba(59,130,246,0.06), rgba(30,41,59,0));
    border-left-color: var(--accent);
}
.insight-banner.green {
    background: linear-gradient(90deg, rgba(34,197,94,0.06), rgba(30,41,59,0));
    border-left-color: var(--low);
}
.kpi-insight { font-size: 0.7rem; color: var(--text-muted); margin-top: 0.3rem; line-height: 1.4; }

/* ════════════════════════════════════
   LOGIN PAGE
   ════════════════════════════════════ */
.il-login-wrap {
    min-height: 100vh;
    background: var(--bg-primary);
    display: flex; flex-direction: column;
    position: relative; overflow: hidden;
}
.il-login-wrap::before {
    content: '';
    position: fixed; inset: 0;
    background:
        radial-gradient(ellipse at 20% 50%, rgba(59,130,246,0.08) 0%, transparent 50%),
        radial-gradient(ellipse at 80% 20%, rgba(139,92,246,0.06) 0%, transparent 40%),
        radial-gradient(ellipse at 60% 80%, rgba(34,197,94,0.04) 0%, transparent 40%);
    pointer-events: none;
}
.il-login-topbar {
    background: #080E1A;
    height: 32px;
    display: flex; align-items: center;
    padding: 0 2rem;
    font-size: 0.68rem; color: var(--text-muted);
    justify-content: space-between;
    border-bottom: 1px solid var(--border);
    position: relative; z-index: 10;
}
.il-login-navbar {
    background: rgba(8,14,26,0.95);
    backdrop-filter: blur(20px);
    border-bottom: 1px solid var(--border);
    padding: 0 2rem;
    height: 60px;
    display: flex; align-items: center;
    position: relative; z-index: 10;
}
.il-login-body {
    flex: 1;
    display: flex; align-items: center; justify-content: center;
    padding: 2.5rem 2rem;
    position: relative; z-index: 5;
}
.il-login-card {
    background: var(--card-bg);
    backdrop-filter: blur(40px);
    -webkit-backdrop-filter: blur(40px);
    border: 1px solid var(--card-border);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-lg), 0 0 60px rgba(59,130,246,0.08);
    width: 100%; max-width: 420px;
    overflow: hidden;
    animation: fadeSlideUp 0.5s ease both;
}
.il-login-card-header {
    background: linear-gradient(135deg, #1e3a5f, #1e293b);
    padding: 1.75rem 2rem;
    border-bottom: 1px solid rgba(59,130,246,0.2);
    position: relative; overflow: hidden;
}
.il-login-card-header::after {
    content: '🛡️';
    position: absolute; right: 1.5rem; top: 50%;
    transform: translateY(-50%);
    font-size: 3rem; opacity: 0.12;
}
.il-login-card-title {
    font-size: 1.25rem; font-weight: 800; margin: 0 0 0.3rem;
    color: var(--text-primary); letter-spacing: -0.3px;
}
.il-login-card-sub {
    font-size: 0.8rem; color: var(--text-secondary); margin: 0;
}
.il-login-card-body { padding: 1.75rem 2rem; }
.il-login-footer {
    background: rgba(8,14,26,0.5);
    border-top: 1px solid var(--border);
    padding: 1rem 1.5rem;
    font-size: 0.7rem; color: var(--text-muted);
    text-align: center; line-height: 1.7;
}
.il-login-footer code {
    background: var(--bg-tertiary); padding: 2px 6px;
    border-radius: 4px; font-family: var(--font-mono);
    font-size: 0.68rem; color: var(--accent);
}
.il-feature-list { display: flex; flex-direction: column; gap: 0.85rem; margin: 2rem 0 0; max-width: 460px; }
.il-feat { display: flex; align-items: flex-start; gap: 0.8rem; }
.il-feat-icon {
    width: 28px; height: 28px;
    background: linear-gradient(135deg, var(--accent), #1D4ED8);
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 0.75rem; flex-shrink: 0; margin-top: 0.05rem;
    box-shadow: 0 0 10px var(--accent-glow);
}
.il-feat-text strong {
    display: block; font-size: 0.85rem; color: var(--text-primary); font-weight: 600; margin-bottom: 0.1rem;
}
.il-feat-text span { font-size: 0.78rem; color: var(--text-muted); }

/* ════════════════════════════════════
   DOWNLOAD BUTTON
   ════════════════════════════════════ */
[data-testid="stDownloadButton"] > button {
    background: var(--bg-secondary) !important;
    border: 1px solid var(--border-strong) !important;
    color: var(--text-secondary) !important;
    border-radius: var(--radius) !important;
    font-size: 0.8rem !important;
    font-family: var(--font) !important;
    transition: all 0.2s !important;
}
[data-testid="stDownloadButton"] > button:hover {
    border-color: var(--accent) !important;
    color: var(--accent) !important;
    box-shadow: 0 0 12px var(--accent-glow) !important;
}

/* ════════════════════════════════════
   CAPTION / TEXT
   ════════════════════════════════════ */
.stCaption, small, [data-testid="stCaptionContainer"] p {
    color: var(--text-muted) !important;
    font-size: 0.75rem !important;
}
p { color: var(--text-secondary) !important; }
h1, h2, h3, h4 { color: var(--text-primary) !important; }
strong { color: var(--text-primary) !important; }
code {
    background: var(--bg-tertiary) !important;
    color: var(--accent) !important;
    font-family: var(--font-mono) !important;
    font-size: 0.82em !important;
    padding: 2px 5px !important;
    border-radius: 4px !important;
}

/* ════════════════════════════════════
   CONTAINER BORDER
   ════════════════════════════════════ */
[data-testid="stVerticalBlock"] > [data-testid="stVerticalBlockBorderWrapper"] > div > div {
    background: var(--card-bg) !important;
    border: 1px solid var(--card-border) !important;
    border-radius: var(--radius-md) !important;
    backdrop-filter: blur(20px) !important;
}

/* Multiselect tags */
[data-baseweb="tag"] {
    background: rgba(59,130,246,0.15) !important;
    border: 1px solid rgba(59,130,246,0.3) !important;
    border-radius: 4px !important;
}
[data-baseweb="tag"] span { color: var(--accent) !important; }
</style>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════════════════════════════
VALID_USERS = {
    "admin":   {"password": "admin123",   "name": "Admin User",       "role": "Administrator"},
    "analyst": {"password": "analyst123", "name": "Security Analyst", "role": "SOC Analyst"},
    "socgen":  {"password": "socgen2026", "name": "SocGen Demo",      "role": "Viewer"},
}

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.user = None

# ── LOGIN PAGE ─────────────────────────────────────────────────────────────────
if not st.session_state.authenticated:
    st.markdown("""
    <div class="il-login-topbar">
        <div style="display:flex;align-items:center;gap:0.75rem;">
            <span class="live-dot"></span>
            <span>Secure Enterprise Access Portal</span>
        </div>
        <div style="display:flex;align-items:center;gap:1.5rem;">
            <span>Documentation</span>
            <span>Support</span>
            <span style="opacity:0.5;">|</span>
            <span>© 2026 IdentityLens AI</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="il-login-navbar">
        <div class="il-brand">
            <div class="il-logo">🛡️</div>
            <div class="il-brand-text">
                <div class="il-brand-name">IdentityLens AI</div>
                <div class="il-brand-sub">Enterprise Security Platform</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    col_features, col_gap, col_login = st.columns([1.15, 0.1, 0.85])

    with col_features:
        st.markdown("""
        <div style="padding:2.5rem 0 2rem;">
            <div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;
                        color:var(--accent);margin-bottom:1rem;">Enterprise Security Platform</div>
            <h1 style="font-size:2.4rem;font-weight:900;color:var(--text-primary);line-height:1.15;
                        letter-spacing:-1px;margin:0 0 1rem;">
                Identity Intelligence<br>
                <span style="background:linear-gradient(135deg,#3B82F6,#8B5CF6);-webkit-background-clip:text;
                             -webkit-text-fill-color:transparent;background-clip:text;">for the Modern SOC</span>
            </h1>
            <p style="font-size:0.95rem;color:var(--text-secondary);margin:0 0 2rem;line-height:1.7;max-width:440px;">
                Real-time visibility into enterprise identities across Active Directory,
                AWS IAM, and Okta — powered by Gemini AI and built for Security Operations Centers.
            </p>
            <div class="il-feature-list">
                <div class="il-feat">
                    <div class="il-feat-icon">🔗</div>
                    <div class="il-feat-text">
                        <strong>360° Identity Correlation</strong>
                        <span>Unified view across all platforms in real time</span>
                    </div>
                </div>
                <div class="il-feat">
                    <div class="il-feat-icon">🤖</div>
                    <div class="il-feat-text">
                        <strong>AI-Powered Anomaly Detection</strong>
                        <span>ML + rule engine detecting behavioural threats</span>
                    </div>
                </div>
                <div class="il-feat">
                    <div class="il-feat-icon">🔒</div>
                    <div class="il-feat-text">
                        <strong>Automated Quarantine & Remediation</strong>
                        <span>Instant isolation with Gemini AI remediation plans</span>
                    </div>
                </div>
                <div class="il-feat">
                    <div class="il-feat-icon">📊</div>
                    <div class="il-feat-text">
                        <strong>Attack Graph Visualization</strong>
                        <span>Interactive lateral movement path tracing</span>
                    </div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with col_login:
        st.markdown("""
        <div style="padding:2.5rem 0 2rem;">
        <div class="il-login-card">
            <div class="il-login-card-header">
                <div class="il-login-card-title">Sign In</div>
                <div class="il-login-card-sub">Access IdentityLens AI Platform</div>
            </div>
            <div class="il-login-card-body">
        """, unsafe_allow_html=True)

        username = st.text_input("Username", placeholder="Enter your username", key="login_user",
                                  label_visibility="visible")
        password = st.text_input("Password", placeholder="Enter your password",
                                  type="password", key="login_pass",
                                  label_visibility="visible")

        if st.button("Sign In →", type="primary", use_container_width=True, key="login_btn"):
            if username in VALID_USERS and VALID_USERS[username]["password"] == password:
                st.session_state.authenticated = True
                st.session_state.user = {"username": username, **VALID_USERS[username]}
                st.rerun()
            else:
                st.error("Invalid credentials. Please try again.")

        st.markdown("""
            </div>
            <div class="il-login-footer">
                <strong style="color:var(--text-secondary);">Demo credentials:</strong><br>
                <code>admin / admin123</code> &nbsp;|&nbsp;
                <code>analyst / analyst123</code> &nbsp;|&nbsp;
                <code>socgen / socgen2026</code><br><br>
                🔒 All access is monitored and logged. Enterprise-grade security.
            </div>
        </div>
        </div>
        """, unsafe_allow_html=True)

    st.stop()

# ═══════════════════════════════════════════════════════════════════
# AUTHENTICATED APP
# ═══════════════════════════════════════════════════════════════════

@st.cache_data(ttl=300)
def load_identity_summary():
    from backend.identity_resolver import IdentityResolver
    return IdentityResolver().get_identity_summary()

@st.cache_data(ttl=300)
def load_risk_scores():
    from backend.risk_engine import RiskEngine
    return RiskEngine().calculate_risk_scores()

@st.cache_data(ttl=300)
def load_anomalies():
    from backend.anomaly_detection import AnomalyDetectionEngine
    return AnomalyDetectionEngine().detect_anomalies()

try:
    summary        = load_identity_summary()
    risk_df        = load_risk_scores()
    anomalies_df   = load_anomalies()
    critical_count = len(risk_df[risk_df['risk_level'] == 'Critical'])
    high_count     = len(risk_df[risk_df['risk_level'] == 'High'])
    anomaly_count  = len(anomalies_df)
    avg_risk       = round(risk_df['risk_score'].mean(), 1)
    total_ids      = summary.get('total_identities', 0)
except Exception:
    critical_count = high_count = anomaly_count = avg_risk = total_ids = 0

user     = st.session_state.user
initials = "".join([n[0].upper() for n in user["name"].split()[:2]])

# ── Top utility bar ────────────────────────────────────────────────────────────
from datetime import datetime
now_str = datetime.now().strftime("%d %b %Y · %H:%M UTC")

st.markdown(f"""
<div class="il-utility-bar">
    <div class="il-util-left">
        <span class="live-dot"></span>
        <span>System Operational</span>
        <span style="opacity:0.3;">|</span>
        <span>IdentityLens AI v2.0</span>
        <span style="opacity:0.3;">|</span>
        <span>{now_str}</span>
    </div>
    <div class="il-util-right">
        <span class="il-util-link">Documentation</span>
        <span class="il-util-link">Support</span>
        <span style="opacity:0.3;">|</span>
        <span style="color:var(--text-muted);">© 2026 IdentityLens AI</span>
    </div>
</div>
""", unsafe_allow_html=True)

# ── Navigation Definition ──────────────────────────────────────────────────────
p1 = st.Page("views/1_Executive_Overview.py",     title="Executive Overview")
p2 = st.Page("views/2_Identity_Explorer.py",      title="Identity Explorer")
p3 = st.Page("views/3_Risk_Center.py",            title="Risk Center")
p4 = st.Page("views/4_Anomaly_Detection.py",      title="Anomaly Detection")
p5 = st.Page("views/5_Attack_Graph.py",           title="Attack Graph")
p6 = st.Page("views/6_AI_Remediation_Center.py",  title="AI Copilot")
p7 = st.Page("views/7_Quarantine_Center.py",      title="Quarantine Center")
p8 = st.Page("views/8_Validation_Center.py",      title="Validation Center")

pg = st.navigation([p1, p2, p3, p4, p5, p6, p7, p8], position="hidden")

# ── Dark Nav Bar ───────────────────────────────────────────────────────────────
nav_cols = st.columns([2.2, 1, 0.9, 0.8, 0.85, 0.8, 1, 1.05, 1.1, 1.4], vertical_alignment="center")

with nav_cols[0]:
    st.markdown("""
        <div class="il-brand">
            <div class="il-logo">🛡️</div>
            <div class="il-brand-text">
                <div class="il-brand-name">IdentityLens AI</div>
                <div class="il-brand-sub">Enterprise Security Platform</div>
            </div>
        </div>
    """, unsafe_allow_html=True)

with nav_cols[1]: st.page_link(p1, label="Overview")
with nav_cols[2]: st.page_link(p2, label="Identity")
with nav_cols[3]: st.page_link(p3, label="Risk")
with nav_cols[4]: st.page_link(p4, label="Threats")
with nav_cols[5]: st.page_link(p5, label="Graph")
with nav_cols[6]: st.page_link(p6, label="AI Copilot")
with nav_cols[7]: st.page_link(p7, label="Quarantine")
with nav_cols[8]: st.page_link(p8, label="Validation")

with nav_cols[9]:
    st.markdown(f"""
        <div class="il-user-chip">
            <div class="il-user-avatar">{initials}</div>
            <span>{user['name']}</span>
            <span style="font-size:0.6rem;color:var(--text-muted);">·</span>
            <span style="font-size:0.65rem;color:var(--text-muted);">{user['role']}</span>
        </div>
    """, unsafe_allow_html=True)

# ── Stats bar ──────────────────────────────────────────────────────────────────
critical_color = "red"   if critical_count > 0 else "green"
high_color     = "orange" if high_count > 0     else "green"
anomaly_color  = "red"   if anomaly_count > 0  else "green"

st.markdown(f"""
<div class="il-stats-bar">
    <div class="il-stat">
        <span class="live-dot blue" style="width:5px;height:5px;"></span>
        <span class="il-stat-label">Identities Monitored</span>
        <span class="il-stat-value blue">{total_ids}</span>
    </div>
    <div class="il-stat">
        <span class="il-stat-label">Critical Risk</span>
        <span class="il-stat-value {critical_color}">{critical_count}</span>
    </div>
    <div class="il-stat">
        <span class="il-stat-label">High Risk</span>
        <span class="il-stat-value {high_color}">{high_count}</span>
    </div>
    <div class="il-stat">
        <span class="il-stat-label">Active Anomalies</span>
        <span class="il-stat-value {anomaly_color}">{anomaly_count}</span>
    </div>
    <div class="il-stat">
        <span class="il-stat-label">Avg Risk Score</span>
        <span class="il-stat-value">{avg_risk}</span>
    </div>
    <div style="flex:1;"></div>
    <div class="il-stat" style="border-right:none;">
        <span class="live-dot" style="width:5px;height:5px;"></span>
        <span class="il-stat-label">All systems operational</span>
    </div>
</div>
""", unsafe_allow_html=True)

# Run the page content
pg.run()

# Sign out in sidebar
with st.sidebar:
    st.markdown(f"""
    <div style="padding:1rem;border-bottom:1px solid var(--border);margin-bottom:1rem;">
        <div style="font-size:0.65rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:0.4rem;">Signed in as</div>
        <div style="font-weight:700;color:var(--text-primary);font-size:0.9rem;">{user['name']}</div>
        <div style="font-size:0.75rem;color:var(--text-muted);">{user['role']}</div>
    </div>
    """, unsafe_allow_html=True)
    if st.button("🚪 Sign Out", use_container_width=True, key="signout"):
        st.session_state.authenticated = False
        st.session_state.user = None
        st.rerun()

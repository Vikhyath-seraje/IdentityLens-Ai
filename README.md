# 🛡️ IdentityLens AI

> **See every identity. Secure every path.**
>
> An autonomous identity security operations platform that detects, prioritizes, and **auto-remediates** identity risk across cloud, on-prem, and SaaS environments — in real time.

<p align="center">
  <em>Built for the Société Générale Hackathon 2026</em>
</p>

---

## 🧠 The Problem

Modern enterprises manage **thousands of identities** — humans, service accounts, and machine identities — scattered across Active Directory, Okta, AWS, and hundreds of SaaS apps.

- **80%+ of breaches** start with a compromised, stale, or over-privileged identity.
- Security teams drown in **alerts** with no context on *blast radius* or *exploitable paths*.
- Remediation is **manual**, slow (days/weeks), and error-prone.

**IdentityLens AI** turns identity security from a reactive, alert-fatigued process into a **proactive, autonomous defense.**

---

## ✨ Key Features

| Capability | What it does |
|------------|--------------|
| 🔍 **Identity Resolver** | Unifies identities across AD, Okta, AWS, HR, and API tokens into a single graph |
| 📊 **Risk Engine** | Scores every identity by privilege, stale access, exposure, and behavior |
| 🧩 **Anomaly Detection** | Isolation Forest + clustering surfaces behavioral outliers static rules miss |
| 🕸️ **Attack Graph** | Maps full kill-chains — from low-priv entry points to crown-jewel assets |
| 🤖 **AI Copilot** | Grounded LLM recommendations for one-click remediations |
| 🚪 **Quarantine Engine** | Instantly isolates risky identities without disrupting the business |
| ✅ **Validation Engine** | Verifies remediations worked — closing the detect→fix→verify loop |

### The Closed-Loop Workflow

```
   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
   │  DETECT  │ ─▶ │ ANALYZE  │ ─▶ │ REMEDIATE│ ─▶ │ VALIDATE │
   └──────────┘    └──────────┘    └──────────┘    └──────────┘
        ▲                                               │
        └─────────────────── feedback ──────────────────┘
```

---

## 🖥️ The Platform — 8 Modules

| # | Module | Audience | Purpose |
|---|--------|----------|---------|
| 1 | **Executive Overview** | CISO / Leadership | Real-time org risk posture, KPIs, trends |
| 2 | **Identity Explorer** | Analysts | Investigate identities, access graphs, lateral movement |
| 3 | **Risk Center** | Analysts | Prioritized, explainable risk rankings |
| 4 | **Anomaly Detection** | SOC | ML-flagged behavioral outliers |
| 5 | **Attack Graph** | Red Team / Architects | Visualize exploitable kill-chains |
| 6 | **AI Remediation Center** | Analysts | One-click, AI-grounded remediations |
| 7 | **Quarantine Center** | Responders | Isolate identities, measure before/after risk |
| 8 | **Validation Center** | Auditors | Verify remediations held — close the loop |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Streamlit Frontend (app.py)               │
│   Executive │ Identity │ Risk │ Anomaly │ Attack │ AI │ ...  │
└──────────────┬──────────────────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────────────────┐
│                     Backend Engines                          │
│  identity_resolver · risk_engine · anomaly_detection         │
│  attack_graph · ai_engine · quarantine_engine                │
│  validation_engine · privilege_analyzer · terraform_manager  │
└──────────────┬──────────────────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────────────────┐
│           SQLite — Unified Identity Graph Store              │
│  identities · ad_accounts · okta_accounts · aws_accounts     │
│  hr_records · api_tokens · group_memberships · audit_logs    │
│  quarantine_records · risk_labels · ...                      │
└─────────────────────────────────────────────────────────────┘
```

**Tech Stack**
- 🐍 **Python 3.10+**
- 🎈 **Streamlit** — interactive dashboard
- 📊 **Plotly** — rich visualizations & network graphs
- 🤖 **scikit-learn** — Isolation Forest anomaly detection
- 🕸️ **NetworkX** — attack-path / identity graph modeling
- 🗄️ **SQLite** — unified identity data store
- ✨ **Google Gemini API** — AI remediation recommendations

---

## 🚀 Quick Start

### Prerequisites
- Python **3.10+**
- pip

### Installation

```bash
# 1. Clone the repo
git clone https://github.com/Vikhyath-seraje/IdentityLens-Ai.git
cd IdentityLens-Ai

# 2. Create a virtual environment
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) Set your Gemini API key for AI Copilot features
#    Create a .env file in the project root:
#        GEMINI_API_KEY=your_key_here

# 5. Run it!
streamlit run app.py
```

The app launches at **http://localhost:8501** 🎉

---

## 🔑 Demo Credentials

| Username | Password | Role |
|----------|----------|------|
| `admin` | `admin123` | Administrator (full access) |
| `analyst` | `analyst123` | SOC Analyst |
| `socgen` | `socgen2026` | Viewer (read-only) |

> ⚠️ **Demo credentials only.** Reset before any real deployment.

---

## 📂 Project Structure

```
IdentityLens-Ai/
├── app.py                      # Streamlit entrypoint, auth, nav, global styles
├── requirements.txt
├── backend/
│   ├── identity_resolver.py    # Unify identities across sources
│   ├── risk_engine.py          # Score identities by risk
│   ├── anomaly_detection.py    # ML-based behavioral outlier detection
│   ├── attack_graph.py         # Build exploitable-path graphs
│   ├── ai_engine.py            # LLM remediation recommendations
│   ├── quarantine_engine.py    # Isolate risky identities
│   ├── validation_engine.py    # Verify remediations held
│   ├── privilege_analyzer.py   # Detect over-privileged access
│   └── terraform_manager.py    # IaC-based remediation export
├── views/                      # The 8 dashboard modules
│   ├── 1_Executive_Overview.py
│   ├── 2_Identity_Explorer.py
│   ├── 3_Risk_Center.py
│   ├── 4_Anomaly_Detection.py
│   ├── 5_Attack_Graph.py
│   ├── 6_AI_Remediation_Center.py
│   ├── 7_Quarantine_Center.py
│   └── 8_Validation_Center.py
├── models/
│   └── isolation_forest.py     # Trained anomaly detection model
├── database/
│   ├── identitylens.db         # SQLite unified identity store
│   └── init_db.py              # Schema initialization
└── data/                       # Source identity data
```

---

## 💡 How It Works

1. **Ingest & Unify** — The Identity Resolver pulls from AD, Okta, AWS IAM, HR systems, and API token stores, resolving them into a single canonical identity per person/service.
2. **Score & Rank** — The Risk Engine computes a composite risk score per identity using privilege level, access staleness, exposure surface, and behavioral signals.
3. **Detect Anomalies** — An Isolation Forest model, trained on access patterns, flags identities behaving abnormally — impossible logins, privilege creep, off-hours access.
4. **Map Attack Paths** — NetworkX builds a directed graph of reachability, surfacing multi-hop lateral-movement paths from low-privilege entry points to critical assets.
5. **AI Remediation** — The AI Copilot analyzes each attack path and recommends concrete, one-click fixes (revoke access, enforce MFA, quarantine) — grounded in your actual policy, not hallucinated.
6. **Quarantine** — Risky identities are instantly isolated while a full audit trail is captured.
7. **Validate** — The Validation Engine re-checks the identity graph to confirm the remediation actually closed the exposure — then feeds that signal back into risk scoring.

---

## 🎯 Use Cases

- **🔥 Privilege Creep Detection** — Catch service accounts accumulating excessive permissions over time.
- **🕵️ Insider Threat Hunting** — Spot anomalous access patterns from legitimate users.
- **⚡ Incident Response** — Quarantine a compromised identity in seconds, with measurable risk reduction.
- **📋 Access Reviews & Compliance** — Automated, evidence-backed attestations instead of spreadsheets.

---

## 🛣️ Roadmap

- [ ] Real-time streaming ingestion (Kafka / SQS)
- [ ] Support for Azure AD & GCP IAM
- [ ] SOAR integrations (Splunk SOAR, Cortex XSOAR)
- [ ] JIT (just-in-time) access elevation workflows
- [ ] Multi-tenant deployment mode

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👥 Team

Built with ❤️ for the **Société Générale Hackathon 2026**.

- **Vikhyath Seraje** — *Lead Developer*

> *Questions? Open an issue or reach out.*

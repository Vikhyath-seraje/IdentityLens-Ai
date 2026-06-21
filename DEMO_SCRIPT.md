# IdentityLens AI — Demo Video Script
**Duration:** ~4-5 minutes | **Format:** Screen recording with voiceover

---

## 🎬 PRE-RECORDING SETUP (do this before hitting record)
1. Open **http://localhost:8502** in Chrome
2. Log out if logged in (so you start at the login screen)
3. Close all other tabs / notifications (Do Not Disturb on)
4. Set screen resolution to **1920×1080**, browser zoom **100%**
5. Have these credentials ready:
   - Username: `admin`  | Password: `admin123`
6. Start recording (OBS / Win+G / Loom)

---

## 🎙️ SCRIPT

### [0:00 — INTRO]  *(Show a title card / logo for 5s, then cut to login screen)*
> "IdentityLens AI — an autonomous identity security operations platform.
> Today, the average enterprise manages **thousands of identities** across cloud, on-prem, and SaaS — humans, service accounts, and machine identities. Most breaches start with a **compromised or over-privileged identity**.
> IdentityLens AI detects, prioritizes, and **automatically remediates** identity risk in real time. Let me show you."

---

### [0:25 — LOGIN]  *(Type credentials slowly)*
> "We log in as an administrator. Role-based access controls ensure analysts and viewers see only what they're authorized for."

---

### [0:40 — EXECUTIVE OVERVIEW]  *(First screen after login)*
> "This is the **Executive Overview** — a real-time command center for CISOs and leadership.
> - Top-left: live counts of **identities under management**, flagged as **risky**, or placed in **quarantine**.
> - The **threat gauge** shows our current organizational risk posture — currently elevated.
> - This **risk heatmap** and **identity-type breakdown** let leaders instantly see exposure by department and identity type.
> - The **trend chart** at the bottom tracks how risk evolves over time — so we can prove the platform is working."

*(Hover over each chart, pause 2s on each)*

---

### [1:30 — IDENTITY EXPLORER]  *(Click it in the nav)*
> "Now let's go deeper. The **Identity Explorer** is where analysts investigate.
> - Every identity — human, service, or machine — is enriched with its **risk score, privilege level, and access footprint**.
> - Selecting an identity shows its **full access graph**: what it can reach, and critically, **what it can reach *through* other identities** — the lateral movement paths attackers exploit."

*(Click on a high-risk identity, let the access graph render, hover over nodes)*

---

### [2:10 — RISK CENTER]  *(Click it in the nav)*
> "The **Risk Center** prioritizes what matters. Instead of thousands of alerts, analysts see a **ranked, contextualized list** of identities by risk severity.
> - This isn't just a number — each score is explained by contributing factors: **stale access, excessive privileges, anomalous behavior**.
> - The histograms let us see the **distribution of risk** across the org at a glance."

*(Scroll the risk list, expand one identity's risk breakdown)*

---

### [2:40 — ANOMALY DETECTION]  *(Click it in the nav)*
> "Here's where ML does the heavy lifting. The **Anomaly Detection** module uses **Isolation Forest and clustering** to surface behavioral outliers — impossible logins, access pattern shifts, off-hours activity.
> - The scatter plot shows identities flagged as anomalies, color-coded by severity.
> - This catches threats that **static rules miss**."

*(Point to flagged points on the scatter plot)*

---

### [3:05 — ATTACK GRAPH]  *(Click it in the nav — this is the showstopper)*
> "This is the **Attack Graph** — the crown jewel. It maps the **kill chain**: how an attacker could move from a low-privilege entry point to crown-jewel assets, step by step.
> - Each node is an identity or resource. Each edge is an exploitable path.
> - And critically — we don't just show the problem..."

*(Let the graph render, hover over a path from a low-priv node to a critical asset)*

---

### [3:30 — AI COPILOT / REMEDIATION]  *(Click it in the nav)*
> "...we **fix it**. The **AI Copilot** analyzes the attack path and recommends **concrete remediations** — revoke this access, quarantine that identity, enforce MFA here.
> - It's not a chatbot — it's grounded in **your actual identity graph and policy**.
> - Recommendations are **one-click actionable**."

*(Click 'Apply' on a remediation, watch the attack graph update in real-time)*

---

### [4:00 — QUARANTINE & VALIDATION]  *(Click through both)*
> "Once an identity is quarantined, it's **instantly isolated** without disrupting the business. The **Quarantine Center** shows the risk delta — before and after.
> The **Validation Center** then verifies the remediation worked — closing the loop. **Detect → Analyze → Remediate → Validate**, fully autonomous."

*(Show the before/after gauge in Quarantine, then briefly show Validation)*

---

### [4:30 — CLOSING]  *(Return to Executive Overview, hold for 3s)*
> "IdentityLens AI turns identity security from a **reactive, alert-fatigued process** into a **proactive, autonomous defense**.
> Less manual toil for analysts. Faster response. provable risk reduction for leadership.
> **IdentityLens AI — see every identity. Secure every path.**
>
> Thank you."

*(Hold logo/title card 3s, then stop recording)*

---

## 🎯 PRO TIPS FOR A CLEAN RECORDING
- **Pace yourself** — move ~30% slower than feels natural; viewers need time to absorb charts.
- **Narrate before you click** — say what you're about to do, then do it.
- **Cursor visible** — turn on cursor highlighting (Windows: Settings → Accessibility → Mouse pointer = large + colorful).
- **Silence between sections** — a 1-second pause between pages feels deliberate, not laggy.
- **No scrolling during cuts** — pre-scroll to the good part, then start talking.
- **Record audio separately if needed** — you can re-narrate over the screen capture in editing (CapCut/DaVinci) for cleaner sound.

## 🛠 IF SOMETHING BREAKS LIVE
- Refresh the page (`F5`) — Streamlit re-runs instantly, no data loss.
- If the AI Copilot hangs, say: *"and the AI generates a remediation plan..."* and click past it.
- Have a backup screenshot of each page ready in case of network issues.

## 📊 KEY NUMBERS TO MENTION (fill in from your data)
- Identities under management: **___**
- Identities currently quarantined: **___**
- Avg. risk reduction after remediation: **___%**
- Mean time to remediate: **< 1 minute**

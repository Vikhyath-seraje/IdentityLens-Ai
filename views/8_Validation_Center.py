import sys, os
import pandas as pd
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import streamlit as st
import time
from backend.validation_engine import ValidationEngine

# ── Page header ─────────────────────────────────────────────────────────────────
st.markdown("""
<div style="padding:1.8rem 2.5rem 0;max-width:1440px;margin:0 auto;">
<div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:1rem;
            padding-bottom:1.2rem;border-bottom:1px solid #E0E0E0;margin-bottom:1.8rem;">
    <div>
        <div style="font-size:0.68rem;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;
                    color:#E60028;margin-bottom:0.3rem;">Testing & Compliance</div>
        <h1 style="font-size:1.55rem;font-weight:800;color:#1A1A1A;margin:0 0 0.25rem;letter-spacing:-0.3px;">
            Validation Center</h1>
        <p style="font-size:0.875rem;color:#6B6B6B;margin:0;">
            Automated execution of predefined threat scenarios to validate detection, risk, and graph engines.
        </p>
    </div>
    <span style="display:inline-flex;align-items:center;padding:0.25rem 0.75rem;
                background:rgba(0,122,76,0.06);border:1px solid rgba(0,122,76,0.2);
                border-radius:100px;font-size:0.68rem;font-weight:700;color:#007A4C;
                letter-spacing:0.8px;text-transform:uppercase;margin-top:0.2rem;">AUTO-TEST SUITE</span>
</div>
</div>
<style>
@keyframes fadeSlideUp {
    from{opacity:0;transform:translateY(14px)}
    to{opacity:1;transform:translateY(0)}
}
.test-card {
    background:white;border:1px solid #E0E0E0;border-radius:10px;
    padding:1rem 1.2rem;margin-bottom:1rem;
    box-shadow:0 1px 4px rgba(0,0,0,0.05);
    animation:fadeSlideUp 0.35s ease both;
}
.test-card-pass { border-left:4px solid #007A4C; }
.test-card-fail { border-left:4px solid #E60028; }
.test-header { display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem; }
.test-title { font-size:1.0rem; font-weight:700; color:#1A1A1A; }
.test-status-pass { color:#007A4C; font-weight:800; font-size:0.9rem; }
.test-status-fail { color:#E60028; font-weight:800; font-size:0.9rem; }
.test-details { font-size:0.85rem; color:#4A4A4A; line-height:1.5; background:rgba(0,0,0,0.02); padding:0.8rem; border-radius:6px; margin-top:0.8rem; border:1px solid rgba(0,0,0,0.05); }
.metric-box { text-align:center; padding:1rem; border:1px solid #E0E0E0; border-radius:8px; background:white; }
.metric-val { font-size:1.8rem; font-weight:800; color:#1A1A1A; }
.metric-lbl { font-size:0.75rem; color:#6B6B6B; text-transform:uppercase; font-weight:600; letter-spacing:0.5px; }
</style>
""", unsafe_allow_html=True)

st.markdown('<div style="padding:0 2.5rem 2.5rem;max-width:1440px;margin:0 auto;">', unsafe_allow_html=True)

if 'validation_results' not in st.session_state:
    st.session_state.validation_results = None

col1, col2 = st.columns([1, 4])
with col1:
    if st.button("Run All Test Cases", type="primary", use_container_width=True):
        st.session_state.validation_results = "running"
        st.rerun()

with col2:
    if st.session_state.validation_results == "running":
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        engine = ValidationEngine()
        status_text.markdown("**Step 1:** Injecting test data into database...")
        progress_bar.progress(20)
        time.sleep(0.5)
        
        status_text.markdown("**Step 2:** Running Identity Resolver...")
        progress_bar.progress(40)
        time.sleep(0.5)
        
        status_text.markdown("**Step 3:** Running Anomaly Detection Engine...")
        progress_bar.progress(60)
        time.sleep(0.5)
        
        status_text.markdown("**Step 4:** Running Risk Scoring Engine...")
        progress_bar.progress(80)
        time.sleep(0.5)
        
        status_text.markdown("**Step 5:** Validating outcomes...")
        results = engine.run_validations()
        progress_bar.progress(100)
        time.sleep(0.5)
        
        st.session_state.validation_results = results
        st.rerun()

st.divider()

if isinstance(st.session_state.validation_results, list):
    results = st.session_state.validation_results
    passed = sum(1 for r in results if r['status'] == 'PASS')
    failed = len(results) - passed
    coverage = int((passed / len(results)) * 100) if len(results) > 0 else 0

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(f'<div class="metric-box"><div class="metric-val">{len(results)}</div><div class="metric-lbl">Total Tests</div></div>', unsafe_allow_html=True)
    with m2:
        st.markdown(f'<div class="metric-box"><div class="metric-val" style="color:#007A4C;">{passed}</div><div class="metric-lbl">Passed</div></div>', unsafe_allow_html=True)
    with m3:
        st.markdown(f'<div class="metric-box"><div class="metric-val" style="color:#E60028;">{failed}</div><div class="metric-lbl">Failed</div></div>', unsafe_allow_html=True)
    with m4:
        st.markdown(f'<div class="metric-box"><div class="metric-val" style="color:#0060A8;">{coverage}%</div><div class="metric-lbl">Coverage</div></div>', unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)

    for res in results:
        card_class = "test-card-pass" if res['status'] == 'PASS' else "test-card-fail"
        status_class = "test-status-pass" if res['status'] == 'PASS' else "test-status-fail"
        
        html = f"""
        <div class="test-card {card_class}">
            <div class="test-header">
                <div class="test-title">{res['name']}</div>
                <div class="{status_class}">{res['status']}</div>
            </div>
            <div class="test-details">
                {res['details']}
            </div>
        </div>
        """
        st.markdown(html, unsafe_allow_html=True)
    
    # Download Report
    csv_data = pd.DataFrame(results).to_csv(index=False)
    st.download_button(
        label="Download Validation Report (CSV)",
        data=csv_data,
        file_name='identitylens_validation_report.csv',
        mime='text/csv',
    )
elif st.session_state.validation_results is None:
    st.info("Validation tests have not been run yet. Click 'Run All Test Cases' to begin execution.")

st.markdown('</div>', unsafe_allow_html=True)

"""
Objective 5 — minimal SOC-style dashboard.

Deliberately basic: a single Streamlit table with severity color-coding,
plus an expandable per-case detail view. Correlation logic correctness
matters more than dashboard polish for this proof of concept.

Run with: streamlit run dashboard.py
"""

import pandas as pd
import streamlit as st

from run_scenarios import run

SEVERITY_COLOR = {
    "CRITICAL": "#b00020",
    "HIGH": "#e65100",
    "MEDIUM": "#f9a825",
    "LOW": "#2e7d32",
}

st.set_page_config(page_title="Cloud Security Risk Dashboard", layout="wide")
st.title("Cloud Security Risk Dashboard")
st.caption(
    "Correlated view across config scanning, rule-based behavioral detection, "
    "and the Isolation Forest anomaly signal. Illustrative staged scenarios, "
    "proof-of-concept scale."
)

results = run()

summary_rows = [{
    "Case": r.case_id,
    "Identity": r.identity,
    "Resources": ", ".join(r.resources),
    "Signals triggered": ", ".join(r.signals_triggered) or "none",
    "Severity": r.severity,
} for r in results]

df = pd.DataFrame(summary_rows)


def highlight_severity(row):
    color = SEVERITY_COLOR.get(row["Severity"], "#ffffff")
    return [f"background-color: {color}; color: white"] * len(row)


st.subheader("Correlated findings")
st.dataframe(df.style.apply(highlight_severity, axis=1), use_container_width=True)

st.subheader("Case detail")
for r in results:
    with st.expander(f"[{r.severity}] {r.case_id} - {r.identity}"):
        if not r.findings:
            st.write("No findings on any signal.")
        for f in r.findings:
            st.markdown(f"- **({f.issue})** {f.detail}")

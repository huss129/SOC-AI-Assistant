import json, os
import pandas as pd
import streamlit as st
from parse_alerts import load_alerts
import analyze

st.set_page_config(page_title="SOC AI Assistant", layout="wide")
st.title("SOC AI Assistant")

VERDICTS = "verdicts.json"
verdicts = json.load(open(VERDICTS)) if os.path.exists(VERDICTS) else {}

import wazuh_client

st.sidebar.header("Source")
source = st.sidebar.radio("Alerts source", ["Live from Wazuh", "File (alerts.json)"])
if st.sidebar.button("Refresh"):
    st.cache_data.clear()

@st.cache_data(ttl=60)
def get_alerts(src):
    if src == "Live from Wazuh":
        try:
            return wazuh_client.fetch_alerts(size=1000), None
        except Exception as e:
            return load_alerts(), f"Wazuh unreachable, using file. ({str(e)[:80]})"
    return load_alerts(), None

alerts, warn = get_alerts(source)
if warn:
    st.warning(warn)
st.sidebar.write(f"Loaded: {len(alerts)} alerts")

# ---- الشريط الجانبي: فلاتر ----
st.sidebar.header("Filters")
min_level = st.sidebar.slider("Min rule level", 0, 15, 5)
rules = sorted({a["rule_id"] for a in alerts})
chosen = st.sidebar.multiselect("Rule IDs", rules)
filtered = [a for a in alerts if a["level"] >= min_level
            and (not chosen or a["rule_id"] in chosen)]
st.sidebar.write(f"{len(filtered)} alerts")

# ---- جدول ----
df = pd.DataFrame([{
    "idx": i, "time": a["time"], "level": a["level"],
    "rule": a["rule_id"], "description": a["description"][:70],
    "srcip": a["srcip"], "my_verdict": verdicts.get(str(a["time"]), ""),
} for i, a in enumerate(filtered)])
st.dataframe(df.drop(columns="idx"), use_container_width=True, height=300)

# ---- تحليل alert واحد ----
st.subheader("Analyze an alert")
if not filtered:
    st.info("No alerts match the filters.")
    st.stop()

idx = st.number_input("Alert row number", 0, len(filtered) - 1, 0)
a = filtered[idx]
st.write(f"**{a['description']}** | level {a['level']} | rule {a['rule_id']}")
st.code(a["full_log"], language="text")

if st.button("Analyze"):
    with st.spinner("Thinking..."):
        st.session_state["result"] = analyze.analyze(a, alerts)
        st.session_state["result_for"] = idx

r = st.session_state.get("result")
if r and st.session_state.get("result_for") == idx:
    c1, c2, c3 = st.columns(3)
    c1.metric("Severity", r["severity"])
    c2.metric("Threat?", "YES" if r["is_likely_threat"] else "no")
    c3.metric("Decided by", r.get("decided_by", "?") + " (ctx: " + str(r.get("context_events", 0)) + ")")
    st.write("**Category:**", r.get("category"))
    st.write("**Summary:**", r.get("summary"))
    st.write("**Timeline (computed):**", r.get("timeline", "-"))
    st.write("**Evidence:**")
    st.code(r.get("evidence", ""), language="text")
    st.write("**Next steps:**")
    steps = r.get("next_steps", [])
    steps = [steps] if isinstance(steps, str) else steps
    for s in steps:
        st.write("-", s)

# ---- حكمك ----
st.subheader("Your verdict")
col1, col2 = st.columns(2)
for col, label in ((col1, "threat"), (col2, "noise")):
    if col.button(f"Mark as {label}"):
        verdicts[str(a["time"])] = label
        json.dump(verdicts, open(VERDICTS, "w"))
        st.success(f"Saved: {label}")

import json
import pandas as pd
import streamlit as st
import db

st.set_page_config(page_title="SOC AI Assistant", layout="wide")
st.title("SOC AI Assistant")

if st.sidebar.button("Refresh"):
    st.rerun()

rows = db.load_all()
if not rows:
    st.info("No analyzed alerts yet. Run: python worker.py")
    st.stop()

df = pd.DataFrame(rows)
if "status" not in df.columns:
    df["status"] = "done"
df["status"] = df["status"].fillna("done")
failed = df[df["status"] == "failed"]
df = df[df["status"] != "failed"]

total = len(df)
threats = int(df["is_threat"].sum())
by_rule = int((df["decided_by"] == "rule").sum())
c1, c2, c3, c4 = st.columns(4)
c1.metric("Alerts analyzed", total)
c2.metric("Flagged as threat", threats)
c3.metric("Noise filtered", total - threats)
c4.metric("Decided by code rules", f"{by_rule/total:.0%}")
st.caption(f"Not analyzed (failed): {len(failed)}")

st.sidebar.header("Filters")
only_threats = st.sidebar.checkbox("Threats only", value=True)
cats = sorted(df["category"].dropna().unique())
chosen = st.sidebar.multiselect("Category", cats)
sev = st.sidebar.multiselect("Severity", ["low", "medium", "high", "critical"])

view = df.copy()
if only_threats:
    view = view[view["is_threat"] == 1]
if chosen:
    view = view[view["category"].isin(chosen)]
if sev:
    view = view[view["severity"].isin(sev)]

st.write(f"Showing {len(view)} alerts")
table = view[["time", "severity", "category", "rule_id", "description", "decided_by"]]
st.dataframe(table, use_container_width=True, height=320)

if len(view):
    st.subheader("Alert details")
    i = st.number_input("Row number", 0, len(view) - 1, 0)
    r = view.iloc[int(i)]
    st.write(f"**{r['description']}** | level {r['level']} | rule {r['rule_id']}")
    a, b, c = st.columns(3)
    a.metric("Severity", r["severity"])
    b.metric("Threat?", "YES" if r["is_threat"] else "no")
    c.metric("Decided by", r["decided_by"])
    st.write("**Category:**", r["category"])
    st.write("**Summary:**", r["summary"])
    st.write("**Timeline (computed):**", r["timeline"] or "-")
    st.write("**Evidence:**")
    st.code(r["evidence"], language="text")
    st.write("**Next steps:**")
    for s in json.loads(r["next_steps"] or "[]"):
        st.write("-", s)

if len(failed):
    with st.expander(f"Not analyzed ({len(failed)}) - treat as unknown, not safe"):
        st.dataframe(failed[["time", "rule_id", "description", "attempts", "error"]],
                     use_container_width=True)

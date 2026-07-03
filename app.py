import json
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st
from triage import analyze_alert
from report import generate_incident_pdf

ALERT_FILE = Path("/var/ossec/logs/alerts/alerts.json")


st.set_page_config(
    page_title="AI-Powered SOC Dashboard",
    page_icon="🛡️",
    layout="wide"
)


def load_alerts(limit=500):
    alerts = []

    if not ALERT_FILE.exists():
        return pd.DataFrame()

    with ALERT_FILE.open("r", encoding="utf-8", errors="ignore") as file:
        lines = file.readlines()[-limit:]

    for line in lines:
        try:
            alert = json.loads(line)

            alerts.append({
                "timestamp": alert.get("timestamp", "N/A"),
                "agent": alert.get("agent", {}).get("name", "N/A"),
                "rule_id": alert.get("rule", {}).get("id", "N/A"),
                "level": alert.get("rule", {}).get("level", 0),
                "description": alert.get("rule", {}).get("description", "N/A"),
                "groups": ", ".join(alert.get("rule", {}).get("groups", [])),
                "location": alert.get("location", "N/A"),
                "full_log": alert.get("full_log", "N/A")
            })

        except json.JSONDecodeError:
            continue

    return pd.DataFrame(alerts)


st.title("🛡️ AI-Powered SOC Dashboard")
st.caption("Custom SOC dashboard using real Wazuh security alerts")

df = load_alerts()

if df.empty:
    st.warning("No alerts found. Check Wazuh alerts.json.")
    st.stop()

total_alerts = len(df)
critical_alerts = len(df[df["level"] >= 15])
high_alerts = len(df[(df["level"] >= 12) & (df["level"] <= 14)])
medium_alerts = len(df[(df["level"] >= 7) & (df["level"] <= 11)])
low_alerts = len(df[df["level"] <= 6])

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Total Alerts", total_alerts)
col2.metric("Critical", critical_alerts)
col3.metric("High", high_alerts)
col4.metric("Medium", medium_alerts)
col5.metric("Low", low_alerts)

st.divider()

left_col, right_col = st.columns(2)

with left_col:
    st.subheader("Alerts by Severity Level")
    severity_chart = df["level"].value_counts().reset_index()
    severity_chart.columns = ["level", "count"]
    fig = px.bar(severity_chart, x="level", y="count", text="count")
    st.plotly_chart(fig, use_container_width=True)

with right_col:
    st.subheader("Top Rule Groups")
    group_chart = df["groups"].value_counts().head(10).reset_index()
    group_chart.columns = ["groups", "count"]
    fig = px.pie(group_chart, names="groups", values="count")
    st.plotly_chart(fig, use_container_width=True)

st.divider()

st.subheader("Recent Security Alerts")

search = st.text_input(
    "Search alerts",
    placeholder="Try: ssh, sudo, syscheck, authentication, kali-agent"
)

filtered_df = df.copy()

if search:
    filtered_df = filtered_df[
        filtered_df.apply(
            lambda row: search.lower() in str(row).lower(),
            axis=1
        )
    ]

st.dataframe(
    filtered_df[["timestamp", "agent", "level", "description", "groups", "location"]],
    use_container_width=True,
    height=350
)

st.divider()

st.subheader("Alert Details")

if not filtered_df.empty:
    selected_index = st.selectbox(
        "Choose an alert to inspect",
        filtered_df.index,
        format_func=lambda i: f"{filtered_df.loc[i, 'timestamp']} | Level {filtered_df.loc[i, 'level']} | {filtered_df.loc[i, 'description']}"
    )

    selected_alert = filtered_df.loc[selected_index]

    st.write("**Agent:**", selected_alert["agent"])
    st.write("**Rule ID:**", selected_alert["rule_id"])
    st.write("**Severity Level:**", selected_alert["level"])
    st.write("**Description:**", selected_alert["description"])
    st.write("**Groups:**", selected_alert["groups"])
    st.write("**Location:**", selected_alert["location"])

    st.text_area("Full Log", selected_alert["full_log"], height=160)
    st.divider()

    st.subheader("🤖 AI Analyst Triage")

    triage = analyze_alert(selected_alert)

    triage_col1, triage_col2, triage_col3 = st.columns(3)

    triage_col1.metric("Triage Severity", triage["severity"])
    triage_col2.metric("Attack Type", triage["attack_type"])
    triage_col3.metric("MITRE Tactic", triage["mitre_tactic"])

    st.write("**Summary:**")
    st.info(triage["summary"])

    st.write("**Severity Reason:**")
    st.write(triage["severity_reason"])

    st.write("**MITRE ATT&CK Mapping:**")
    st.write(f"**Tactic:** {triage['mitre_tactic']}")
    st.write(f"**Technique:** {triage['mitre_technique']}")

    st.write("**Investigation Steps:**")
    for step in triage["investigation_steps"]:
        st.write(f"- {step}")

    st.write("**Recommended Response Actions:**")
    for action in triage["response_actions"]:
        st.write(f"- {action}")

    st.write("**False Positive Note:**")
    st.warning(triage["false_positive_note"])
    st.divider()

    st.subheader("📄 Incident Report Generator")

    incident_pdf = generate_incident_pdf(selected_alert, triage)

    st.download_button(
        label="Download Incident Report as PDF",
        data=incident_pdf,
        file_name=f"incident_report_rule_{selected_alert['rule_id']}.pdf",
        mime="application/pdf"
    )

else:
    st.info("No alerts match your search.")
    
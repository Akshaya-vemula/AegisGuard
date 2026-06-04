import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import time
import datetime

from ueba_service import score_df


# =========================
# PAGE CONFIG
# =========================

st.set_page_config(
    page_title="AegisGuard COMMAND",
    layout="wide",
    page_icon="🛡️"
)

# =========================
# DARK MODE STYLING
# =========================

st.markdown("""
<style>

.stApp {
    background-color: #0e1117;
    color: white;
}

div[data-testid="stMetric"] {
    background-color: #161b22;
    border: 1px solid #30363d;
    padding: 15px;
    border-radius: 12px;
}

</style>
""", unsafe_allow_html=True)

# =========================
# SESSION STATE
# =========================

if 'incident_log' not in st.session_state:
    st.session_state['incident_log'] = []

# =========================
# TITLE
# =========================

st.title("🛡️ AegisGuard SOC Dashboard")
st.markdown("### UEBA-Based Insider Threat Detection Platform")

# =========================
# SIDEBAR
# =========================

st.sidebar.header("⚙ Controls")

live_mode = st.sidebar.toggle(
    "Enable Live Monitoring",
    value=True
)

refresh_rate = st.sidebar.slider(
    "Refresh Rate (Seconds)",
    2,
    10,
    3
)

# =========================
# ATTACK SIMULATION
# =========================

if st.sidebar.button("💥 Inject Attack Simulation"):

    attack_data = {
        "user_id": "STOLEN_CRED",
        "timestamp": f"{datetime.date.today()} 03:15:00",
        "department": "Finance",
        "role": "External",
        "login_count": 1,
        "file_access": 95,
        "avg_file_access_30d": 2,
        "usb_usage": 1,
        "emails_sent": 1,
        "email_subject": "DUMP_CONFIDENTIAL_PASSWORDS",
        "network_traffic_mb": 52.4
    }

    pd.DataFrame([attack_data]).to_csv(
        "live_telemetry.csv",
        mode='a',
        header=False,
        index=False
    )

    st.sidebar.error("🚨 Attack Injected")

# =========================
# DASHBOARD RENDER
# =========================

def render_dashboard(df):

    if df.empty:
        st.warning("Waiting for telemetry...")
        return

    results = score_df(df)

    latest = results.iloc[-1]

    # =========================
    # ALERT STATUS
    # =========================

    if latest['threat_level'] == 'CRITICAL':
        st.error(f"🚨 CRITICAL ALERT: {latest['risk_factors']}")

    elif latest['threat_level'] == 'MEDIUM':
        st.warning("⚠ Suspicious activity detected")

    else:
        st.success("✅ System operating normally")

    # =========================
    # KPI METRICS
    # =========================

    m1, m2, m3, m4 = st.columns(4)

    with m1:
        st.metric(
            "Risk Score",
            int(latest['risk_score'])
        )

    with m2:

        if latest['threat_level'] == "CRITICAL":
            st.error(f"Threat Level: {latest['threat_level']}")

        elif latest['threat_level'] == "MEDIUM":
            st.warning(f"Threat Level: {latest['threat_level']}")

        else:
            st.success(f"Threat Level: {latest['threat_level']}")

    with m3:
        st.metric(
            "Network Traffic",
            f"{latest['network_traffic_mb']} MB"
        )

    with m4:
        st.metric(
            "File Access",
            int(latest['file_access'])
        )

    # =========================
    # TABS
    # =========================

    tabs = st.tabs([
        "📺 Live Feed",
        "📊 Analytics",
        "🕵️ Forensics",
        "📜 Incident Log"
    ])

    # =========================
    # LIVE FEED
    # =========================

    with tabs[0]:

        st.subheader("🚨 Live Threat Feed")

        view_cols = [
            'timestamp',
            'user_id',
            'risk_score',
            'threat_level',
            'risk_factors'
        ]

        # =========================
        # COLOR STYLING
        # =========================

        def highlight_threat(val):

            if val == "CRITICAL":
                return (
                    "background-color: #5c0000;"
                    "color: white;"
                    "font-weight: bold;"
                )

            elif val == "MEDIUM":
                return (
                    "background-color: #5c3b00;"
                    "color: white;"
                    "font-weight: bold;"
                )

            elif val == "LOW":
                return (
                    "background-color: #003b1f;"
                    "color: white;"
                )

            return ""

        styled_df = results[view_cols].sort_values(
            'timestamp',
            ascending=False
        ).style.map(
            highlight_threat,
            subset=['threat_level']
        )

        st.dataframe(
            styled_df,
            use_container_width=True
        )

        # =========================
        # THREAT TRAJECTORY
        # =========================

        fig = px.line(
            results.tail(50),
            x='timestamp',
            y='risk_score',
            title='Threat Trajectory'
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    # =========================
    # ANALYTICS
    # =========================

    with tabs[1]:

        col1, col2 = st.columns(2)

        with col1:

            fig1 = px.pie(
                results,
                names='threat_level',
                title='Threat Distribution'
            )

            st.plotly_chart(
                fig1,
                use_container_width=True
            )

        with col2:

            fig2 = px.histogram(
                results,
                x='department',
                y='risk_score',
                color='threat_level',
                title='Department Risk Exposure'
            )

            st.plotly_chart(
                fig2,
                use_container_width=True
            )

    # =========================
    # FORENSICS
    # =========================

    with tabs[2]:

        st.subheader("🕵️ Forensic Inspector")

        st.code(
            f"Subject: {latest['email_subject']}\n"
            f"Patterns: {latest['patterns_found']}"
        )

        gauge = go.Figure(go.Indicator(
            mode='gauge+number',
            value=latest['risk_score'],
            title={'text': 'Risk Index'},
            gauge={
                'axis': {'range': [0, 100]}
            }
        ))

        st.plotly_chart(
            gauge,
            use_container_width=True
        )

    # =========================
    # INCIDENT LOG
    # =========================

    with tabs[3]:

        if st.button("🛑 Isolate Entity"):

            entry = {
                'User': latest['user_id'],
                'Action': 'Isolated',
                'Reason': latest['risk_factors'],
                'Time': datetime.datetime.now().strftime('%H:%M:%S')
            }

            st.session_state['incident_log'].append(entry)

            st.success("Entity isolated successfully")

        if st.session_state['incident_log']:

            st.table(
                pd.DataFrame(
                    st.session_state['incident_log']
                )
            )

        else:
            st.info("No response actions yet")

# =========================
# LIVE LOOP
# =========================

if live_mode:

    placeholder = st.empty()

    last_row_count = 0

    while True:

        try:

            df = pd.read_csv(
                'live_telemetry.csv',
                on_bad_lines='skip',
                engine='python'
            )

            if not df.empty:

                if len(df) != last_row_count:

                    last_row_count = len(df)

                    with placeholder.container():
                        render_dashboard(df)

            time.sleep(refresh_rate)

        except Exception:
            time.sleep(1)
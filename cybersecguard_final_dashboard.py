import streamlit as st
import random
import time
from datetime import datetime
import pandas as pd

# ===== PAGE CONFIG =====
st.set_page_config(page_title="CyberSecGuard Dashboard", layout="wide")

# ===== PASSWORD PROTECTION =====
password = st.text_input("🔐 Enter password to access CyberSecGuard:", type="password")
if password != "secure123":
    st.error("❌ Access Denied. Please enter the correct password.")
    st.stop()

# ===== BACKGROUND IMAGE FROM URL =====
st.markdown(
    f"""
    <style>
    .stApp {{
        background-image: url("https://media.istockphoto.com/id/1277739542/photo/cybersecurity-digital-technology-privacy-concept.jpg");
        background-size: cover;
        background-position: center;
        background-attachment: fixed;
    }}
    .overlay {{
        background-color: rgba(0,0,0,0.65);
        padding: 20px;
        border-radius: 10px;
    }}
    .success {{color: #39ff14; font-weight: bold; font-family: monospace;}}
    .warning {{color: #ffff33; font-weight: bold; font-family: monospace;}}
    .critical {{color: #ff073a; font-weight: bold; font-family: monospace;}}
    </style>
    """, unsafe_allow_html=True
)

# ===== DATA =====
known_bad_ips = {
    "192.168.10.45": "Malware Command & Control",
    "203.0.113.99": "Phishing Server",
    "45.67.89.101": "DDoS Botnet Node"
}

attack_types = [
    "Phishing Email",
    "Malware Injection",
    "DDoS Attack",
    "Ransomware",
    "Port Scanning",
    "Brute Force Login"
]

severity_map = {
    "Phishing Email": "Low",
    "Port Scanning": "Medium",
    "Brute Force Login": "Medium",
    "Malware Injection": "High",
    "Ransomware": "Critical",
    "DDoS Attack": "Critical"
}

fake_geo = ["US", "IN", "RU", "CN", "DE", "BR", "FR", "GB"]

# ===== UTILS =====
def current_time():
    return datetime.now().strftime("%H:%M:%S")

def log_event(msg, level="info"):
    if level == "success":
        st.markdown(f"<p class='success'>✅ {msg}</p>", unsafe_allow_html=True)
    elif level == "warning":
        st.markdown(f"<p class='warning'>⚠️ {msg}</p>", unsafe_allow_html=True)
    elif level == "critical":
        st.markdown(f"<p class='critical'>🚨 {msg}</p>", unsafe_allow_html=True)
    else:
        st.markdown(f"ℹ️ {msg}")

def automated_response(ip, attack):
    log_event(f"[{current_time()}] 🚨 Threat detected: {attack} from {ip}", "critical")
    log_event("Blocking IP in firewall...", "warning")
    time.sleep(0.5)
    log_event("Quarantining affected device...", "warning")
    time.sleep(0.5)
    log_event("Alert sent to Security Team", "info")
    log_event("Threat neutralized successfully!", "success")
    return "Blocked"

def sandbox_analysis(file_name, delay):
    log_event(f"Sending {file_name} to sandbox for analysis...", "info")
    time.sleep(delay)
    verdict = random.choice(["MALICIOUS", "CLEAN"])
    if verdict == "MALICIOUS":
        log_event(f"Sandbox verdict: {verdict}", "critical")
    else:
        log_event(f"Sandbox verdict: {verdict}", "success")
    return verdict

def simulate_threat(ip, sandbox_delay, feed_data):
    attack = random.choice(attack_types)
    severity = severity_map[attack]
    country = random.choice(fake_geo)
    incident_id = f"INC-{random.randint(1000,9999)}"
    log_event(f"Simulating: {attack} from IP {ip} [{country}] | Severity: {severity}", "info")
    time.sleep(0.5)

    status = "Clean"
    if ip in known_bad_ips:
        log_event(f"IP matched Threat Intelligence DB: {known_bad_ips[ip]}", "critical")
        status = automated_response(ip, attack)
    else:
        if random.random() > 0.5:
            if attack in ["Malware Injection", "Ransomware"]:
                verdict = sandbox_analysis(f"file_{random.randint(100,999)}.exe", sandbox_delay)
                if verdict == "MALICIOUS":
                    status = automated_response(ip, attack)
                else:
                    log_event("No action needed. File is safe.", "success")
            else:
                status = automated_response(ip, attack)
        else:
            log_event("No malicious activity detected.", "success")

    feed_data.append({
        "Incident ID": incident_id,
        "Time": current_time(),
        "IP Address": ip,
        "Location": country,
        "Attack Type": attack,
        "Severity": severity,
        "Status": status
    })

# ===== UI =====
st.markdown("<div class='overlay'>", unsafe_allow_html=True)
st.title("🛡 CyberSecGuard – Threat Simulation & Response Dashboard")
st.warning("⚠ **Disclaimer:** This is a simulation. No real cyber threats are used. All attacks are artificial and for training purposes only.")
st.markdown("</div>", unsafe_allow_html=True)

# Sidebar controls
st.sidebar.header("Simulation Settings")
ip_input = st.sidebar.text_input("Enter IP addresses (comma-separated) or leave blank for random")
if ip_input:
    ip_list = [ip.strip() for ip in ip_input.split(",")]
else:
    ip_list = [f"192.168.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(5)]

num_runs = st.sidebar.number_input("Number of simulations", min_value=1, value=len(ip_list))
sandbox_delay = st.sidebar.slider("Sandbox analysis delay (seconds)", 1, 5, 2)
sim_speed = st.sidebar.slider("Simulation speed (seconds per attack)", 0.1, 2.0, 0.5)

new_threat = st.sidebar.text_input("Add known bad IP (format: IP=Description) or leave blank")
if "=" in new_threat:
    ip, desc = new_threat.split("=")
    known_bad_ips[ip.strip()] = desc.strip()

feed_data = []
feed_placeholder = st.empty()

if st.button("🚀 Run Simulation"):
    st.markdown("---")
    log_event("Simulation Started...", "info")
    for i in range(num_runs):
        ip = ip_list[i % len(ip_list)]
        simulate_threat(ip, sandbox_delay, feed_data)
        feed_placeholder.dataframe(pd.DataFrame(feed_data))
        time.sleep(sim_speed)

    log_event("Simulation Completed.", "success")

    csv = pd.DataFrame(feed_data).to_csv(index=False).encode('utf-8')
    st.download_button("📥 Download Report", csv, "cybersecguard_report.csv", "text/csv")

    st.subheader("📊 Attack Type Frequency")
    chart_df = pd.DataFrame(feed_data)["Attack Type"].value_counts()
    st.bar_chart(chart_df)

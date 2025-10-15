import streamlit as st
import pandas as pd

# Konfigurasi halaman
st.set_page_config(
    page_title="Mobile Banking Threat Model",
    page_icon="🛡️",
    layout="wide"
)

# Inisialisasi session state
if 'threats' not in st.session_state:
    st.session_state.threats = {
        'spoofing': [],
        'tampering': [],
        'repudiation': [],
        'information_disclosure': [],
        'denial_of_service': [],
        'elevation_of_privilege': []
    }

if 'monitoring' not in st.session_state:
    st.session_state.monitoring = []

# Header
st.title("Mobile Banking App - Threat Model")
st.subheader("STRIDE Framework Implementation Exercise")

# Metrics Dashboard
col1, col2, col3 = st.columns(3)
total_threats = sum(len(v) for v in st.session_state.threats.values())

with col1:
    st.metric("Total Threats Identified", total_threats)
with col2:
    st.metric("Monitoring Mechanisms", len(st.session_state.monitoring))
with col3:
    categories_covered = sum(1 for v in st.session_state.threats.values() if len(v) > 0)
    st.metric("STRIDE Categories Covered", f"{categories_covered}/6")

st.divider()

# Tabs
tab1, tab2, tab3, tab4 = st.tabs([
    "1. Identify Assets", 
    "2. Apply STRIDE", 
    "3. Monitoring & Response", 
    "4. Summary"
])

# TAB 1: IDENTIFY ASSETS
with tab1:
    st.header("Critical Assets to Protect")
    st.write("Identify and prioritize assets in the mobile banking application")
    
    assets_data = {
        'Asset Name': [
            'User Credentials',
            'Transaction Data',
            'Personal Information',
            'Session Tokens',
            'Account Balance'
        ],
        'Description': [
            'Username, password, biometric data',
            'Payment details, account numbers',
            'Name, address, phone number',
            'Authentication tokens, API keys',
            'Financial information'
        ],
        'Risk Level': [
            'Critical',
            'Critical',
            'High',
            'High',
            'Critical'
        ]
    }
    
    df_assets = pd.DataFrame(assets_data)
    st.dataframe(df_assets, use_container_width=True, hide_index=True)
    
    st.info("Tip: Critical assets require the strongest security controls and monitoring")

# TAB 2: STRIDE THREAT MODELING
with tab2:
    st.header("STRIDE Threat Modeling")
    st.write("Identify threats for each STRIDE category")
    
    # STRIDE Categories
    stride_categories = {
        'spoofing': {
            'name': 'Spoofing',
            'description': 'Pretending to be someone or something else',
            'examples': [
                'Fake login pages',
                'Credential theft',
                'Session hijacking',
                'Phishing attacks'
            ]
        },
        'tampering': {
            'name': 'Tampering',
            'description': 'Modifying data or code',
            'examples': [
                'Transaction manipulation',
                'API tampering',
                'Code injection',
                'Man-in-the-middle attacks'
            ]
        },
        'repudiation': {
            'name': 'Repudiation',
            'description': 'Denying actions performed',
            'examples': [
                'No transaction logs',
                'Missing audit trails',
                'Weak authentication',
                'Insufficient logging'
            ]
        },
        'information_disclosure': {
            'name': 'Information Disclosure',
            'description': 'Exposing sensitive information',
            'examples': [
                'Data leakage',
                'Insecure storage',
                'Unencrypted communication',
                'Information exposure'
            ]
        },
        'denial_of_service': {
            'name': 'Denial of Service',
            'description': 'Making system unavailable',
            'examples': [
                'DDoS attacks',
                'Resource exhaustion',
                'API flooding',
                'System overload'
            ]
        },
        'elevation_of_privilege': {
            'name': 'Elevation of Privilege',
            'description': 'Gaining unauthorized access',
            'examples': [
                'Privilege escalation',
                'Admin access bypass',
                'Role manipulation',
                'Authorization bypass'
            ]
        }
    }
    
    # Display STRIDE categories overview
    st.subheader("STRIDE Categories Overview")
    
    for key, category in stride_categories.items():
        threat_count = len(st.session_state.threats[key])
        status = "Covered" if threat_count > 0 else "Not Covered"
        
        with st.expander(f"{category['name']} - {threat_count} threats identified ({status})"):
            st.write(f"**Description:** {category['description']}")
            st.write("**Examples:**")
            for example in category['examples']:
                st.write(f"- {example}")
    
    st.divider()
    
    # Select category to add threats
    st.subheader("Add Threats to STRIDE Category")
    
    selected_category = st.selectbox(
        "Select STRIDE Category:",
        options=list(stride_categories.keys()),
        format_func=lambda x: stride_categories[x]['name']
    )
    
    # Show current category info
    st.write(f"**{stride_categories[selected_category]['name']}:** {stride_categories[selected_category]['description']}")
    
    # Add threat form
    new_threat = st.text_input(
        "Describe the threat:", 
        key="threat_input",
        placeholder="Enter a threat description..."
    )
    
    col1, col2 = st.columns([1, 5])
    with col1:
        add_button = st.button("Add Threat", type="primary", use_container_width=True)
    
    if add_button:
        if new_threat.strip():
            st.session_state.threats[selected_category].append(new_threat.strip())
            st.success(f"Threat added to {stride_categories[selected_category]['name']}")
            st.rerun()
        else:
            st.error("Please enter a threat description")
    
    # Quick add common threats
    st.write("**Quick Add Common Threats:**")
    
    common_threats = {
        'spoofing': [
            'Phishing attacks targeting user credentials',
            'Fake mobile app impersonation'
        ],
        'tampering': [
            'Man-in-the-middle attack during transaction',
            'API request manipulation'
        ],
        'repudiation': [
            'Insufficient audit logging',
            'No transaction verification'
        ],
        'information_disclosure': [
            'Insecure data storage on device',
            'Unencrypted network communication'
        ],
        'denial_of_service': [
            'API rate limiting not implemented',
            'Server resource exhaustion'
        ],
        'elevation_of_privilege': [
            'Broken access control',
            'Role-based authentication bypass'
        ]
    }
    
    if selected_category in common_threats:
        for threat in common_threats[selected_category]:
            if st.button(f"Add: {threat}", key=f"quick_{selected_category}_{threat}"):
                if threat not in st.session_state.threats[selected_category]:
                    st.session_state.threats[selected_category].append(threat)
                    st.rerun()
    
    st.divider()
    
    # Display identified threats
    st.subheader(f"Identified Threats for {stride_categories[selected_category]['name']}")
    st.write(f"Total: {len(st.session_state.threats[selected_category])} threats")
    
    if len(st.session_state.threats[selected_category]) == 0:
        st.info("No threats identified yet. Add threats above.")
    else:
        for idx, threat in enumerate(st.session_state.threats[selected_category]):
            col1, col2 = st.columns([5, 1])
            with col1:
                st.write(f"**{idx + 1}.** {threat}")
            with col2:
                if st.button("Delete", key=f"del_{selected_category}_{idx}"):
                    st.session_state.threats[selected_category].pop(idx)
                    st.rerun()

# TAB 3: MONITORING & RESPONSE
with tab3:
    st.header("Monitoring & Response Mechanisms")
    st.write("Define monitoring strategies and incident response procedures")
    
    # Add monitoring mechanism
    st.subheader("Add Monitoring Mechanism")
    
    new_monitoring = st.text_input(
        "Describe monitoring or response mechanism:", 
        key="monitoring_input",
        placeholder="Enter a monitoring mechanism..."
    )
    
    col1, col2 = st.columns([1, 5])
    with col1:
        add_mon_button = st.button("Add Mechanism", type="primary", use_container_width=True)
    
    if add_mon_button:
        if new_monitoring.strip():
            st.session_state.monitoring.append(new_monitoring.strip())
            st.success("Monitoring mechanism added")
            st.rerun()
        else:
            st.error("Please enter a mechanism description")
    
    # Quick add suggestions
    st.write("**Suggested Mechanisms:**")
    suggestions = [
        'Real-time transaction monitoring',
        'Failed login attempt tracking',
        'API rate limiting and alerts',
        'SIEM integration for log analysis',
        'Anomaly detection using ML',
        'Automated incident response playbooks',
        'Continuous security scanning',
        'User behavior analytics'
    ]
    
    cols = st.columns(2)
    for idx, suggestion in enumerate(suggestions):
        with cols[idx % 2]:
            if st.button(f"Add: {suggestion}", key=f"suggest_{idx}"):
                if suggestion not in st.session_state.monitoring:
                    st.session_state.monitoring.append(suggestion)
                    st.rerun()
    
    st.divider()
    
    # Display configured mechanisms
    st.subheader("Configured Monitoring Mechanisms")
    st.write(f"Total: {len(st.session_state.monitoring)} mechanisms")
    
    if len(st.session_state.monitoring) == 0:
        st.info("No monitoring mechanisms configured yet. Add mechanisms above.")
    else:
        for idx, mechanism in enumerate(st.session_state.monitoring):
            col1, col2 = st.columns([5, 1])
            with col1:
                st.success(f"**{idx + 1}.** {mechanism}")
            with col2:
                if st.button("Delete", key=f"del_mon_{idx}"):
                    st.session_state.monitoring.pop(idx)
                    st.rerun()

# TAB 4: SUMMARY
with tab4:
    st.header("Threat Model Summary")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("STRIDE Coverage")
        stride_summary = []
        for key, category in stride_categories.items():
            threat_count = len(st.session_state.threats[key])
            stride_summary.append({
                'Category': category['name'],
                'Threats': threat_count,
                'Status': 'Covered' if threat_count > 0 else 'Not Covered'
            })
        
        df_stride = pd.DataFrame(stride_summary)
        st.dataframe(df_stride, use_container_width=True, hide_index=True)
        
        # Overall statistics
        st.divider()
        st.write("**Overall Statistics:**")
        st.write(f"- Total Threats: {total_threats}")
        st.write(f"- Categories Covered: {categories_covered}/6")
        st.write(f"- Monitoring Mechanisms: {len(st.session_state.monitoring)}")
    
    with col2:
        st.subheader("Implementation Status")
        
        # Threats status
        if total_threats > 0:
            st.success(f"Threat Identification: {total_threats} total threats identified")
        else:
            st.warning("Threat Identification: No threats identified yet")
        
        # Monitoring status
        if len(st.session_state.monitoring) > 0:
            st.success(f"Monitoring Strategy: {len(st.session_state.monitoring)} mechanisms configured")
        else:
            st.warning("Monitoring Strategy: No mechanisms configured yet")
        
        # Completeness
        completeness = (categories_covered / 6) * 100
        
        st.divider()
        st.write("**Completeness Score:**")
        st.metric("Progress", f"{completeness:.0f}%")
        st.progress(completeness / 100)
        
        if completeness == 100:
            st.success("All STRIDE categories covered!")
        elif completeness >= 50:
            st.info("Good progress! Continue adding threats.")
        else:
            st.warning("Add more threats to cover all categories.")
    
    st.divider()
    
    # Detailed threat list
    st.subheader("All Identified Threats by Category")
    
    has_threats = False
    for key, category in stride_categories.items():
        if len(st.session_state.threats[key]) > 0:
            has_threats = True
            with st.expander(f"{category['name']} ({len(st.session_state.threats[key])} threats)"):
                for idx, threat in enumerate(st.session_state.threats[key]):
                    st.write(f"{idx + 1}. {threat}")
    
    if not has_threats:
        st.info("No threats identified yet. Start by adding threats in the 'Apply STRIDE' tab.")
    
    # Export functionality
    st.divider()
    st.subheader("Export Threat Model")
    
    if st.button("Generate Report", type="primary"):
        report = f"""MOBILE BANKING APP - THREAT MODEL REPORT
STRIDE Framework Analysis
{'=' * 60}

SUMMARY
-------
Total Threats Identified: {total_threats}
Monitoring Mechanisms: {len(st.session_state.monitoring)}
STRIDE Categories Covered: {categories_covered}/6
Completeness: {completeness:.0f}%

DETAILED THREATS
----------------
"""
        for key, category in stride_categories.items():
            report += f"\n{category['name'].upper()}\n"
            report += f"{'-' * len(category['name'])}\n"
            if len(st.session_state.threats[key]) > 0:
                for idx, threat in enumerate(st.session_state.threats[key]):
                    report += f"{idx + 1}. {threat}\n"
            else:
                report += "No threats identified.\n"
        
        report += f"\nMONITORING MECHANISMS\n"
        report += f"---------------------\n"
        if len(st.session_state.monitoring) > 0:
            for idx, mechanism in enumerate(st.session_state.monitoring):
                report += f"{idx + 1}. {mechanism}\n"
        else:
            report += "No monitoring mechanisms configured.\n"
        
        report += f"\n{'=' * 60}\n"
        report += "End of Report\n"
        
        st.download_button(
            label="Download Report as Text",
            data=report,
            file_name="threat_model_report.txt",
            mime="text/plain"
        )
        
        st.success("Report generated! Click button above to download.")

# Sidebar
with st.sidebar:
    st.markdown("### Atanasius Surya Gunadharma_220711667")
    st.header("Settings")
    st.subheader("Session Management")
    
    if st.button("Reset All Data", type="secondary", use_container_width=True):
        if st.session_state.get('confirm_reset', False):
            st.session_state.threats = {
                'spoofing': [],
                'tampering': [],
                'repudiation': [],
                'information_disclosure': [],
                'denial_of_service': [],
                'elevation_of_privilege': []
            }
            st.session_state.monitoring = []
            st.session_state.confirm_reset = False
            st.success("All data has been reset!")
            st.rerun()
        else:
            st.session_state.confirm_reset = True
            st.warning("Click again to confirm reset")
    
    if st.button("Cancel Reset", use_container_width=True):
        st.session_state.confirm_reset = False
        st.rerun()
    
    st.divider()
    
    st.subheader("Quick Guide")
    st.write("""
    **Steps:**
    1. Identify Assets - Review critical assets
    2. Apply STRIDE - Identify threats for each category
    3. Monitoring - Define response mechanisms
    4. Summary - Review and export report
    """)
    
    st.divider()
    
    st.subheader("Session Statistics")
    st.write(f"**Threats:** {total_threats}")
    st.write(f"**Monitoring:** {len(st.session_state.monitoring)}")
    st.write(f"**Coverage:** {categories_covered}/6 categories")
    
    # Show breakdown
    st.write("**Threats by Category:**")
    for key, category in stride_categories.items():
        count = len(st.session_state.threats[key])
        st.write(f"- {category['name']}: {count}")

# Footer
st.divider()
st.caption("Data Security and Privacy Protection - Week 5")
st.caption("Mobile Banking Threat Modeling Exercise using STRIDE Framework")

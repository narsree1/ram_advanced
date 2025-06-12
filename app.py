"""
Cybersecurity Response Platform
Main Streamlit Application

A comprehensive platform for SIEM rule analysis, incident response planning,
and SOAR workflow automation using Claude 3.5 Haiku.
"""
import streamlit as st
from cybersecurity_platform import CybersecurityResponsePlatform
from display_functions import (
    display_mitre_mapping, 
    display_incident_response_plan, 
    display_soar_workflow,
    display_tab_previews
)

# Configure page
st.set_page_config(
    page_title="Cybersecurity Response Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

def main():
    st.title("🛡️ Cybersecurity Response Platform")
    st.markdown("**Comprehensive SIEM analysis, incident response planning, and SOAR workflow automation**")
    
    # Sidebar configuration
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        # API Key setup
        default_api_key = st.secrets.get("CLAUDE_API_KEY", "")
        
        if default_api_key:
            api_key = default_api_key
            st.success("✅ API Key loaded from secrets")
        else:
            api_key = st.text_input(
                "Claude API Key", 
                type="password",
                placeholder="Enter your Claude API key...",
                help="Get your API key from https://console.anthropic.com/"
            )
            
            if not api_key:
                st.warning("Please enter your Claude API key to continue")
                st.info("💡 **Tip**: Configure the API key in Streamlit Cloud secrets")
                st.stop()
        
        # Model selection
        model_options = {
            "Claude 3.5 Haiku": "claude-3-5-haiku-20241022",
            "Claude 3.5 Sonnet": "claude-3-5-sonnet-20241022", 
            "Claude 3 Haiku": "claude-3-haiku-20240307",
            "Claude 3 Sonnet": "claude-3-sonnet-20240229"
        }
        
        selected_model_display = st.selectbox(
            "🤖 Model Selection",
            options=list(model_options.keys()),
            index=0,
            help="Choose the Claude model. Haiku is fastest for structured tasks."
        )
        selected_model = model_options[selected_model_display]
        
        confidence_threshold = st.slider(
            "Confidence Threshold",
            min_value=0.1,
            max_value=1.0,
            value=0.7,
            step=0.1,
            help="Minimum confidence score for technique relevance"
        )
        
        st.markdown("---")
        st.header("📋 Platform Modules")
        st.markdown("""
        **🎯 MITRE Mapping**
        - SIEM rule analysis
        - ATT&CK technique identification
        
        **📋 Incident Response**
        - L1/L2 investigation steps
        - Team-specific recommendations
        
        **🔄 SOAR Workflow**
        - End-to-end automation
        - Decision points & integrations
        """)
        
        # Model-specific tips
        if "haiku" in selected_model.lower():
            st.success("🚀 **Claude Haiku**: Lightning fast & cost-effective!")
        elif "sonnet" in selected_model.lower() and "3.5" in selected_model:
            st.info("⚡ **Claude 3.5 Sonnet**: Premium performance")
        else:
            st.warning("📝 **Claude 3**: Reliable baseline models")

    # Shared SIEM rule input
    st.header("📝 SIEM Rule Input")
    
    example_rules = {
        "Splunk - Suspicious PowerShell": """index=main sourcetype="WinEventLog:Security" EventCode=4688 | search process_name="*powershell.exe*" command_line="*-EncodedCommand*" | stats count by host, user, process_name, command_line""",
        
        "Splunk - Registry Persistence": """index=main sourcetype="WinEventLog:System" | search registry_path="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*" | stats count by host, registry_path, registry_value""",
        
        "Microsoft Sentinel - Suspicious Login": """SecurityEvent | where EventID == 4624 | where LogonType == 10 | summarize count() by Account, IpAddress | where count_ > 10""",
        
        "Microsoft Sentinel - Process Creation": """DeviceProcessEvents | where ProcessCommandLine contains "powershell" and ProcessCommandLine contains "-EncodedCommand" | summarize count() by DeviceName, AccountName""",
        
        "Elastic (ELK) - Network Connection": """{"query": {"bool": {"must": [{"term": {"event_type": "network"}}, {"range": {"destination_port": {"gte": 4444, "lte": 4445}}}]}}}""",
        
        "Elastic (ELK) - Suspicious Process": """{"query": {"bool": {"must": [{"wildcard": {"process.name": "*powershell*"}}, {"match": {"process.args": "EncodedCommand"}}]}}}""",
        
        "Google Chronicle - Domain Resolution": """metadata.event_type = "NETWORK_DNS" AND network.dns.questions.name = /.*suspicious-domain\\.com.*/ AND metadata.collected_timestamp.seconds > 86400""",
        
        "IBM QRadar - Failed Logins": """SELECT sourceip, username, eventname FROM events WHERE eventname = 'Failed Login' AND starttime > NOW() - INTERVAL '24 HOURS' GROUP BY sourceip HAVING COUNT(*) > 10""",
        
        "Sumo Logic - File Creation": """_source="windows-security" | parse "TargetFilename=*" as filename | where filename matches "*temp*.exe" | timeslice 1h | count by _timeslice, filename"""
    }
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        selected_example = st.selectbox("Choose example or enter custom:", ["Custom"] + list(example_rules.keys()))
        
        if selected_example != "Custom":
            siem_rule = st.text_area(
                "SIEM Rule:", 
                value=example_rules[selected_example],
                height=120,
                help="SIEM rule in any format (Splunk SPL, Elasticsearch, KQL, etc.)"
            )
        else:
            siem_rule = st.text_area(
                "SIEM Rule:", 
                height=120,
                placeholder="Enter your SIEM rule here...",
                help="SIEM rule in any format (Splunk SPL, Elasticsearch, KQL, etc.)"
            )
    
    with col2:
        st.markdown("**Quick Actions:**")
        analyze_button = st.button("🔍 Analyze Rule", type="primary", use_container_width=True)
        
        if st.button("🔄 Clear Results", use_container_width=True):
            if 'analysis_results' in st.session_state:
                del st.session_state['analysis_results']
            st.rerun()
        
        st.markdown("**Analysis Status:**")
        if 'analysis_results' in st.session_state:
            st.success("✅ Analysis Complete")
            st.info(f"🤖 Model: {selected_model_display}")
        else:
            st.info("⏳ Ready for Analysis")

    # Process analysis
    if analyze_button and siem_rule.strip():
        with st.spinner("🔍 Analyzing SIEM rule..."):
            platform = CybersecurityResponsePlatform(api_key, selected_model)
            
            # Progress tracking
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            try:
                status_text.text("Step 1/3: Extracting IoCs and mapping to MITRE ATT&CK...")
                progress_bar.progress(33)
                
                # Run complete analysis
                results = platform.run_complete_analysis(siem_rule, confidence_threshold)
                
                progress_bar.progress(66)
                status_text.text("Step 2/3: Generating incident response plan...")
                
                # Small delay for UI feedback
                import time
                time.sleep(0.5)
                
                progress_bar.progress(100)
                status_text.text("Step 3/3: Creating SOAR workflow...")
                
                time.sleep(0.5)
                
                if results:
                    # Store results in session state
                    st.session_state['analysis_results'] = results
                    status_text.text("✅ Analysis complete!")
                    st.success("🎉 Analysis completed successfully! Check the tabs below for results.")
                else:
                    status_text.text("❌ Analysis failed")
                    st.error("Analysis failed. Please check your input and try again.")
                
            except Exception as e:
                status_text.text(f"❌ Error: {str(e)}")
                st.error(f"Analysis failed: {str(e)}")

    st.markdown("---")

    # Main content with tabs - ALWAYS VISIBLE
    tab1, tab2, tab3 = st.tabs(["🎯 MITRE Mapping", "📋 Incident Response Plan", "🔄 SOAR Workflow"])
    
    # Get preview functions
    show_incident_response_preview, show_soar_workflow_preview = display_tab_previews()
    
    # Tab 1: MITRE Mapping
    with tab1:
        if 'analysis_results' in st.session_state:
            display_mitre_mapping(st.session_state['analysis_results'])
        else:
            st.header("🎯 MITRE ATT&CK Mapping")
            st.info("👆 **Enter a SIEM rule above and click 'Analyze Rule' to see MITRE ATT&CK technique mappings**")
            
            st.subheader("📋 What You'll Get:")
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("""
                **🔍 Rule Analysis:**
                - IoC extraction from SIEM rules
                - Natural language translation
                - Data source identification
                
                **🎯 MITRE Mapping:**
                - Relevant ATT&CK techniques
                - Confidence scoring (0.0-1.0)
                - Detailed reasoning for each match
                """)
            
            with col2:
                st.markdown("""
                **📊 Results Include:**
                - Technique IDs (e.g., T1055, T1003.001)
                - Technique names and descriptions
                - Attack behavior explanations
                
                **🔗 Contextual Information:**
                - Web-based IoC enrichment
                - Threat intelligence context
                - Attack pattern insights
                """)
            
            # Example results preview
            with st.expander("🔍 Example MITRE Mapping Result", expanded=False):
                st.markdown("""
                **T1059.001 - PowerShell** (Confidence: 0.92)
                
                **Description:** Adversaries may abuse PowerShell commands and scripts for execution.
                
                **Reasoning:** The SIEM rule specifically looks for PowerShell processes with encoded commands (`-EncodedCommand`), which is a common technique used by attackers to obfuscate malicious PowerShell scripts.
                """)
    
    # Tab 2: Incident Response Plan
    with tab2:
        if 'analysis_results' in st.session_state:
            display_incident_response_plan(st.session_state['analysis_results'])
        else:
            show_incident_response_preview()
    
    # Tab 3: SOAR Workflow
    with tab3:
        if 'analysis_results' in st.session_state:
            display_soar_workflow(st.session_state['analysis_results'])
        else:
            show_soar_workflow_preview()

    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center'>
        <p>Built with ❤️ using Streamlit and Claude API</p>
        <p><a href='https://github.com/your-username/cybersecurity-response-platform'>📚 View on GitHub</a> | 
        <a href='https://arxiv.org/html/2502.02337v1'>📄 Original Paper</a> |
        <a href='https://console.anthropic.com/'>🔑 Get Claude API Key</a></p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()

"""
Cybersecurity Response Platform - Enhanced Version
Main Streamlit Application with Separate Pages

A comprehensive platform for SIEM rule analysis, incident response planning,
and SOAR workflow automation using Claude 3.5 Haiku.
"""
import streamlit as st
from cybersecurity_platform import CybersecurityResponsePlatform
from enhanced_display_functions import (
    display_mitre_mapping, 
    display_incident_response_plan, 
    display_soar_workflow,
    display_home_page,
    display_rule_analysis_page
)

# Configure page
st.set_page_config(
    page_title="Cybersecurity Response Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

def main():
    # Sidebar navigation
    with st.sidebar:
        st.title("🛡️ Cyber Platform")
        st.markdown("---")
        
        # Navigation
        page = st.selectbox(
            "📍 Navigate to:",
            ["🏠 Home", "📝 Rule Analysis", "🎯 MITRE Mapping", "📋 Incident Response", "🔄 SOAR Workflow"],
            index=0
        )
        
        st.markdown("---")
        
        # Configuration section
        st.header("⚙️ Configuration")
        
        # API Key setup
        default_api_key = st.secrets.get("CLAUDE_API_KEY", "")
        
        if default_api_key:
            api_key = default_api_key
            st.success("✅ API Key loaded")
        else:
            api_key = st.text_input(
                "Claude API Key", 
                type="password",
                placeholder="Enter your Claude API key...",
                help="Get your API key from https://console.anthropic.com/"
            )
            
            if not api_key and page not in ["🏠 Home"]:
                st.warning("Please enter your Claude API key")
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
        
        # Status section
        st.header("📊 Status")
        if 'analysis_results' in st.session_state:
            st.success("✅ Analysis Complete")
            st.info(f"🤖 Model: {selected_model_display}")
            
            # Quick stats
            if st.session_state['analysis_results'].get('relevant_techniques'):
                techniques_count = len(st.session_state['analysis_results']['relevant_techniques'])
                st.metric("Techniques Found", techniques_count)
        else:
            st.info("⏳ Ready for Analysis")
        
        st.markdown("---")
        
        # Quick actions
        if 'analysis_results' in st.session_state:
            if st.button("🔄 Clear Results", use_container_width=True):
                del st.session_state['analysis_results']
                st.rerun()
        
        # Platform info
        st.markdown("---")
        st.header("📋 Modules")
        st.markdown("""
        **🎯 MITRE Mapping**
        - SIEM rule analysis
        - ATT&CK technique ID
        
        **📋 Incident Response**
        - Template-based procedures
        - L1/L2 investigation steps
        
        **🔄 SOAR Workflow**
        - Visual workflow diagram
        - End-to-end automation
        """)

    # Main content area - render based on selected page
    if page == "🏠 Home":
        display_home_page()
        
    elif page == "📝 Rule Analysis":
        display_rule_analysis_page(api_key, selected_model, confidence_threshold)
        
    elif page == "🎯 MITRE Mapping":
        if 'analysis_results' in st.session_state:
            display_mitre_mapping(st.session_state['analysis_results'])
        else:
            st.header("🎯 MITRE ATT&CK Mapping")
            st.info("👈 **Go to 'Rule Analysis' to analyze a SIEM rule first**")
            display_mitre_preview()
            
    elif page == "📋 Incident Response":
        if 'analysis_results' in st.session_state:
            display_incident_response_plan(st.session_state['analysis_results'])
        else:
            st.header("📋 Incident Response Plan")
            st.info("👈 **Go to 'Rule Analysis' to analyze a SIEM rule first**")
            display_incident_response_preview()
            
    elif page == "🔄 SOAR Workflow":
        if 'analysis_results' in st.session_state:
            display_soar_workflow(st.session_state['analysis_results'])
        else:
            st.header("🔄 SOAR Workflow")
            st.info("👈 **Go to 'Rule Analysis' to analyze a SIEM rule first**")
            display_soar_preview()

    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center'>
        <p>Built with ❤️ using Streamlit and Claude API</p>
        <p><a href='https://github.com/your-username/cybersecurity-response-platform'>📚 View on GitHub</a> | 
        <a href='https://console.anthropic.com/'>🔑 Get Claude API Key</a></p>
    </div>
    """, unsafe_allow_html=True)

def display_mitre_preview():
    """Preview content for MITRE mapping page"""
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

def display_incident_response_preview():
    """Preview content for incident response page"""
    st.subheader("🔍 Template-Based Investigation:")
    
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
        **📋 Structured Approach:**
        - ✅ Historical check procedures
        - ✅ Duplicate incident verification
        - ✅ Systematic event investigation
        - ✅ Clear recommendations
        
        **🛡️ Platform Support:**
        - 🟠 **Splunk** - SPL queries
        - 🔵 **Microsoft Sentinel** - KQL queries
        - 🟢 **Elastic (ELK)** - JSON DSL
        - 🔴 **IBM QRadar** - SQL queries
        """)
    
    with col2:
        st.markdown("""
        **⚡ Investigation Levels:**
        - 🔍 **Step 1** - Historical analysis
        - 🔍 **Step 2** - Duplicate check
        - 🔍 **Step 3** - Event investigation
        - 🔍 **Step 4** - Recommendations
        
        **🎯 Team Integration:**
        - 👥 SOC L1/L2 procedures
        - 🛠️ Platform-specific commands
        - 📈 Clear escalation criteria
        """)

def display_soar_preview():
    """Preview content for SOAR workflow page"""
    st.subheader("🔄 Visual Workflow Automation:")
    
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
        **🎨 Interactive Diagram:**
        - ✅ Visual workflow representation
        - ✅ Drag-and-drop interface
        - ✅ Real-time step updates
        - ✅ Decision point highlighting
        
        **🤖 Automation Steps:**
        - Alert ingestion & enrichment
        - Threat intelligence lookup
        - Automated containment
        - ServiceNow integration
        """)
    
    with col2:
        st.markdown("""
        **👤 Manual Interventions:**
        - L1 analyst review points
        - False positive determination
        - Evidence collection
        - Final case closure
        
        **📤 Export Options:**
        - 📊 JSON workflow export
        - 📋 Task checklist format
        - 🎫 ServiceNow templates
        """)

if __name__ == "__main__":
    main()

"""
Enhanced Display Functions for the Cybersecurity Response Platform
Includes template-based incident response and visual SOAR workflow
"""
import streamlit as st
import json
from data_models import TechniqueResult, SOARWorkflowStep

def display_home_page():
    """Display the home page with platform overview"""
    st.title("🛡️ Cybersecurity Response Platform")
    st.markdown("**Comprehensive SIEM analysis, incident response planning, and SOAR workflow automation**")
    
    # Platform overview
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        ### 🎯 MITRE Mapping
        **Automated ATT&CK Technique Identification**
        
        - Extract IoCs from SIEM rules
        - Map to MITRE ATT&CK framework
        - Confidence scoring & reasoning
        - Support for all major SIEM platforms
        
        **Supported Platforms:**
        - 🟠 Splunk (SPL)
        - 🔵 Microsoft Sentinel (KQL)
        - 🟢 Elastic Stack (JSON DSL)
        - 🔴 IBM QRadar (SQL)
        - 🟡 Google Chronicle (UDM)
        """)
    
    with col2:
        st.markdown("""
        ### 📋 Incident Response
        **Template-Based Investigation Procedures**
        
        - Structured 4-step approach
        - Historical analysis & duplicate checks
        - Platform-specific SIEM commands
        - Multi-EDR integration support
        
        **Investigation Steps:**
        - 📊 **Step 1:** Historical check
        - 🔍 **Step 2:** Duplicate verification
        - 🕵️ **Step 3:** Event investigation
        - 💡 **Step 4:** Recommendations
        """)
    
    with col3:
        st.markdown("""
        ### 🔄 SOAR Workflow
        **Visual Workflow Automation**
        
        - Interactive workflow diagrams
        - End-to-end automation steps
        - Decision points & manual interventions
        - ServiceNow integration templates
        
        **Workflow Components:**
        - 🤖 Automated actions
        - 👤 Manual review points
        - 🤔 Decision branches
        - 🎫 ITSM integration
        """)
    
    st.markdown("---")
    
    # Getting started section
    st.header("🚀 Getting Started")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("""
        ### Quick Start Guide:
        
        1. **📝 Rule Analysis**: Enter your SIEM rule in any format (SPL, KQL, JSON DSL, etc.)
        2. **🎯 MITRE Mapping**: View automatically mapped ATT&CK techniques with confidence scores
        3. **📋 Incident Response**: Get template-based investigation procedures for your platform
        4. **🔄 SOAR Workflow**: Visualize and export the complete automation workflow
        
        **Supported SIEM Rule Formats:**
        - Splunk Search Processing Language (SPL)
        - Microsoft Sentinel Kusto Query Language (KQL)
        - Elasticsearch Query DSL (JSON)
        - IBM QRadar SQL queries
        - Google Chronicle UDM syntax
        - Generic detection logic
        """)
    
    with col2:
        st.info("""
        **💡 Pro Tips:**
        
        ✅ Start with the Rule Analysis page
        
        ✅ Configure your Claude API key in the sidebar
        
        ✅ Adjust confidence threshold for MITRE mapping
        
        ✅ Export results for your SOAR platform
        """)
    
    # Example rules showcase
    st.header("📋 Example SIEM Rules")
    
    example_showcase = st.selectbox(
        "View example rules for different platforms:",
        ["Splunk - Suspicious PowerShell", "Microsoft Sentinel - Failed Logins", "Elastic - Network Connections"]
    )
    
    examples = {
        "Splunk - Suspicious PowerShell": {
            "code": """index=main sourcetype="WinEventLog:Security" EventCode=4688 
| search process_name="*powershell.exe*" command_line="*-EncodedCommand*" 
| stats count by host, user, process_name, command_line""",
            "description": "Detects PowerShell execution with encoded commands, often used for malicious script obfuscation."
        },
        "Microsoft Sentinel - Failed Logins": {
            "code": """SecurityEvent 
| where EventID == 4625 
| where LogonType == 2 
| summarize count() by Account, IpAddress 
| where count_ > 10""",
            "description": "Identifies accounts with multiple failed interactive login attempts from the same IP address."
        },
        "Elastic - Network Connections": {
            "code": """{
  "query": {
    "bool": {
      "must": [
        {"term": {"event_type": "network"}},
        {"range": {"destination_port": {"gte": 4444, "lte": 4445}}}
      ]
    }
  }
}""",
            "description": "Monitors network connections to suspicious high ports commonly used by backdoors."
        }
    }
    
    selected_example = examples[example_showcase]
    st.code(selected_example["code"], language="sql" if "SELECT" in selected_example["code"] else "json")
    st.write(f"**Description:** {selected_example['description']}")

def display_rule_analysis_page(api_key, selected_model, confidence_threshold):
    """Display the rule analysis input page"""
    st.title("📝 SIEM Rule Analysis")
    st.markdown("**Enter your SIEM rule to begin comprehensive analysis**")
    
    # Example rules
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
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        selected_example = st.selectbox("Choose example or enter custom:", ["Custom"] + list(example_rules.keys()))
        
        if selected_example != "Custom":
            siem_rule = st.text_area(
                "SIEM Rule:", 
                value=example_rules[selected_example],
                height=150,
                help="SIEM rule in any format (Splunk SPL, Elasticsearch, KQL, etc.)"
            )
        else:
            siem_rule = st.text_area(
                "SIEM Rule:", 
                height=150,
                placeholder="Enter your SIEM rule here...",
                help="SIEM rule in any format (Splunk SPL, Elasticsearch, KQL, etc.)"
            )
    
    with col2:
        st.markdown("**Analysis Actions:**")
        analyze_button = st.button("🔍 Analyze Rule", type="primary", use_container_width=True)
        
        st.markdown("**Current Configuration:**")
        st.info(f"🤖 **Model:** {selected_model.split('-')[2].title()}\n\n🎯 **Confidence:** {confidence_threshold}")
        
        if 'analysis_results' in st.session_state:
            st.success("✅ **Status:** Analysis Complete")
            if st.button("🔄 Run New Analysis", use_container_width=True):
                if 'analysis_results' in st.session_state:
                    del st.session_state['analysis_results']
                st.rerun()
        else:
            st.info("⏳ **Status:** Ready for Analysis")
    
    # Process analysis
    if analyze_button and siem_rule.strip():
        if not api_key:
            st.error("Please configure your Claude API key in the sidebar")
            return
            
        with st.spinner("🔍 Analyzing SIEM rule..."):
            platform = CybersecurityResponsePlatform(api_key, selected_model)
            
            # Progress tracking
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            try:
                status_text.text("Step 1/4: Extracting IoCs and contextual information...")
                progress_bar.progress(25)
                
                # Run complete analysis
                results = platform.run_complete_analysis(siem_rule, confidence_threshold)
                
                progress_bar.progress(50)
                status_text.text("Step 2/4: Mapping to MITRE ATT&CK techniques...")
                
                import time
                time.sleep(0.5)
                
                progress_bar.progress(75)
                status_text.text("Step 3/4: Generating incident response plan...")
                
                time.sleep(0.5)
                
                progress_bar.progress(100)
                status_text.text("Step 4/4: Creating SOAR workflow...")
                
                time.sleep(0.5)
                
                if results:
                    # Store results in session state
                    st.session_state['analysis_results'] = results
                    status_text.text("✅ Analysis complete!")
                    st.success("🎉 Analysis completed successfully! Navigate to other pages to view results.")
                    st.balloons()
                else:
                    status_text.text("❌ Analysis failed")
                    st.error("Analysis failed. Please check your input and try again.")
                
            except Exception as e:
                status_text.text(f"❌ Error: {str(e)}")
                st.error(f"Analysis failed: {str(e)}")
    
    # Show analysis preview when no rule is entered
    if not siem_rule or not siem_rule.strip():
        st.markdown("---")
        st.header("📊 Analysis Pipeline Overview")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown("""
            **🔍 Step 1: IoC Extraction**
            - Process names
            - File paths
            - Registry keys
            - Network indicators
            - Event codes
            """)
        
        with col2:
            st.markdown("""
            **🎯 Step 2: MITRE Mapping**
            - Technique identification
            - Confidence scoring
            - Reasoning analysis
            - Data source mapping
            """)
        
        with col3:
            st.markdown("""
            **📋 Step 3: Response Plan**
            - Template-based procedures
            - Platform-specific commands
            - Investigation steps
            - Team recommendations
            """)
        
        with col4:
            st.markdown("""
            **🔄 Step 4: SOAR Workflow**
            - Visual workflow diagram
            - Automation steps
            - Decision points
            - Export formats
            """)

def display_mitre_mapping(results):
    """Display MITRE ATT&CK mapping results"""
    st.header("🎯 MITRE ATT&CK Mapping Results")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("📋 Rule Description")
        st.write(results['rule_description'])
        
        st.subheader("🎯 Relevant MITRE ATT&CK Techniques")
        
        if results['relevant_techniques']:
            for i, technique in enumerate(results['relevant_techniques'][:5]):
                with st.expander(f"**{technique.id}** - {technique.name} (Confidence: {technique.confidence:.2f})", expanded=(i==0)):
                    st.write(f"**Description:** {technique.description}")
                    st.write(f"**Reasoning:** {technique.reasoning}")
                    st.progress(technique.confidence)
        else:
            st.warning("No relevant techniques found with current confidence threshold.")
    
    with col2:
        st.subheader("📊 Analysis Summary")
        
        # Metrics
        if results['relevant_techniques']:
            st.metric("Techniques Found", len(results['relevant_techniques']))
            avg_confidence = sum(t.confidence for t in results['relevant_techniques']) / len(results['relevant_techniques'])
            st.metric("Avg Confidence", f"{avg_confidence:.2f}")
            high_confidence = sum(1 for t in results['relevant_techniques'] if t.confidence >= 0.8)
            st.metric("High Confidence", high_confidence)
        
        st.subheader("🔍 Data Source")
        st.info(f"**{results['data_source']}**")
        
        # IoCs
        with st.expander("🔍 Extracted IoCs"):
            st.json(results['iocs'])

def display_incident_response_plan(results):
    """Display incident response plan in template format"""
    if not results.get('incident_plan'):
        st.header("📋 Incident Response Plan")
        st.warning("No incident response plan generated. Please run analysis first.")
        return
    
    plan = results['incident_plan']
    top_technique = results['relevant_techniques'][0] if results['relevant_techniques'] else None
    
    # Generate incident title
    incident_title = generate_incident_title(results['rule_description'], top_technique)
    
    st.title(f"📋 {incident_title}")
    
    # MITRE ATT&CK Mapping Table (following template format)
    st.subheader("🎯 MITRE ATT&CK Classification")
    
    if top_technique:
        # Create a table similar to the template
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("**Category**")
            st.info(classify_incident_category(results['rule_description']))
        
        with col2:
            st.markdown("**MITRE Tactic**")
            st.info(extract_mitre_tactic(top_technique.name))
        
        with col3:
            st.markdown("**MITRE Technique**")
            st.info(f"{top_technique.id}")
    
    # Description (following template format)
    st.subheader("📝 Description")
    st.write(f"This notable will trigger when {results['rule_description'].lower()}")
    
    # SIEM Platform Detection
    siem_platform = plan.get('siem_platform', 'Generic SIEM')
    st.info(f"🔧 **Detected SIEM Platform:** {siem_platform}")
    
    st.markdown("---")
    
    # Main investigation steps (following template format)
    st.header("🕵️ When the analyst receives the alert, they need to perform below activities:")
    
    # Step 1: Historical check
    st.subheader("📊 Step 1: Historical check")
    with st.container():
        st.markdown("""
        - Check previous notable events related to the same indicators or user accounts in the authentication threat category
        - Note any useful comments or additional information from previous incidents
        - Review historical patterns for similar attack vectors
        - Identify if this is part of a larger campaign
        """)
        
        if plan.get('l1_steps') and len(plan['l1_steps']) > 0:
            st.markdown("**Platform-specific queries:**")
            for cmd in plan['l1_steps'][0].get('siem_commands', []):
                st.code(cmd, language="sql")
    
    # Step 2: Duplicate check
    st.subheader("🔍 Step 2: Duplicate check and add details to Investigation")
    with st.container():
        st.markdown("""
        - Search if there is an open incident for the same issue in ServiceNow
        - If yes, add any new information captured from the new notable to existing incident
        - Close the new notable as Duplicate if appropriate
        - Update the master incident with additional context
        """)
    
    # Step 3: Investigate the events
    st.subheader("🕵️ Step 3: Investigate the events")
    with st.container():
        st.markdown("**Collect the below information from the respective SIEM notable event:**")
        
        # Information to collect (specific to the detection type)
        info_to_collect = generate_collection_items(results['rule_description'], results['iocs'])
        for item in info_to_collect:
            st.markdown(f"- {item}")
        
        # L1 Investigation Steps
        if plan.get('l1_steps'):
            st.markdown("**L1 Investigation Procedures:**")
            for i, step in enumerate(plan['l1_steps'], 1):
                with st.expander(f"L1.{i}: {step.get('step', 'Investigation Step')}", expanded=(i==1)):
                    st.write(step.get('step', 'No description'))
                    
                    if step.get('siem_commands'):
                        st.markdown(f"**{siem_platform} Query:**")
                        for cmd in step['siem_commands']:
                            st.code(cmd, language="sql")
                    
                    if isinstance(step.get('edr_commands'), dict):
                        st.markdown("**EDR Queries:**")
                        for platform, cmd in step['edr_commands'].items():
                            st.markdown(f"**{platform}:**")
                            st.code(cmd, language="bash")
                    
                    st.write(f"**Expected Outcome:** {step.get('expected_outcome', 'Gather relevant evidence')}")
                    st.write(f"**Timeline:** {step.get('timeline', '15-20 minutes')}")
        
        # L2 Investigation Steps (if available)
        if plan.get('l2_steps'):
            st.markdown("**L2 Deep Analysis Procedures:**")
            for i, step in enumerate(plan['l2_steps'], 1):
                with st.expander(f"L2.{i}: {step.get('step', 'Deep Analysis Step')}"):
                    st.write(step.get('step', 'No description'))
                    
                    if step.get('siem_commands'):
                        st.markdown(f"**Advanced {siem_platform} Query:**")
                        for cmd in step['siem_commands']:
                            st.code(cmd, language="sql")
                    
                    if isinstance(step.get('edr_commands'), dict):
                        st.markdown("**Multi-Platform EDR Analysis:**")
                        for platform_name, commands in step['edr_commands'].items():
                            if isinstance(commands, list):
                                st.markdown(f"**{platform_name}:**")
                                for cmd in commands:
                                    st.code(cmd, language="bash")
                    
                    st.write(f"**Expected Outcome:** {step.get('expected_outcome', 'Comprehensive threat analysis')}")
                    st.write(f"**Timeline:** {step.get('timeline', '30-45 minutes')}")
    
    # Step 4: Recommendations
    st.subheader("💡 Step 4: Recommendations")
    with st.container():
        if plan.get('resolver_recommendations'):
            for rec in plan['resolver_recommendations']:
                priority_emoji = {'High': '🔴', 'Medium': '🟡', 'Low': '🟢'}.get(rec.get('priority', 'Medium'), '🟡')
                
                st.markdown(f"**{priority_emoji} {rec.get('team', 'Security Team')}:**")
                st.markdown(f"- {rec.get('action', 'Take appropriate action')}")
                if rec.get('platform_specific'):
                    st.markdown(f"- Platform Implementation: {rec['platform_specific']}")
                st.markdown(f"- Priority: {rec.get('priority', 'Medium')} | Timeline: {rec.get('timeline', 'ASAP')}")
                st.markdown("")
        else:
            # Default recommendations based on technique type
            default_recommendations = generate_default_recommendations(results['rule_description'], top_technique)
            for rec in default_recommendations:
                st.markdown(f"- {rec}")

def display_soar_workflow(results):
    """Display visual SOAR workflow with interactive diagram"""
    st.header("🔄 SOAR Workflow Visualization")
    
    if not results.get('soar_workflow'):
        st.warning("No SOAR workflow generated. Please run analysis first.")
        return
    
    workflow = results['soar_workflow']
    
    # Workflow overview metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        automated_steps = sum(1 for step in workflow if step.type == 'automated')
        st.metric("🤖 Automated", automated_steps)
    with col2:
        manual_steps = sum(1 for step in workflow if step.type == 'manual')
        st.metric("👤 Manual", manual_steps)
    with col3:
        decision_steps = sum(1 for step in workflow if step.type == 'decision')
        st.metric("🤔 Decisions", decision_steps)
    with col4:
        st.metric("📋 Total Steps", len(workflow))
    
    # Interactive Visual Workflow
    st.subheader("📊 Interactive Workflow Diagram")
    
    # Generate the visual workflow HTML
    workflow_html = generate_visual_workflow_html(workflow)
    
    # Display the interactive workflow
    st.components.v1.html(workflow_html, height=600, scrolling=True)
    
    st.markdown("---")
    
    # Detailed workflow steps
    st.subheader("📋 Detailed Workflow Steps")
    
    for i, step in enumerate(workflow):
        type_emoji = {"automated": "🤖", "manual": "👤", "decision": "🤔"}.get(step.type, "📋")
        type_color = {"automated": "blue", "manual": "orange", "decision": "red"}.get(step.type, "gray")
        
        with st.expander(f"{type_emoji} {step.step_id}: {step.name}", expanded=(i<3)):
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.write(f"**Description:** {step.description}")
                st.write(f"**Responsible Team:** {step.responsible_team}")
                
                if step.inputs:
                    st.write("**Required Inputs:**")
                    for inp in step.inputs:
                        st.write(f"• {inp}")
                
                if step.outputs:
                    st.write("**Expected Outputs:**")
                    for out in step.outputs:
                        st.write(f"• {out}")
            
            with col2:
                st.markdown(f"**Type:** :{type_color}[{step.type.upper()}]")
                
                if step.next_steps:
                    st.write("**Next Steps:**")
                    for next_step in step.next_steps:
                        st.write(f"→ {next_step}")
                
                # Interactive elements for decision points
                if step.type == 'decision':
                    st.write("**Quick Actions:**")
                    if st.button("✅ Approve", key=f"approve_{step.step_id}"):
                        st.success(f"Step {step.step_id} approved!")
                    if st.button("⚠️ Escalate", key=f"escalate_{step.step_id}"):
                        st.warning(f"Step {step.step_id} escalated!")
    
    # Export options
    st.markdown("---")
    st.subheader("📤 Export Workflow")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        workflow_json = json.dumps([{
            'step_id': step.step_id,
            'name': step.name,
            'type': step.type,
            'description': step.description,
            'responsible_team': step.responsible_team,
            'inputs': step.inputs,
            'outputs': step.outputs,
            'next_steps': step.next_steps
        } for step in workflow], indent=2)
        
        st.download_button(
            label="📊 Download JSON",
            data=workflow_json,
            file_name="soar_workflow.json",
            mime="application/json",
            use_container_width=True
        )
    
    with col2:
        checklist = generate_workflow_checklist(workflow)
        st.download_button(
            label="📋 Download Checklist",
            data=checklist,
            file_name="workflow_checklist.md",
            mime="text/markdown",
            use_container_width=True
        )
    
    with col3:
        snow_template = generate_servicenow_template(results)
        st.download_button(
            label="🎫 ServiceNow Template",
            data=snow_template,
            file_name="servicenow_template.txt",
            mime="text/plain",
            use_container_width=True
        )

def generate_visual_workflow_html(workflow):
    """Generate HTML for interactive workflow visualization"""
    
    # Prepare workflow data for JavaScript
    workflow_data = []
    for step in workflow:
        workflow_data.append({
            'id': step.step_id,
            'name': step.name,
            'type': step.type,
            'description': step.description[:100] + "..." if len(step.description) > 100 else step.description,
            'team': step.responsible_team,
            'next_steps': step.next_steps
        })
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
                margin: 0;
                padding: 20px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 580px;
            }}
            
            .workflow-container {{
                display: flex;
                flex-direction: column;
                align-items: center;
                gap: 30px;
                padding: 20px;
            }}
            
            .workflow-step {{
                background: rgba(255, 255, 255, 0.95);
                border-radius: 15px;
                padding: 20px;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 255, 255, 0.18);
                max-width: 400px;
                width: 100%;
                transition: all 0.3s ease;
                cursor: pointer;
                position: relative;
            }}
            
            .workflow-step:hover {{
                transform: translateY(-5px);
                box-shadow: 0 15px 40px rgba(0, 0, 0, 0.15);
            }}
            
            .step-header {{
                display: flex;
                align-items: center;
                margin-bottom: 10px;
            }}
            
            .step-icon {{
                font-size: 24px;
                margin-right: 12px;
            }}
            
            .step-title {{
                font-weight: 600;
                font-size: 16px;
                color: #2c3e50;
            }}
            
            .step-type {{
                position: absolute;
                top: 10px;
                right: 15px;
                padding: 4px 8px;
                border-radius: 12px;
                font-size: 11px;
                font-weight: 600;
                text-transform: uppercase;
            }}
            
            .type-automated {{
                background: #e3f2fd;
                color: #1976d2;
            }}
            
            .type-manual {{
                background: #fff3e0;
                color: #f57c00;
            }}
            
            .type-decision {{
                background: #ffebee;
                color: #d32f2f;
            }}
            
            .step-description {{
                color: #5f6368;
                font-size: 14px;
                line-height: 1.4;
                margin-bottom: 10px;
            }}
            
            .step-team {{
                font-size: 12px;
                color: #8e8e93;
                font-weight: 500;
            }}
            
            .connector {{
                width: 2px;
                height: 30px;
                background: linear-gradient(to bottom, rgba(255,255,255,0.8), rgba(255,255,255,0.3));
                position: relative;
            }}
            
            .connector::after {{
                content: '▼';
                position: absolute;
                bottom: -5px;
                left: 50%;
                transform: translateX(-50%);
                color: rgba(255,255,255,0.8);
                font-size: 12px;
            }}
            
            .workflow-title {{
                color: white;
                font-size: 24px;
                font-weight: 600;
                text-align: center;
                margin-bottom: 10px;
                text-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            
            .workflow-subtitle {{
                color: rgba(255,255,255,0.9);
                font-size: 14px;
                text-align: center;
                margin-bottom: 20px;
            }}
            
            @keyframes slideIn {{
                from {{
                    opacity: 0;
                    transform: translateY(20px);
                }}
                to {{
                    opacity: 1;
                    transform: translateY(0);
                }}
            }}
            
            .workflow-step {{
                animation: slideIn 0.6s ease forwards;
            }}
        </style>
    </head>
    <body>
        <div class="workflow-container">
            <div class="workflow-title">🔄 SOAR Automation Workflow</div>
            <div class="workflow-subtitle">End-to-End Incident Response Automation</div>
    """
    
    # Add workflow steps
    for i, step in enumerate(workflow_data):
        type_icons = {"automated": "🤖", "manual": "👤", "decision": "🤔"}
        icon = type_icons.get(step['type'], "📋")
        
        html += f"""
        <div class="workflow-step" style="animation-delay: {i * 0.1}s;">
            <div class="step-type type-{step['type']}">{step['type']}</div>
            <div class="step-header">
                <div class="step-icon">{icon}</div>
                <div class="step-title">{step['id']}: {step['name']}</div>
            </div>
            <div class="step-description">{step['description']}</div>
            <div class="step-team">👥 {step['team']}</div>
        </div>
        """
        
        # Add connector (except for last step)
        if i < len(workflow_data) - 1:
            html += '<div class="connector"></div>'
    
    html += """
        </div>
        
        <script>
            document.querySelectorAll('.workflow-step').forEach(step => {
                step.addEventListener('click', function() {
                    const stepId = this.querySelector('.step-title').textContent.split(':')[0];
                    this.style.background = 'rgba(76, 175, 80, 0.1)';
                    this.style.borderColor = '#4caf50';
                    
                    setTimeout(() => {
                        this.style.background = 'rgba(255, 255, 255, 0.95)';
                        this.style.borderColor = 'rgba(255, 255, 255, 0.18)';
                    }, 2000);
                });
            });
        </script>
    </body>
    </html>
    """
    
    return html

# Helper functions
def generate_incident_title(rule_description, top_technique):
    """Generate incident title based on rule description and top technique"""
    if "powershell" in rule_description.lower():
        return "Suspicious PowerShell Execution Detected"
    elif "registry" in rule_description.lower():
        return "Registry Persistence Mechanism Detected"
    elif "network" in rule_description.lower():
        return "Suspicious Network Activity Detected"
    elif "login" in rule_description.lower() or "authentication" in rule_description.lower():
        return "Suspicious Authentication Activity Detected"
    elif "file" in rule_description.lower():
        return "Suspicious File Activity Detected"
    elif top_technique:
        return f"{top_technique.name} - Security Alert"
    else:
        return "Security Alert - Suspicious Activity Detected"

def classify_incident_category(rule_description):
    """Classify incident based on rule description"""
    rule_lower = rule_description.lower()
    
    if any(word in rule_lower for word in ["privilege", "escalation", "admin"]):
        return "Unauthorized Privilege Activity"
    elif any(word in rule_lower for word in ["data", "transfer", "exfiltration"]):
        return "Data Exfiltration"
    elif any(word in rule_lower for word in ["network", "connection", "port"]):
        return "Suspicious Network Communication"
    elif any(word in rule_lower for word in ["phishing", "email", "malicious"]):
        return "Suspicious User Behaviour"
    else:
        return "Suspicious System Activity"

def extract_mitre_tactic(technique_name):
    """Extract MITRE tactic from technique name"""
    tactic_mapping = {
        "execution": "Execution",
        "persistence": "Persistence", 
        "privilege": "Privilege Escalation",
        "defense": "Defense Evasion",
        "credential": "Credential Access",
        "discovery": "Discovery",
        "lateral": "Lateral Movement",
        "collection": "Collection",
        "command": "Command and Control",
        "exfiltration": "Exfiltration",
        "impact": "Impact"
    }
    
    technique_lower = technique_name.lower()
    for keyword, tactic in tactic_mapping.items():
        if keyword in technique_lower:
            return tactic
    
    return "Execution"  # Default tactic

def generate_collection_items(rule_description, iocs):
    """Generate items to collect during investigation"""
    items = []
    
    # Always include basic information
    items.extend([
        "Event Time/Timestamp",
        "Source Host/Hostname", 
        "User Account/Username",
        "Source IP Address",
        "Destination Information"
    ])
    
    # Add specific items based on rule content
    if "powershell" in rule_description.lower():
        items.extend([
            "PowerShell Command Line Arguments",
            "Encoded Command Content",
            "Parent Process Information",
            "Process Execution Path"
        ])
    
    if "registry" in rule_description.lower():
        items.extend([
            "Registry Key Path",
            "Registry Value Name",
            "Registry Value Data",
            "Registry Action (Create/Modify/Delete)"
        ])
    
    if "network" in rule_description.lower():
        items.extend([
            "Destination Port",
            "Protocol Used",
            "Bytes Transferred",
            "Connection Duration"
        ])
    
    # Add IoC-specific items
    if 'processes' in iocs:
        items.append("Process Names and Paths")
    if 'files' in iocs:
        items.append("File Names and Locations")
    if 'registry_keys' in iocs:
        items.append("Registry Modifications")
    
    return items

def generate_default_recommendations(rule_description, top_technique):
    """Generate default recommendations based on detection type"""
    recommendations = []
    
    # Basic recommendations
    recommendations.extend([
        "Verify the activity with the responsible administrator or user",
        "Check if the reported activity is part of authorized maintenance or testing",
        "If unauthorized, immediately isolate the affected system(s)",
        "Document all findings and evidence for further analysis"
    ])
    
    # Specific recommendations based on content
    if "powershell" in rule_description.lower():
        recommendations.extend([
            "Decode any base64 encoded PowerShell commands",
            "Check for PowerShell execution policy bypasses",
            "Review PowerShell logs for additional suspicious activity",
            "Consider implementing PowerShell constrained language mode"
        ])
    
    if "network" in rule_description.lower():
        recommendations.extend([
            "Block suspicious IP addresses at the firewall level",
            "Monitor for additional connections from the same source",
            "Check network logs for data exfiltration patterns",
            "Implement network segmentation if appropriate"
        ])
    
    return recommendations[:8]  # Limit to 8 recommendations

def generate_workflow_checklist(workflow):
    """Generate a checklist format of the workflow"""
    checklist = "# SOAR Workflow Execution Checklist\n\n"
    checklist += f"**Total Steps:** {len(workflow)}\n"
    checklist += f"**Generated:** {st.session_state.get('analysis_timestamp', 'Now')}\n\n"
    
    for step in workflow:
        type_emoji = {"automated": "🤖", "manual": "👤", "decision": "🤔"}.get(step.type, "📋")
        checklist += f"- [ ] **{step.step_id}** - {step.name} {type_emoji}\n"
        checklist += f"  - **Team:** {step.responsible_team}\n"
        checklist += f"  - **Type:** {step.type.title()}\n"
        checklist += f"  - **Description:** {step.description}\n"
        if step.inputs:
            checklist += f"  - **Requires:** {', '.join(step.inputs)}\n"
        checklist += "\n"
    
    return checklist

def generate_servicenow_template(results):
    """Generate ServiceNow ticket template"""
    techniques = results.get('relevant_techniques', [])
    top_technique = techniques[0] if techniques else None
    
    template = f"""
╔════════════════════════════════════════╗
║         SECURITY INCIDENT TICKET       ║
╚════════════════════════════════════════╝

📋 INCIDENT DETAILS
═══════════════════════════════════════════
Title: Security Alert - {top_technique.name if top_technique else 'Suspicious Activity'} Detected
Priority: {'High' if top_technique and top_technique.confidence > 0.8 else 'Medium'}
Category: Security Incident
Subcategory: MITRE ATT&CK Detection

🎯 THREAT CLASSIFICATION
═══════════════════════════════════════════
MITRE ATT&CK Techniques:
{chr(10).join([f"• {t.id}: {t.name} (Confidence: {t.confidence:.2f})" for t in techniques[:3]])}

Detection Rule: {results.get('rule_description', 'Security rule triggered')[:200]}...

📊 ASSIGNMENT INFORMATION
═══════════════════════════════════════════
Assignment Groups:
• SOC L1 Team (Initial triage and false positive determination)
• SOC L2 Team (Deep analysis if escalated)
• Security Engineering (Rule tuning and improvements)
• Incident Response Team (Escalated incidents)

🔍 INVESTIGATION STATUS
═══════════════════════════════════════════
☐ Step 1: Historical check completed
☐ Step 2: Duplicate verification completed  
☐ Step 3: Event investigation completed
☐ Step 4: Recommendations implemented

📝 WORK NOTES
═══════════════════════════════════════════
• Automated MITRE ATT&CK mapping completed
• Incident response plan generated
• SOAR workflow initiated
• Platform-specific investigation commands provided

🎯 NEXT STEPS
═══════════════════════════════════════════
1. L1 analyst to review alert within 15 minutes
2. Determine false positive status using provided checklist
3. If legitimate threat, escalate to L2 for deep analysis
4. Follow structured investigation procedures
5. Update ticket with findings and evidence
6. Implement recommended containment actions

📎 ATTACHMENTS
═══════════════════════════════════════════
• SOAR Workflow JSON Export
• Investigation Command Checklist  
• MITRE ATT&CK Mapping Report
• Platform-Specific Query Guide

🏷️ TAGS
═══════════════════════════════════════════
Security, MITRE-ATT&CK, Incident-Response, {top_technique.id if top_technique else 'Detection'}, SOAR-Automation

═══════════════════════════════════════════
Generated by Cybersecurity Response Platform
Powered by Claude AI | MITRE ATT&CK Framework
═══════════════════════════════════════════
"""
    return template

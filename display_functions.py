"""
Display functions for the Cybersecurity Response Platform
Handles UI rendering for all three tabs
"""
import streamlit as st
import json
from data_models import TechniqueResult, SOARWorkflowStep

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
    """Display incident response plan"""
    st.header("📋 Incident Response Plan")
    
    if not results.get('incident_plan'):
        st.warning("No incident response plan generated. Please run analysis first.")
        return
    
    plan = results['incident_plan']
    
    # Overview
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("L1 Steps", len(plan.get('l1_steps', [])))
    with col2:
        st.metric("L2 Steps", len(plan.get('l2_steps', [])))
    with col3:
        st.metric("Team Actions", len(plan.get('resolver_recommendations', [])))
    
    # L1 Investigation Steps
    st.subheader("🔍 SOC L1 Investigation Steps")
    
    if plan.get('l1_steps'):
        for i, step in enumerate(plan['l1_steps'], 1):
            with st.expander(f"L1 Step {i}: {step.get('step', 'Investigation Step')}", expanded=(i==1)):
                st.write(f"**Action:** {step.get('step', 'No description')}")
                
                if step.get('commands'):
                    st.write("**Commands/Tools:**")
                    for cmd in step['commands']:
                        st.code(cmd, language="bash")
                
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**Expected Outcome:** {step.get('expected_outcome', 'Not specified')}")
                with col2:
                    st.write(f"**Escalation Criteria:** {step.get('escalation_criteria', 'Not specified')}")
    else:
        st.info("No L1 investigation steps generated.")
    
    # L2 Investigation Steps
    st.subheader("🔬 SOC L2 Investigation Steps")
    
    if plan.get('l2_steps'):
        for i, step in enumerate(plan['l2_steps'], 1):
            with st.expander(f"L2 Step {i}: {step.get('step', 'Deep Analysis Step')}"):
                st.write(f"**Action:** {step.get('step', 'No description')}")
                
                if step.get('commands'):
                    st.write("**Commands/Tools:**")
                    for cmd in step['commands']:
                        st.code(cmd, language="bash")
                
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**Expected Outcome:** {step.get('expected_outcome', 'Not specified')}")
                with col2:
                    st.write(f"**Escalation Criteria:** {step.get('escalation_criteria', 'Not specified')}")
    else:
        st.info("No L2 investigation steps generated.")
    
    # Resolver Team Recommendations
    st.subheader("👥 Resolver Team Recommendations")
    
    if plan.get('resolver_recommendations'):
        for rec in plan['resolver_recommendations']:
            priority_color = {
                'High': '🔴',
                'Medium': '🟡', 
                'Low': '🟢'
            }.get(rec.get('priority', 'Medium'), '🟡')
            
            with st.expander(f"{priority_color} {rec.get('team', 'Team')} - {rec.get('action', 'Action')}"):
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**Priority:** {rec.get('priority', 'Medium')}")
                    st.write(f"**Timeline:** {rec.get('timeline', 'Not specified')}")
                with col2:
                    st.write(f"**Action:** {rec.get('action', 'No action specified')}")
    else:
        st.info("No resolver team recommendations generated.")

def display_soar_workflow(results):
    """Display SOAR workflow"""
    st.header("🔄 SOAR Workflow")
    
    if not results.get('soar_workflow'):
        st.warning("No SOAR workflow generated. Please run analysis first.")
        return
    
    workflow = results['soar_workflow']
    
    # Workflow overview
    col1, col2, col3 = st.columns(3)
    with col1:
        automated_steps = sum(1 for step in workflow if step.type == 'automated')
        st.metric("Automated Steps", automated_steps)
    with col2:
        manual_steps = sum(1 for step in workflow if step.type == 'manual')
        st.metric("Manual Steps", manual_steps)
    with col3:
        decision_steps = sum(1 for step in workflow if step.type == 'decision')
        st.metric("Decision Points", decision_steps)
    
    # Workflow visualization
    st.subheader("📊 Workflow Steps")
    
    for i, step in enumerate(workflow):
        # Step type styling
        type_emoji = {
            'automated': '🤖',
            'manual': '👤',
            'decision': '🤔'
        }.get(step.type, '📋')
        
        type_color = {
            'automated': 'blue',
            'manual': 'orange', 
            'decision': 'red'
        }.get(step.type, 'gray')
        
        with st.container():
            col1, col2 = st.columns([3, 1])
            
            with col1:
                with st.expander(f"{type_emoji} {step.step_id}: {step.name}", expanded=(i<3)):
                    st.write(f"**Description:** {step.description}")
                    st.write(f"**Responsible Team:** {step.responsible_team}")
                    
                    if step.inputs:
                        st.write("**Inputs:**")
                        for inp in step.inputs:
                            st.write(f"• {inp}")
                    
                    if step.outputs:
                        st.write("**Outputs:**")
                        for out in step.outputs:
                            st.write(f"• {out}")
                    
                    if step.next_steps:
                        st.write("**Next Steps:**")
                        for next_step in step.next_steps:
                            st.write(f"→ {next_step}")
            
            with col2:
                st.markdown(f"**Type:** :{type_color}[{step.type.upper()}]")
                
                # Special handling for decision points
                if step.type == 'decision':
                    st.write("**Decision Options:**")
                    if 'false positive' in step.description.lower():
                        if st.button("✅ Mark False Positive", key=f"fp_{step.step_id}", help="Close case as false positive"):
                            st.success("Case marked as false positive and closed.")
                        if st.button("⚠️ Escalate", key=f"esc_{step.step_id}", help="Escalate to L2/resolver teams"):
                            st.info("Case escalated to next level for investigation.")
                
                # ServiceNow integration hint
                if 'ticket' in step.description.lower() or 'servicenow' in step.description.lower():
                    st.info("🎫 ServiceNow Integration Point")
        
        # Add visual separator between steps
        if i < len(workflow) - 1:
            st.markdown("⬇️")
    
    # Export options
    st.subheader("📤 Export Options")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📊 Export to JSON"):
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
                label="⬇️ Download Workflow JSON",
                data=workflow_json,
                file_name="soar_workflow.json",
                mime="application/json"
            )
    
    with col2:
        if st.button("📋 Generate Checklist"):
            checklist = "# SOAR Workflow Checklist\n\n"
            for step in workflow:
                checklist += f"- [ ] {step.step_id}: {step.name} ({step.responsible_team})\n"
            
            st.download_button(
                label="⬇️ Download Checklist",
                data=checklist,
                file_name="workflow_checklist.md",
                mime="text/markdown"
            )
    
    with col3:
        if st.button("🎫 ServiceNow Template"):
            snow_template = generate_servicenow_template(results)
            st.download_button(
                label="⬇️ Download SNOW Template", 
                data=snow_template,
                file_name="servicenow_template.txt",
                mime="text/plain"
            )

def generate_servicenow_template(results):
    """Generate ServiceNow ticket template"""
    techniques = results.get('relevant_techniques', [])
    top_technique = techniques[0] if techniques else None
    
    template = f"""
SECURITY INCIDENT TICKET TEMPLATE

Title: Security Alert - {top_technique.name if top_technique else 'Suspicious Activity'} Detected

Priority: {'High' if top_technique and top_technique.confidence > 0.8 else 'Medium'}

Description:
{results.get('rule_description', 'Security rule triggered')}

MITRE ATT&CK Techniques:
{chr(10).join([f"- {t.id}: {t.name} (Confidence: {t.confidence:.2f})" for t in techniques[:3]])}

Assignment Groups:
- SOC L1 (Initial triage)
- SOC L2 (Deep analysis if escalated)
- Security Engineering (Rule tuning if needed)

Work Notes:
- Initial analysis completed via automated SIEM rule
- Incident response plan generated
- SOAR workflow initiated

Next Steps:
1. L1 analyst to review alert and determine false positive status
2. If legitimate, escalate to L2 for deep analysis
3. Follow incident response playbook
4. Update ticket with findings

Categories: Security, Incident Response, MITRE ATT&CK

Attachments:
- SOAR Workflow JSON
- Investigation Checklist
- MITRE ATT&CK Mapping Report
"""
    return template

def display_tab_previews():
    """Display preview content for tabs when no analysis has been run"""
    
    # Tab 2 Preview
    def show_incident_response_preview():
        st.header("📋 Incident Response Plan")
        st.info("👆 **Run analysis first to generate a comprehensive incident response plan**")
        
        st.subheader("🔍 SOC L1 Investigation Steps")
        st.markdown("""
        **What L1 analysts will receive:**
        - ✅ Initial triage procedures
        - ✅ Basic analysis commands
        - ✅ Evidence collection steps
        - ✅ Clear escalation criteria
        """)
        
        with st.expander("🔍 Example L1 Investigation Step"):
            st.markdown("""
            **Step:** Verify PowerShell execution and command line analysis
            
            **Commands to run:**
            ```bash
            Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Message -like "*powershell*"}
            Get-Process powershell | Select-Object Id,ProcessName,StartTime,Path
            ```
            
            **Expected Outcome:** Identify suspicious PowerShell processes with encoded commands
            
            **Escalation Criteria:** If encoded/obfuscated commands are found or unknown processes detected
            """)
        
        st.subheader("🔬 SOC L2 Investigation Steps")
        st.markdown("""
        **What L2 analysts will receive:**
        - 🔍 Deep analysis procedures
        - 🔍 Advanced threat hunting queries
        - 🔍 Forensic analysis steps
        - 🔍 Technical investigation guidance
        """)
        
        with st.expander("🔬 Example L2 Investigation Step"):
            st.markdown("""
            **Step:** PowerShell command decoding and malware analysis
            
            **Commands to run:**
            ```powershell
            # Decode base64 PowerShell commands
            [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encodedCommand))
            
            # Check for process injection indicators
            Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=8}
            ```
            
            **Expected Outcome:** Decoded malicious payload and injection evidence
            
            **Escalation Criteria:** Confirmed malware or advanced persistent threat indicators
            """)
        
        st.subheader("👥 Resolver Team Recommendations")
        st.markdown("""
        **Teams that will receive specific actions:**
        - 🔥 **Firewall Team** - Block malicious IPs and domains
        - 🔐 **Identity Team** - Reset compromised accounts
        - 🎫 **Service Desk** - User notifications and remediation
        - 🌐 **Network Team** - Isolate affected systems
        """)
        
        col1, col2 = st.columns(2)
        with col1:
            st.info("🔴 **High Priority Actions**\nImmediate containment (0-15 min)")
        with col2:
            st.info("🟡 **Medium Priority Actions**\nInvestigation support (15-60 min)")
    
    # Tab 3 Preview
    def show_soar_workflow_preview():
        st.header("🔄 SOAR Workflow")
        st.info("👆 **Run analysis first to generate end-to-end SOAR automation workflow**")
        
        st.subheader("🤖 What the SOAR Workflow Includes:")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            **🔄 Automated Steps:**
            - Alert ingestion and enrichment
            - Initial threat intelligence lookup
            - Automated containment actions
            - ServiceNow ticket creation
            
            **👤 Manual Steps:**
            - L1 analyst review and triage
            - False positive assessment
            - Evidence collection oversight
            - Final case closure
            """)
        
        with col2:
            st.markdown("""
            **🤔 Decision Points:**
            - False positive determination
            - Escalation to L2 teams
            - Resolver team activation
            - Case closure authorization
            
            **🎫 Integrations:**
            - ServiceNow ITSM tickets
            - SIEM alert management
            - Threat intelligence platforms
            - Security tool orchestration
            """)
        
        st.subheader("📊 Example Workflow Preview")
        
        # Mock workflow steps for preview
        workflow_preview = [
            {"step": "STEP_001", "name": "Alert Ingestion", "type": "automated", "team": "SIEM Platform"},
            {"step": "STEP_002", "name": "Threat Enrichment", "type": "automated", "team": "SOAR Platform"},
            {"step": "STEP_003", "name": "L1 Analyst Review", "type": "manual", "team": "SOC L1"},
            {"step": "STEP_004", "name": "False Positive Check", "type": "decision", "team": "SOC L1"},
            {"step": "STEP_005", "name": "ServiceNow Ticket Creation", "type": "automated", "team": "ITSM Platform"},
            {"step": "STEP_006", "name": "Automated Containment", "type": "automated", "team": "Security Tools"},
            {"step": "STEP_007", "name": "Case Closure", "type": "manual", "team": "SOC L1"}
        ]
        
        for i, step in enumerate(workflow_preview):
            type_emoji = {"automated": "🤖", "manual": "👤", "decision": "🤔"}.get(step["type"], "📋")
            
            col1, col2, col3 = st.columns([2, 1, 1])
            with col1:
                st.write(f"{type_emoji} **{step['step']}**: {step['name']}")
            with col2:
                st.write(f"_{step['type'].title()}_")
            with col3:
                st.write(f"_{step['team']}_")
            
            if i < len(workflow_preview) - 1:
                st.write("⬇️")
        
        st.subheader("📤 Export Options Available:")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("""
            **📊 JSON Export**
            - Machine-readable workflow
            - SOAR platform integration
            - API consumption ready
            """)
        
        with col2:
            st.markdown("""
            **📋 Task Checklist**
            - Human-readable format
            - Step-by-step procedures
            - Markdown format
            """)
        
        with col3:
            st.markdown("""
            **🎫 ServiceNow Template**
            - ITSM-ready ticket format
            - Pre-filled incident details
            - Assignment group mapping
            """)
    
    return show_incident_response_preview, show_soar_workflow_preview

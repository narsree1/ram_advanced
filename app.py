"""
Cybersecurity Response Platform - Single File Version
A comprehensive platform for SIEM rule analysis, incident response planning,
and SOAR workflow automation using Claude 3.5 Haiku.
"""
import streamlit as st
import anthropic
import json
import requests
import time
import re
from typing import Dict, List, Any
from dataclasses import dataclass

# Configure page
st.set_page_config(
    page_title="Cybersecurity Response Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Data Models
@dataclass
class TechniqueResult:
    """MITRE ATT&CK technique result with confidence scoring"""
    id: str
    name: str
    description: str
    confidence: float
    reasoning: str

@dataclass
class SOARWorkflowStep:
    """SOAR workflow step definition"""
    step_id: str
    name: str
    type: str  # automated, manual, decision
    description: str
    responsible_team: str
    inputs: List[str]
    outputs: List[str]
    next_steps: List[str]

# Core Platform Class
class CybersecurityResponsePlatform:
    def __init__(self, api_key: str, model_name: str = "claude-3-5-haiku-20241022"):
        """Initialize platform with Claude API"""
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model_name = model_name
        
        # Test the API connection
        try:
            test_response = self.client.messages.create(
                model=model_name,
                max_tokens=10,
                messages=[{"role": "user", "content": "Test"}]
            )
        except Exception as e:
            st.error(f"Failed to connect to Claude API: {str(e)}")
            st.stop()
    
    def _call_claude(self, prompt: str, max_tokens: int = 2048, temperature: float = 0.1) -> str:
        """Helper method to call Claude API with consistent parameters"""
        try:
            response = self.client.messages.create(
                model=self.model_name,
                max_tokens=max_tokens,
                temperature=temperature,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text
        except Exception as e:
            st.error(f"Error calling Claude API: {str(e)}")
            return ""

    def extract_iocs(self, siem_rule: str) -> Dict[str, List[str]]:
        """Step 1: Extract IoCs from SIEM rule"""
        prompt = f"""You are a cybersecurity specialist analyzing SIEM rules.

Your task is to identify and extract all Indicators of Compromise (IoCs) from the provided SIEM rule. Extract types like processes, files, IP addresses, registry keys, log sources, event codes, network ports, domains.

Return results ONLY as a valid JSON dictionary where keys are IoC types and values are lists of specific IoC details.

Example format: {{"processes": ["process1.exe"], "files": ["file1.txt"], "registry_keys": ["HKEY_LOCAL_MACHINE\\Software\\..."]}}

SIEM Rule to analyze:
{siem_rule}

Return only the JSON dictionary, no other text."""
        
        try:
            response_text = self._call_claude(prompt, max_tokens=1024, temperature=0.1)
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            return {}
        except Exception as e:
            st.error(f"Error extracting IoCs: {str(e)}")
            return {}

    def search_web_context(self, query: str) -> str:
        """Simple web search using DuckDuckGo Instant Answer API"""
        try:
            url = f"https://api.duckduckgo.com/?q={query}&format=json&no_html=1&skip_disambig=1"
            response = requests.get(url, timeout=5)
            data = response.json()
            
            context = ""
            if data.get('Abstract'):
                context += f"Abstract: {data['Abstract']} "
            if data.get('Definition'):
                context += f"Definition: {data['Definition']} "
            
            return context if context else f"General cybersecurity context for: {query}"
        except:
            return f"Cybersecurity indicator: {query}"

    def retrieve_contextual_info(self, iocs_dict: Dict[str, List[str]]) -> Dict[str, str]:
        """Step 2: Retrieve contextual information for IoCs"""
        context_info = {}
        delay = 0.2 if "haiku" in self.model_name.lower() else 0.3
        
        for ioc_type, ioc_values in iocs_dict.items():
            for ioc_value in ioc_values[:3]:
                search_query = f"cybersecurity {ioc_value} malware analysis threat"
                context = self.search_web_context(search_query)
                context_info[ioc_value] = context
                time.sleep(delay)
        
        return context_info

    def translate_to_natural_language(self, siem_rule: str, iocs_dict: Dict, context_info: Dict) -> str:
        """Step 3: Translate SIEM rule to natural language"""
        prompt = f"""You are translating a SIEM detection rule into natural language.

Your task is to convert the provided SIEM rule into a comprehensive natural language description that explains what the rule detects and why it's important for cybersecurity.

Guidelines: 
- Include both syntactical information from the rule and semantic insights from contextual information
- Make it understandable for security analysts
- Focus on the attack behavior being detected
- Be concise but comprehensive

SIEM Rule:
{siem_rule}

Extracted IoCs:
{json.dumps(iocs_dict, indent=2)}

Contextual Information:
{json.dumps(context_info, indent=2)}

Provide a clear, natural language explanation of what this rule detects:"""
        
        try:
            response_text = self._call_claude(prompt, max_tokens=1024, temperature=0.2)
            return response_text
        except Exception as e:
            st.error(f"Error in translation: {str(e)}")
            return f"Detection rule for monitoring: {str(iocs_dict)}"

    def identify_siem_platform(self, siem_rule: str) -> str:
        """Identify the SIEM platform from the rule syntax"""
        rule_lower = siem_rule.lower()
        
        # SIEM platform detection patterns
        siem_patterns = {
            "Splunk": ["index=", "sourcetype=", "| search", "| stats", "| eval", "| where"],
            "Microsoft Sentinel": ["securityevent", "signinlogs", "auditlogs", "| where", "| summarize", "kusto"],
            "Google Chronicle": ["metadata.event_type", "principal.hostname", "target.hostname", "udm."],
            "IBM QRadar": ["select", "from events", "where", "group by", "order by", "last"],
            "Elastic (ELK)": ['"query":', '"bool":', '"must":', '"range":', '"term":', '"match":'],
            "Sumo Logic": ["_source=", "_sourcecategory=", "| parse", "| timeslice", "| count"],
        }
        
        # Check for platform-specific patterns
        for platform, patterns in siem_patterns.items():
            pattern_matches = sum(1 for pattern in patterns if pattern in rule_lower)
            if pattern_matches >= 2:  # Require at least 2 matching patterns
                return platform
        
        return "Generic SIEM"

    def recommend_probable_techniques(self, rule_description: str, k: int = 11) -> List[Dict]:
        """Step 5: Recommend probable MITRE ATT&CK techniques"""
        prompt = f"""You are a cybersecurity expert mapping SIEM rules to MITRE ATT&CK techniques.

Your task is to recommend the top {k} most probable MITRE ATT&CK techniques or sub-techniques that match this detection rule. Focus on what attack behaviors this rule would detect.

Guidelines: 
- Return results as a JSON array of objects
- Each object should have: "id", "name", "description"
- Use real MITRE ATT&CK technique IDs (like T1055, T1003.001, etc.)
- Prioritize techniques that match the specific behaviors described

Rule Description:
{rule_description}

Return only the JSON array, no other text:"""
        
        try:
            response_text = self._call_claude(prompt, max_tokens=2048, temperature=0.1)
            json_match = re.search(r'\[.*\]', response_text, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            return []
        except Exception as e:
            st.error(f"Error recommending techniques: {str(e)}")
            return []

    def extract_relevant_techniques(self, rule_description: str, probable_techniques: List[Dict], 
                                  confidence_threshold: float = 0.7) -> List[TechniqueResult]:
        """Step 6: Extract most relevant techniques with confidence scoring"""
        relevant_techniques = []
        
        for technique in probable_techniques:
            prompt = f"""You are comparing a SIEM rule description with a MITRE ATT&CK technique for relevance.

Your task is to analyze how well the SIEM rule matches the attack technique. Provide a confidence score (0.0 to 1.0) and reasoning.

Scoring Guidelines: 
- Score 0.9-1.0: Perfect match
- Score 0.7-0.9: Good match
- Score 0.5-0.7: Moderate match
- Score 0.0-0.5: Poor match

Rule Description:
{rule_description}

MITRE ATT&CK Technique:
- ID: {technique.get('id', 'Unknown')}
- Name: {technique.get('name', 'Unknown')}
- Description: {technique.get('description', 'No description')}

Respond in this exact format:
CONFIDENCE: [score between 0.0 and 1.0]
REASONING: [your detailed reasoning for the score]"""
            
            try:
                response_text = self._call_claude(prompt, max_tokens=512, temperature=0.1)
                
                confidence_match = re.search(r'CONFIDENCE:\s*([0-9.]+)', response_text)
                confidence = float(confidence_match.group(1)) if confidence_match else 0.5
                
                reasoning_match = re.search(r'REASONING:\s*(.*)', response_text, re.DOTALL)
                reasoning = reasoning_match.group(1).strip() if reasoning_match else "No reasoning provided"
                
                if confidence >= confidence_threshold:
                    relevant_techniques.append(TechniqueResult(
                        id=technique.get('id', 'Unknown'),
                        name=technique.get('name', 'Unknown'),
                        description=technique.get('description', 'No description'),
                        confidence=confidence,
                        reasoning=reasoning
                    ))
                
            except Exception as e:
                st.warning(f"Error processing technique {technique.get('id', 'Unknown')}: {str(e)}")
                continue
        
        relevant_techniques.sort(key=lambda x: x.confidence, reverse=True)
        return relevant_techniques

    def identify_data_source(self, rule_description: str) -> str:
        """Step 4: Identify MITRE ATT&CK data source"""
        data_sources = {
            "process": "Command: Command Execution",
            "registry": "Windows Registry: Windows Registry Key Modification",
            "file": "File: File Creation",
            "network": "Network Traffic: Network Traffic Flow",
            "endpoint": "Process: Process Creation",
            "authentication": "Logon Session: Logon Session Creation",
            "service": "Service: Service Creation"
        }
        
        rule_lower = rule_description.lower()
        for keyword, data_source in data_sources.items():
            if keyword in rule_lower:
                return data_source
        
        return "Process: Process Creation"

    def generate_incident_response_plan(self, rule_description: str, mitre_techniques: List[TechniqueResult], siem_rule: str) -> Dict[str, Any]:
        """Generate comprehensive incident response plan"""
        siem_platform = self.identify_siem_platform(siem_rule)
        
        techniques_summary = "\n".join([
            f"- {t.id}: {t.name} (Confidence: {t.confidence:.2f})"
            for t in mitre_techniques[:5]
        ])
        
        prompt = f"""You are a senior SOC analyst creating platform-specific investigation procedures.

SIEM Platform Detected: {siem_platform}
Rule Description: {rule_description}
MITRE ATT&CK Techniques: {techniques_summary}

Create detailed investigation steps using the detected SIEM platform ({siem_platform}).

Format as JSON:
{{
  "siem_platform": "{siem_platform}",
  "l1_steps": [
    {{
      "step": "Step description",
      "expected_outcome": "What L1 should find",
      "escalation_criteria": "When to escalate",
      "timeline": "Expected time"
    }}
  ],
  "l2_steps": [
    {{
      "step": "Advanced analysis step",
      "expected_outcome": "What L2 should discover",
      "escalation_criteria": "When to escalate",
      "timeline": "Expected time"
    }}
  ],
  "resolver_recommendations": [
    {{
      "team": "Team name",
      "action": "Specific action",
      "priority": "High/Medium/Low",
      "timeline": "Expected completion"
    }}
  ]
}}

Return only the JSON object:"""
        
        try:
            response_text = self._call_claude(prompt, max_tokens=4096, temperature=0.2)
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            return {}
        except Exception as e:
            st.error(f"Error generating incident response plan: {str(e)}")
            return {}

    def generate_soar_workflow(self, rule_description: str, mitre_techniques: List[TechniqueResult]) -> List[SOARWorkflowStep]:
        """Generate SOAR workflow from alert trigger to case closure"""
        techniques_summary = "\n".join([
            f"- {t.id}: {t.name}"
            for t in mitre_techniques[:3]
        ])
        
        prompt = f"""You are a SOAR architect designing an automated workflow for incident response.

Create a complete SOAR workflow from alert trigger to case closure.

SIEM Rule: {rule_description}
Key Techniques: {techniques_summary}

Return as JSON array of workflow steps:
[
  {{
    "step_id": "STEP_001",
    "name": "Alert Ingestion", 
    "type": "automated",
    "description": "Description of the step",
    "responsible_team": "SIEM/SOAR Platform",
    "inputs": ["alert_data"],
    "outputs": ["enriched_alert"],
    "next_steps": ["STEP_002"]
  }}
]

Return only the JSON array:"""
        
        try:
            response_text = self._call_claude(prompt, max_tokens=4096, temperature=0.2)
            json_match = re.search(r'\[.*\]', response_text, re.DOTALL)
            if json_match:
                workflow_data = json.loads(json_match.group())
                return [
                    SOARWorkflowStep(
                        step_id=step.get('step_id', ''),
                        name=step.get('name', ''),
                        type=step.get('type', ''),
                        description=step.get('description', ''),
                        responsible_team=step.get('responsible_team', ''),
                        inputs=step.get('inputs', []),
                        outputs=step.get('outputs', []),
                        next_steps=step.get('next_steps', [])
                    )
                    for step in workflow_data
                ]
            return []
        except Exception as e:
            st.error(f"Error generating SOAR workflow: {str(e)}")
            return []

    def run_complete_analysis(self, siem_rule: str, confidence_threshold: float = 0.7) -> Dict[str, Any]:
        """Run complete analysis pipeline"""
        results = {}
        
        try:
            # MITRE mapping
            iocs = self.extract_iocs(siem_rule)
            context_info = self.retrieve_contextual_info(iocs)
            rule_description = self.translate_to_natural_language(siem_rule, iocs, context_info)
            data_source = self.identify_data_source(rule_description)
            probable_techniques = self.recommend_probable_techniques(rule_description)
            relevant_techniques = self.extract_relevant_techniques(rule_description, probable_techniques, confidence_threshold)
            
            # Incident response plan
            incident_plan = self.generate_incident_response_plan(rule_description, relevant_techniques, siem_rule)
            
            # SOAR workflow
            soar_workflow = self.generate_soar_workflow(rule_description, relevant_techniques)
            
            results = {
                'rule_description': rule_description,
                'iocs': iocs,
                'context_info': context_info,
                'data_source': data_source,
                'relevant_techniques': relevant_techniques,
                'incident_plan': incident_plan,
                'soar_workflow': soar_workflow,
                'siem_platform': incident_plan.get('siem_platform', 'Unknown')
            }
            
            return results
            
        except Exception as e:
            st.error(f"Analysis failed: {str(e)}")
            return results

# Display Functions
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

def display_rule_analysis_page(api_key, selected_model, confidence_threshold):
    """Display the rule analysis input page"""
    st.title("📝 SIEM Rule Analysis")
    st.markdown("**Enter your SIEM rule to begin comprehensive analysis**")
    
    # Example rules
    example_rules = {
        "Splunk - Suspicious PowerShell": """index=main sourcetype="WinEventLog:Security" EventCode=4688 | search process_name="*powershell.exe*" command_line="*-EncodedCommand*" | stats count by host, user, process_name, command_line""",
        "Microsoft Sentinel - Suspicious Login": """SecurityEvent | where EventID == 4624 | where LogonType == 10 | summarize count() by Account, IpAddress | where count_ > 10""",
        "Elastic (ELK) - Network Connection": """{"query": {"bool": {"must": [{"term": {"event_type": "network"}}, {"range": {"destination_port": {"gte": 4444, "lte": 4445}}}]}}}""",
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
                status_text.text("Step 1/4: Extracting IoCs...")
                progress_bar.progress(25)
                
                results = platform.run_complete_analysis(siem_rule, confidence_threshold)
                
                progress_bar.progress(50)
                status_text.text("Step 2/4: Mapping to MITRE ATT&CK...")
                time.sleep(0.5)
                
                progress_bar.progress(75)
                status_text.text("Step 3/4: Generating response plan...")
                time.sleep(0.5)
                
                progress_bar.progress(100)
                status_text.text("Step 4/4: Creating workflow...")
                time.sleep(0.5)
                
                if results:
                    st.session_state['analysis_results'] = results
                    status_text.text("✅ Analysis complete!")
                    st.success("🎉 Analysis completed successfully!")
                    st.balloons()
                else:
                    st.error("Analysis failed. Please try again.")
                
            except Exception as e:
                st.error(f"Analysis failed: {str(e)}")

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
            st.warning("No relevant techniques found.")
    
    with col2:
        st.subheader("📊 Analysis Summary")
        
        if results['relevant_techniques']:
            st.metric("Techniques Found", len(results['relevant_techniques']))
            avg_confidence = sum(t.confidence for t in results['relevant_techniques']) / len(results['relevant_techniques'])
            st.metric("Avg Confidence", f"{avg_confidence:.2f}")
        
        st.subheader("🔍 Data Source")
        st.info(f"**{results['data_source']}**")
        
        with st.expander("🔍 Extracted IoCs"):
            st.json(results['iocs'])

def display_incident_response_plan(results):
    """Display incident response plan"""
    st.header("📋 Incident Response Plan")
    
    if not results.get('incident_plan'):
        st.warning("No incident response plan generated.")
        return
    
    plan = results['incident_plan']
    top_technique = results['relevant_techniques'][0] if results['relevant_techniques'] else None
    
    # Generate incident title
    incident_title = f"Security Alert - {top_technique.name if top_technique else 'Suspicious Activity'} Detected"
    
    st.title(f"📋 {incident_title}")
    
    # MITRE ATT&CK Classification
    st.subheader("🎯 MITRE ATT&CK Classification")
    
    if top_technique:
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("**Category**")
            st.info("Suspicious System Activity")
        
        with col2:
            st.markdown("**MITRE Tactic**")
            st.info("Execution")
        
        with col3:
            st.markdown("**MITRE Technique**")
            st.info(f"{top_technique.id}")
    
    st.subheader("📝 Description")
    st.write(f"This notable will trigger when {results['rule_description'].lower()}")
    
    # SIEM Platform Detection
    siem_platform = plan.get('siem_platform', 'Generic SIEM')
    st.info(f"🔧 **Detected SIEM Platform:** {siem_platform}")
    
    st.markdown("---")
    
    # Investigation steps
    st.header("🕵️ Investigation Steps")
    
    # Step 1: Historical check
    st.subheader("📊 Step 1: Historical check")
    st.markdown("""
    - Check previous notable events related to the same indicators
    - Note any useful comments or additional information from previous incidents
    - Review historical patterns for similar attack vectors
    """)
    
    # Step 2: Duplicate check
    st.subheader("🔍 Step 2: Duplicate check and add details to Investigation")
    st.markdown("""
    - Search if there is an open incident for the same issue in ServiceNow
    - If yes, add new information to existing incident
    - Close new notable as Duplicate if appropriate
    """)
    
    # Step 3: Investigate the events
    st.subheader("🕵️ Step 3: Investigate the events")
    st.markdown("**L1 Investigation Procedures:**")
    
    if plan.get('l1_steps'):
        for i, step in enumerate(plan['l1_steps'], 1):
            with st.expander(f"L1.{i}: {step.get('step', 'Investigation Step')}", expanded=(i==1)):
                st.write(step.get('step', 'No description'))
                st.write(f"**Expected Outcome:** {step.get('expected_outcome', 'Gather evidence')}")
                st.write(f"**Timeline:** {step.get('timeline', '15-20 minutes')}")
    
    if plan.get('l2_steps'):
        st.markdown("**L2 Deep Analysis:**")
        for i, step in enumerate(plan['l2_steps'], 1):
            with st.expander(f"L2.{i}: {step.get('step', 'Deep Analysis Step')}"):
                st.write(step.get('step', 'No description'))
                st.write(f"**Expected Outcome:** {step.get('expected_outcome', 'Comprehensive analysis')}")
    
    # Step 4: Recommendations
    st.subheader("💡 Step 4: Recommendations")
    
    if plan.get('resolver_recommendations'):
        for rec in plan['resolver_recommendations']:
            priority_emoji = {'High': '🔴', 'Medium': '🟡', 'Low': '🟢'}.get(rec.get('priority', 'Medium'), '🟡')
            st.markdown(f"**{priority_emoji} {rec.get('team', 'Security Team')}:**")
            st.markdown(f"- {rec.get('action', 'Take appropriate action')}")
            st.markdown(f"- Priority: {rec.get('priority', 'Medium')} | Timeline: {rec.get('timeline', 'ASAP')}")

def display_soar_workflow(results):
    """Display SOAR workflow"""
    st.header("🔄 SOAR Workflow")
    
    if not results.get('soar_workflow'):
        st.warning("No SOAR workflow generated.")
        return
    
    workflow = results['soar_workflow']
    
    # Workflow overview
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
    
    # Generate workflow HTML
    workflow_html = f"""
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 10px; color: white; text-align: center;">
        <h3>🔄 SOAR Automation Workflow</h3>
        <p>End-to-End Incident Response Automation</p>
    </div>
    """
    
    st.markdown(workflow_html, unsafe_allow_html=True)
    
    # Detailed workflow steps
    st.subheader("📋 Detailed Workflow Steps")
    
    for i, step in enumerate(workflow):
        type_emoji = {"automated": "🤖", "manual": "👤", "decision": "🤔"}.get(step.type, "📋")
        
        with st.expander(f"{type_emoji} {step.step_id}: {step.name}", expanded=(i<3)):
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
    
    # Export options
    st.subheader("📤 Export Options")
    
    col1, col2 = st.columns(2)
    
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
        checklist = "# SOAR Workflow Checklist\n\n"
        for step in workflow:
            type_emoji = {"automated": "🤖", "manual": "👤", "decision": "🤔"}.get(step.type, "📋")
            checklist += f"- [ ] **{step.step_id}** - {step.name} {type_emoji}\n"
            checklist += f"  - **Team:** {step.responsible_team}\n\n"
        
        st.download_button(
            label="📋 Download Checklist",
            data=checklist,
            file_name="workflow_checklist.md",
            mime="text/markdown",
            use_container_width=True
        )

# Main Application
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
            
            if st.button("🔄 Clear Results", use_container_width=True):
                del st.session_state['analysis_results']
                st.rerun()
        else:
            st.info("⏳ Ready for Analysis")

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
            
    elif page == "📋 Incident Response":
        if 'analysis_results' in st.session_state:
            display_incident_response_plan(st.session_state['analysis_results'])
        else:
            st.header("📋 Incident Response Plan")
            st.info("👈 **Go to 'Rule Analysis' to analyze a SIEM rule first**")
            
    elif page == "🔄 SOAR Workflow":
        if 'analysis_results' in st.session_state:
            display_soar_workflow(st.session_state['analysis_results'])
        else:
            st.header("🔄 SOAR Workflow")
            st.info("👈 **Go to 'Rule Analysis' to analyze a SIEM rule first**")

    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center'>
        <p>Built with ❤️ using Streamlit and Claude API</p>
        <p><a href='https://console.anthropic.com/'>🔑 Get Claude API Key</a></p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()

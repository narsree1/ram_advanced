"""
Modern Cybersecurity Response Platform
A streamlined platform for SIEM rule analysis, MITRE mapping, incident response, and SOAR workflows.
"""
import streamlit as st
import anthropic
import json
import requests
import time
import re
import graphviz
from typing import Dict, List, Any
from dataclasses import dataclass

# Configure page
st.set_page_config(
    page_title="Cybersecurity Response Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS for modern look
st.markdown("""
<style>
.main-header {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    padding: 2rem;
    border-radius: 15px;
    color: white;
    text-align: center;
    margin-bottom: 2rem;
    box-shadow: 0 8px 32px rgba(0,0,0,0.1);
}

.modern-card {
    background: rgba(255, 255, 255, 0.05);
    backdrop-filter: blur(10px);
    border-radius: 15px;
    padding: 1.5rem;
    border: 1px solid rgba(255, 255, 255, 0.1);
    margin: 1rem 0;
}

.technique-card {
    background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
    color: white;
    padding: 1rem;
    border-radius: 10px;
    margin: 0.5rem 0;
    box-shadow: 0 4px 15px rgba(0,0,0,0.1);
}

.step-card {
    background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
    color: white;
    padding: 1.2rem;
    border-radius: 12px;
    margin: 1rem 0;
    box-shadow: 0 6px 20px rgba(0,0,0,0.1);
}

.recommendation-card {
    background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
    color: white;
    padding: 1rem;
    border-radius: 10px;
    margin: 0.5rem 0;
    box-shadow: 0 4px 15px rgba(0,0,0,0.1);
}

.settings-button {
    position: fixed;
    top: 20px;
    right: 20px;
    z-index: 1000;
    background: #667eea;
    color: white;
    border: none;
    border-radius: 50%;
    width: 50px;
    height: 50px;
    cursor: pointer;
    box-shadow: 0 4px 15px rgba(0,0,0,0.2);
}

.workflow-node {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 1rem;
    border-radius: 10px;
    text-align: center;
    margin: 0.5rem;
    box-shadow: 0 4px 15px rgba(0,0,0,0.1);
}

.workflow-arrow {
    text-align: center;
    font-size: 1.5rem;
    color: #667eea;
    margin: 0.5rem 0;
}
</style>
""", unsafe_allow_html=True)

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
    type: str
    description: str
    responsible_team: str
    inputs: List[str]
    outputs: List[str]
    next_steps: List[str]

class CybersecurityResponsePlatform:
    def __init__(self, api_key: str, model_name: str = "claude-3-5-haiku-20241022"):
        """Initialize platform with Claude API - compatible with all Claude versions"""
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model_name = model_name
        self.model_info = get_model_info(model_name)
        
        # Test the API connection with minimal token usage
        try:
            test_response = self.client.messages.create(
                model=model_name,
                max_tokens=5,
                messages=[{"role": "user", "content": "Hi"}]
            )
            st.success(f"✅ Connected to {self.model_info.get('family', model_name)}")
        except Exception as e:
            error_msg = str(e)
            if "model" in error_msg.lower():
                st.error(f"❌ Model '{model_name}' not available. Please check the model name or your API access.")
            else:
                st.error(f"❌ Failed to connect to Claude API: {error_msg}")
            st.stop()
    
    def _call_claude(self, prompt: str, max_tokens: int = 2048, temperature: float = 0.1) -> str:
        """Enhanced Claude API call with adaptive parameters for different model versions"""
        try:
            # Adaptive max_tokens based on model capability
            adjusted_max_tokens = self._adjust_max_tokens(max_tokens)
            
            response = self.client.messages.create(
                model=self.model_name,
                max_tokens=adjusted_max_tokens,
                temperature=temperature,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text
        except Exception as e:
            error_msg = str(e)
            if "rate_limit" in error_msg.lower():
                st.warning(f"Rate limit reached for {self.model_name}. Please wait a moment and try again.")
            elif "tokens" in error_msg.lower():
                st.warning(f"Token limit exceeded. Trying with reduced parameters...")
                # Retry with smaller token limit
                try:
                    response = self.client.messages.create(
                        model=self.model_name,
                        max_tokens=min(1000, adjusted_max_tokens),
                        temperature=temperature,
                        messages=[{"role": "user", "content": prompt}]
                    )
                    return response.content[0].text
                except:
                    pass
            st.error(f"Error calling Claude API: {error_msg}")
            return ""
    
    def _adjust_max_tokens(self, requested_tokens: int) -> int:
        """Adjust max_tokens based on model capabilities"""
        # Claude 4 models typically support higher token limits
        if "claude-4" in self.model_name or "claude-sonnet-4" in self.model_name or "claude-opus-4" in self.model_name:
            return min(requested_tokens, 8192)  # Higher limit for Claude 4
        # Claude 3.5 models
        elif "3-5" in self.model_name or "3.5" in self.model_name:
            return min(requested_tokens, 4096)
        # Claude 3 models (legacy)
        elif "claude-3" in self.model_name:
            return min(requested_tokens, 4096)
        # Unknown/custom models - conservative approach
        else:
            return min(requested_tokens, 2048)
    
    def _get_optimal_delay(self) -> float:
        """Get optimal delay between API calls based on model type"""
        if "haiku" in self.model_name.lower():
            return 0.1  # Haiku is faster
        elif "sonnet" in self.model_name.lower():
            return 0.2  # Sonnet is balanced
        elif "opus" in self.model_name.lower():
            return 0.3  # Opus is more thorough
        else:
            return 0.2  # Default for unknown models

    def extract_iocs(self, siem_rule: str) -> Dict[str, List[str]]:
        """Step 1: Extract IoCs from SIEM rule with improved error handling"""
        prompt = f"""You are a cybersecurity specialist analyzing SIEM rules.

Your task is to identify and extract all Indicators of Compromise (IoCs) from the provided SIEM rule. Extract types like processes, files, IP addresses, registry keys, log sources, event codes, network ports, domains.

Return results ONLY as a valid JSON dictionary where keys are IoC types and values are lists of specific IoC details.

Example format: {{"processes": ["process1.exe"], "files": ["file1.txt"], "registry_keys": ["HKEY_LOCAL_MACHINE\\Software\\..."]}}

SIEM Rule to analyze:
{siem_rule}

Return only the JSON dictionary, no other text."""
        
        try:
            response_text = self._call_claude(prompt, max_tokens=1024, temperature=0.1)
            if not response_text:
                return {}
                
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                parsed_data = json.loads(json_match.group())
                # Ensure all values are lists
                cleaned_data = {}
                for key, value in parsed_data.items():
                    if isinstance(value, list):
                        cleaned_data[key] = value
                    elif isinstance(value, str):
                        cleaned_data[key] = [value]
                    else:
                        cleaned_data[key] = []
                return cleaned_data
            return {}
        except json.JSONDecodeError as e:
            st.warning(f"JSON parsing error in IoC extraction: {str(e)}")
            return {}
        except Exception as e:
            st.warning(f"Error extracting IoCs: {str(e)}")
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
        """Step 2: Retrieve contextual information for IoCs with adaptive delays"""
        context_info = {}
        delay = self._get_optimal_delay()
        
        # Handle case where iocs_dict might be None or empty
        if not iocs_dict:
            return context_info
            
        for ioc_type, ioc_values in iocs_dict.items():
            # Ensure ioc_values is a list and not None
            if ioc_values and isinstance(ioc_values, list):
                for ioc_value in ioc_values[:3]:
                    if ioc_value:  # Ensure ioc_value is not None or empty
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
            "Splunk": ["index=", "sourcetype=", "| search", "| stats", "| eval", "| where", "| tstats"],
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

    def recommend_probable_techniques(self, rule_description: str, k: int = 8) -> List[Dict]:
        """Step 5: Recommend probable MITRE ATT&CK techniques with improved error handling"""
        prompt = f"""You are a cybersecurity expert mapping SIEM rules to MITRE ATT&CK techniques.

Your task is to recommend the top {k} most probable MITRE ATT&CK techniques or sub-techniques that match this detection rule. Focus on what attack behaviors this rule would detect.

Guidelines: 
- Return results as a JSON array of objects
- Each object should have: "id", "name", "description", "tactic"
- Use real MITRE ATT&CK technique IDs (like T1055, T1003.001, etc.)
- Prioritize techniques that match the specific behaviors described
- Focus on the most relevant and accurate mappings

Rule Description:
{rule_description}

Return only the JSON array, no other text:"""
        
        try:
            response_text = self._call_claude(prompt, max_tokens=2048, temperature=0.1)
            if not response_text:
                return []
                
            json_match = re.search(r'\[.*\]', response_text, re.DOTALL)
            if json_match:
                parsed_data = json.loads(json_match.group())
                # Ensure we have a list of dictionaries
                if isinstance(parsed_data, list):
                    return parsed_data
                else:
                    return []
            return []
        except json.JSONDecodeError as e:
            st.warning(f"JSON parsing error in technique recommendation: {str(e)}")
            return []
        except Exception as e:
            st.warning(f"Error recommending techniques: {str(e)}")
            return []

    def extract_relevant_techniques(self, rule_description: str, probable_techniques: List[Dict], 
                                  confidence_threshold: float = 0.7) -> List[TechniqueResult]:
        """Step 6: Extract top 3 most relevant techniques with confidence scoring"""
        relevant_techniques = []
        
        for technique in probable_techniques:
            prompt = f"""You are comparing a SIEM rule description with a MITRE ATT&CK technique for relevance.

Your task is to analyze how well the SIEM rule matches the attack technique. Provide a confidence score (0.0 to 1.0) and reasoning.

Scoring Guidelines: 
- Score 0.9-1.0: Perfect match - technique directly detected by this rule
- Score 0.7-0.9: Good match - technique likely detected with some variations
- Score 0.5-0.7: Moderate match - technique partially detected
- Score 0.0-0.5: Poor match - unlikely to detect this technique

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
        
        # Sort by confidence and return only top 3 most relevant
        relevant_techniques.sort(key=lambda x: x.confidence, reverse=True)
        return relevant_techniques[:3]  # Return only top 3 most relevant techniques

    def generate_detailed_incident_response(self, rule_description: str, mitre_techniques: List[TechniqueResult], siem_rule: str) -> Dict[str, Any]:
        """Generate detailed incident response plan following the template structure"""
        siem_platform = self.identify_siem_platform(siem_rule)
        top_technique = mitre_techniques[0] if mitre_techniques and len(mitre_techniques) > 0 else None
        
        # Generate techniques summary for top 3 techniques
        if mitre_techniques:
            techniques_summary = "\n".join([
                f"- {t.id}: {t.name} (Confidence: {t.confidence:.2f})"
                for t in mitre_techniques  # Already limited to top 3 in extract_relevant_techniques
            ])
        else:
            techniques_summary = "No specific techniques identified"
        
        prompt = f"""You are a senior SOC analyst creating a detailed incident response playbook following the standard 4-step investigation procedure.

DETECTED SIEM PLATFORM: {siem_platform}
RULE DESCRIPTION: {rule_description}
TOP MITRE TECHNIQUE: {top_technique.id if top_technique else 'Unknown'} - {top_technique.name if top_technique else 'Unknown'}
RELATED TECHNIQUES: {techniques_summary}

Create a comprehensive incident response plan following this EXACT structure:

{{
  "alert_title": "Security Alert - [Technique Name] Detected",
  "mitre_classification": {{
    "category": "Category based on technique",
    "tactic": "Primary MITRE tactic",
    "technique": "{top_technique.id if top_technique else 'T1000'}"
  }},
  "description": "This notable will trigger when [specific behavior description]",
  "siem_platform": "{siem_platform}",
  "investigation_steps": {{
    "step1_historical": {{
      "title": "Historical check",
      "actions": [
        "Check previous notable events related to the same indicators",
        "Note any useful comments or additional information from previous incidents", 
        "Review historical patterns for similar attack vectors"
      ]
    }},
    "step2_duplicate": {{
      "title": "Duplicate check and add details to Investigation",
      "actions": [
        "Search if there is an open incident for the same issue in ServiceNow",
        "If yes, add new information to existing incident and close new notable as Duplicate",
        "Verify if this is part of an ongoing investigation"
      ]
    }},
    "step3_investigate": {{
      "title": "Investigate the events",
      "siem_queries": [
        "Platform-specific SIEM query 1 for {siem_platform}",
        "Platform-specific SIEM query 2 for {siem_platform}",
        "Platform-specific SIEM query 3 for {siem_platform}"
      ],
      "edr_actions": [
        "Check EDR alerts on affected hosts",
        "Run memory scan on suspicious processes",
        "Analyze process tree and parent-child relationships",
        "Check for persistence mechanisms"
      ],
      "data_collection": [
        "Source IP addresses and geolocations",
        "User accounts involved",
        "Timeline of events",
        "Affected systems and scope"
      ]
    }},
    "step4_recommendations": {{
      "title": "Recommendations",
      "immediate_actions": [
        "Immediate containment action 1",
        "Immediate containment action 2",
        "Immediate containment action 3"
      ],
      "resolver_teams": [
        {{
          "team": "Security Operations",
          "actions": ["Specific action for SOC team"],
          "priority": "High",
          "timeline": "Immediate"
        }},
        {{
          "team": "IT Infrastructure", 
          "actions": ["Specific action for IT team"],
          "priority": "Medium",
          "timeline": "Within 2 hours"
        }}
      ]
    }}
  }}
}}

Return only the JSON object with detailed, actionable steps:"""
        
        try:
            response_text = self._call_claude(prompt, max_tokens=4096, temperature=0.2)
            if not response_text:
                return {}
                
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            return {}
        except json.JSONDecodeError as e:
            st.warning(f"JSON parsing error in incident response generation: {str(e)}")
            return {}
        except Exception as e:
            st.warning(f"Error generating incident response plan: {str(e)}")
            return {}

    def generate_soar_workflow(self, rule_description: str, mitre_techniques: List[TechniqueResult]) -> Dict[str, Any]:
        """Generate visual SOAR workflow with Graphviz diagram using selected Claude model"""
        # Generate techniques summary for all available techniques (already top 3)
        if mitre_techniques:
            techniques_summary = "\n".join([
                f"- {t.id}: {t.name}"
                for t in mitre_techniques  # Already limited to top 3 most relevant
            ])
        else:
            techniques_summary = "No specific techniques identified"
        
        # Use the selected model for SOAR workflow generation
        current_model = self.model_name
        
        prompt = f"""You are a SOAR architect designing a visual workflow from alert to resolution.

Create a comprehensive SOAR workflow with clear visual steps that can be displayed as a Graphviz diagram.

RULE DESCRIPTION: {rule_description}
KEY TECHNIQUES: {techniques_summary}

Return as JSON object with workflow steps and graphviz DOT notation:
{{
  "workflow_steps": [
    {{
      "step_id": "START",
      "name": "Alert Triggered", 
      "type": "automated",
      "description": "SIEM rule triggered and alert generated",
      "responsible_team": "SIEM Platform",
      "inputs": ["raw_log_data"],
      "outputs": ["structured_alert"],
      "next_steps": ["ENRICH"]
    }},
    {{
      "step_id": "ENRICH",
      "name": "Alert Enrichment",
      "type": "automated", 
      "description": "Gather additional context from threat intelligence and asset databases",
      "responsible_team": "SOAR Platform",
      "inputs": ["structured_alert"],
      "outputs": ["enriched_alert"],
      "next_steps": ["TRIAGE"]
    }},
    {{
      "step_id": "TRIAGE",
      "name": "Initial Triage",
      "type": "manual",
      "description": "L1 analyst reviews alert and determines severity",
      "responsible_team": "L1 SOC Analyst", 
      "inputs": ["enriched_alert"],
      "outputs": ["triage_decision"],
      "next_steps": ["INVESTIGATE"]
    }},
    {{
      "step_id": "INVESTIGATE",
      "name": "Deep Investigation",
      "type": "manual",
      "description": "L2 analyst performs detailed investigation using SIEM and EDR",
      "responsible_team": "L2 SOC Analyst",
      "inputs": ["triage_decision"],
      "outputs": ["investigation_results"],
      "next_steps": ["CONTAIN"]
    }},
    {{
      "step_id": "CONTAIN",
      "name": "Containment Decision",
      "type": "decision",
      "description": "Determine if containment is needed based on investigation",
      "responsible_team": "SOC Manager",
      "inputs": ["investigation_results"],
      "outputs": ["containment_decision"],
      "next_steps": ["RESOLVE"]
    }},
    {{
      "step_id": "RESOLVE",
      "name": "Resolution & Remediation",
      "type": "manual",
      "description": "Complete remediation and document lessons learned",
      "responsible_team": "Security Team",
      "inputs": ["containment_decision"],
      "outputs": ["incident_report"],
      "next_steps": ["CLOSE"]
    }},
    {{
      "step_id": "CLOSE",
      "name": "Case Closure",
      "type": "automated",
      "description": "Close ticket in ITSM and update metrics",
      "responsible_team": "SOAR Platform",
      "inputs": ["incident_report"],
      "outputs": ["closed_case"],
      "next_steps": []
    }}
  ],
  "graphviz_dot": "digraph SOAR {{\\n  rankdir=TD;\\n  node [shape=box, style=filled];\\n  \\n  START [label=\\"Alert Triggered\\\\n(Automated)\\", fillcolor=lightblue];\\n  ENRICH [label=\\"Alert Enrichment\\\\n(Automated)\\", fillcolor=lightblue];\\n  TRIAGE [label=\\"Initial Triage\\\\n(Manual)\\", fillcolor=lightgreen];\\n  INVESTIGATE [label=\\"Deep Investigation\\\\n(Manual)\\", fillcolor=lightgreen];\\n  CONTAIN [label=\\"Containment Decision\\\\n(Decision)\\", fillcolor=yellow];\\n  RESOLVE [label=\\"Resolution\\\\n(Manual)\\", fillcolor=lightgreen];\\n  CLOSE [label=\\"Case Closure\\\\n(Automated)\\", fillcolor=lightblue];\\n  \\n  START -> ENRICH;\\n  ENRICH -> TRIAGE;\\n  TRIAGE -> INVESTIGATE;\\n  INVESTIGATE -> CONTAIN;\\n  CONTAIN -> RESOLVE;\\n  RESOLVE -> CLOSE;\\n}}"
}}

Create a similar structure but generate the actual graphviz DOT notation for the workflow with proper colors:
- Automated steps: lightblue
- Manual steps: lightgreen  
- Decision steps: yellow

Return only the JSON object:"""
        
        try:
            # Use the current model for SOAR workflow generation
            response = self.client.messages.create(
                model=current_model,
                max_tokens=self._adjust_max_tokens(4096),
                temperature=0.2,
                messages=[{"role": "user", "content": prompt}]
            )
            response_text = response.content[0].text
            
            if not response_text:
                return {'workflow_steps': [], 'graphviz_dot': ''}
            
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                workflow_data = json.loads(json_match.group())
                
                # Convert workflow steps to SOARWorkflowStep objects
                workflow_steps = []
                for step in workflow_data.get('workflow_steps', []):
                    if isinstance(step, dict):  # Ensure step is a dictionary
                        workflow_steps.append(SOARWorkflowStep(
                            step_id=step.get('step_id', ''),
                            name=step.get('name', ''),
                            type=step.get('type', ''),
                            description=step.get('description', ''),
                            responsible_team=step.get('responsible_team', ''),
                            inputs=step.get('inputs', []) if isinstance(step.get('inputs'), list) else [],
                            outputs=step.get('outputs', []) if isinstance(step.get('outputs'), list) else [],
                            next_steps=step.get('next_steps', []) if isinstance(step.get('next_steps'), list) else []
                        ))
                
                return {
                    'workflow_steps': workflow_steps,
                    'graphviz_dot': workflow_data.get('graphviz_dot', '')
                }
            return {'workflow_steps': [], 'graphviz_dot': ''}
        except json.JSONDecodeError as e:
            st.warning(f"JSON parsing error in SOAR workflow generation: {str(e)}")
            return {'workflow_steps': [], 'graphviz_dot': ''}
        except Exception as e:
            st.warning(f"Error generating SOAR workflow: {str(e)}")
            return {'workflow_steps': [], 'graphviz_dot': ''}

    def run_complete_analysis(self, siem_rule: str, confidence_threshold: float = 0.7) -> Dict[str, Any]:
        """Run complete analysis pipeline with improved error handling"""
        results = {}
        
        try:
            # Step 1: Extract IoCs
            try:
                iocs = self.extract_iocs(siem_rule)
                if not iocs:
                    iocs = {}
            except Exception as e:
                st.warning(f"IoC extraction failed: {str(e)}")
                iocs = {}
            
            # Step 2: Retrieve contextual information
            try:
                context_info = self.retrieve_contextual_info(iocs)
            except Exception as e:
                st.warning(f"Context retrieval failed: {str(e)}")
                context_info = {}
            
            # Step 3: Translate to natural language
            try:
                rule_description = self.translate_to_natural_language(siem_rule, iocs, context_info)
                if not rule_description:
                    rule_description = f"SIEM detection rule for monitoring security events: {siem_rule[:100]}..."
            except Exception as e:
                st.warning(f"Rule translation failed: {str(e)}")
                rule_description = f"SIEM detection rule for monitoring security events: {siem_rule[:100]}..."
            
            # Step 4: Recommend techniques
            try:
                probable_techniques = self.recommend_probable_techniques(rule_description)
                if not probable_techniques:
                    probable_techniques = []
            except Exception as e:
                st.warning(f"Technique recommendation failed: {str(e)}")
                probable_techniques = []
            
            # Step 5: Extract relevant techniques
            try:
                relevant_techniques = self.extract_relevant_techniques(rule_description, probable_techniques, confidence_threshold)
            except Exception as e:
                st.warning(f"Technique extraction failed: {str(e)}")
                relevant_techniques = []
            
            # Step 6: Generate incident response plan
            try:
                incident_plan = self.generate_detailed_incident_response(rule_description, relevant_techniques, siem_rule)
                if not incident_plan:
                    incident_plan = {}
            except Exception as e:
                st.warning(f"Incident response generation failed: {str(e)}")
                incident_plan = {}
            
            # Step 7: Generate SOAR workflow
            try:
                soar_data = self.generate_soar_workflow(rule_description, relevant_techniques)
                if not soar_data:
                    soar_data = {'workflow_steps': [], 'graphviz_dot': ''}
            except Exception as e:
                st.warning(f"SOAR workflow generation failed: {str(e)}")
                soar_data = {'workflow_steps': [], 'graphviz_dot': ''}
            
            results = {
                'rule_description': rule_description,
                'iocs': iocs,
                'context_info': context_info,
                'relevant_techniques': relevant_techniques,
                'incident_plan': incident_plan,
                'soar_workflow': soar_data.get('workflow_steps', []),
                'soar_graphviz': soar_data.get('graphviz_dot', ''),
                'siem_platform': incident_plan.get('siem_platform', 'Unknown'),
                'model_used': self.model_info.get('family', self.model_name)
            }
            
            return results
            
        except Exception as e:
            st.error(f"Analysis pipeline failed: {str(e)}")
            return results

# Settings Modal
def show_settings_modal():
    """Display settings modal with comprehensive Claude model support"""
    with st.expander("⚙️ Configuration Settings", expanded=False):
        col1, col2 = st.columns(2)
        
        with col1:
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
                if api_key:
                    st.success("✅ API Key configured")
        
        with col2:
            # Comprehensive model selection with all Claude versions
            model_options = {
                # Claude 4 Models (Latest)
                "Claude 4 Sonnet (Latest)": "claude-sonnet-4-20250514",
                "Claude 4 Opus (Most Capable)": "claude-opus-4-20250514",
                
                # Claude 3.5 Models
                "Claude 3.5 Sonnet (Balanced)": "claude-3-5-sonnet-20241022",
                "Claude 3.5 Haiku (Fast)": "claude-3-5-haiku-20241022",
                
                # Claude 3 Models (Legacy Support)
                "Claude 3 Opus (Legacy)": "claude-3-opus-20240229",
                "Claude 3 Sonnet (Legacy)": "claude-3-sonnet-20240229",
                "Claude 3 Haiku (Legacy)": "claude-3-haiku-20240307",
                
                # Custom Model Entry
                "Custom Model": "custom"
            }
            
            selected_model_display = st.selectbox(
                "🤖 Claude Model Selection",
                options=list(model_options.keys()),
                index=0,  # Default to Claude 4 Sonnet
                help="Choose your Claude model. Newer models offer better performance."
            )
            
            # Handle custom model input
            if selected_model_display == "Custom Model":
                selected_model = st.text_input(
                    "Enter Model Name:",
                    placeholder="claude-sonnet-4-20250514",
                    help="Enter the exact model name from Anthropic's API documentation"
                )
                if not selected_model:
                    selected_model = "claude-3-5-haiku-20241022"  # Fallback
            else:
                selected_model = model_options[selected_model_display]
            
            # Model info display
            model_info = get_model_info(selected_model)
            if model_info:
                st.info(f"**{model_info['family']}** | {model_info['description']}")
            
            # Model performance info
            if selected_model_display != "Custom Model":
                model_category = model_info.get('category', 'unknown')
                if model_category == 'fast':
                    st.success("⚡ **Fast Analysis** - Optimized for speed and efficiency")
                elif model_category == 'balanced':
                    st.info("⚖️ **Balanced Performance** - Great mix of speed and accuracy")
                elif model_category == 'premium':
                    st.warning("🎯 **Premium Analysis** - Highest accuracy, may take longer")
                elif model_category == 'legacy':
                    st.info("📚 **Legacy Model** - Stable but may have limited features")
            
            confidence_threshold = st.slider(
                "Confidence Threshold",
                min_value=0.1,
                max_value=1.0,
                value=0.7,
                step=0.1,
                help="Minimum confidence score for technique relevance"
            )
        
        return api_key, selected_model, confidence_threshold

def get_model_info(model_name: str) -> dict:
    """Get information about the selected Claude model"""
    model_info_map = {
        # Claude 4 Models
        "claude-sonnet-4-20250514": {
            "family": "Claude 4 Sonnet",
            "description": "Latest balanced model with enhanced reasoning",
            "category": "balanced"
        },
        "claude-opus-4-20250514": {
            "family": "Claude 4 Opus", 
            "description": "Most capable model for complex analysis",
            "category": "premium"
        },
        
        # Claude 3.5 Models
        "claude-3-5-sonnet-20241022": {
            "family": "Claude 3.5 Sonnet",
            "description": "Balanced performance and speed",
            "category": "balanced"
        },
        "claude-3-5-haiku-20241022": {
            "family": "Claude 3.5 Haiku",
            "description": "Fast and efficient for structured tasks",
            "category": "fast"
        },
        
        # Claude 3 Models
        "claude-3-opus-20240229": {
            "family": "Claude 3 Opus",
            "description": "Legacy high-capability model",
            "category": "legacy"
        },
        "claude-3-sonnet-20240229": {
            "family": "Claude 3 Sonnet",
            "description": "Legacy balanced model",
            "category": "legacy"
        },
        "claude-3-haiku-20240307": {
            "family": "Claude 3 Haiku",
            "description": "Legacy fast model",
            "category": "legacy"
        }
    }
    
    return model_info_map.get(model_name, {
        "family": "Custom Model",
        "description": "User-defined model",
        "category": "custom"
    })

# Main Pages
def display_mitre_mapping_page():
    """Modern MITRE mapping page"""
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ Cybersecurity Response Platform</h1>
        <p>Advanced SIEM Rule Analysis & MITRE ATT&CK Mapping</p>
        <p style="font-size: 0.9em; opacity: 0.8;">✨ Compatible with all Claude models including Claude 4 Sonnet & Opus</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Settings
    api_key, selected_model, confidence_threshold = show_settings_modal()
    
    if not api_key:
        st.error("⚠️ Please configure your Claude API key in the settings above")
        return
    
    # SIEM Rule Input Section
    st.markdown("### 🔍 SIEM Rule Analysis")
    
    # Example rules with modern styling
    example_rules = {
        "Splunk - Suspicious PowerShell": """index=main sourcetype="WinEventLog:Security" EventCode=4688 | search process_name="*powershell.exe*" command_line="*-EncodedCommand*" | stats count by host, user, process_name, command_line""",
        "Microsoft Sentinel - Suspicious Login": """SecurityEvent | where EventID == 4624 | where LogonType == 10 | summarize count() by Account, IpAddress | where count_ > 10""",
        "Elastic (ELK) - Network Connection": """{"query": {"bool": {"must": [{"term": {"event_type": "network"}}, {"range": {"destination_port": {"gte": 4444, "lte": 4445}}}]}}}""",
    }
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        selected_example = st.selectbox("📋 Choose Example or Enter Custom:", ["Custom"] + list(example_rules.keys()))
        
        if selected_example != "Custom":
            siem_rule = st.text_area(
                "SIEM Rule:", 
                value=example_rules[selected_example],
                height=120,
                help="SIEM rule in any format"
            )
        else:
            siem_rule = st.text_area(
                "SIEM Rule:", 
                height=120,
                placeholder="Enter your SIEM rule here...",
                help="SIEM rule in any format"
            )
    
    with col2:
        analyze_button = st.button("🚀 Analyze Rule", type="primary", use_container_width=True)
        
        if st.session_state.get('analysis_results'):
            st.success("✅ Analysis Complete")
            if st.button("🔄 Clear Results", use_container_width=True):
                del st.session_state['analysis_results']
                st.rerun()
        else:
            model_info = get_model_info(selected_model)
            st.info(f"🤖 **Ready with:** {model_info.get('family', selected_model)}")
            if confidence_threshold != 0.7:
                st.info(f"🎯 **Threshold:** {confidence_threshold}")
    
    # Process analysis
    if analyze_button and siem_rule.strip():
        with st.spinner("🔍 Analyzing SIEM rule..."):
            platform = CybersecurityResponsePlatform(api_key, selected_model)
            
            # Progress tracking
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            try:
                status_text.text("🔍 Extracting IoCs and mapping to MITRE ATT&CK...")
                progress_bar.progress(25)
                
                results = platform.run_complete_analysis(siem_rule, confidence_threshold)
                
                progress_bar.progress(50)
                status_text.text("🎯 Identifying attack techniques...")
                time.sleep(0.5)
                
                progress_bar.progress(75)
                status_text.text("📋 Generating response procedures...")
                time.sleep(0.5)
                
                progress_bar.progress(100)
                status_text.text("✅ Analysis complete!")
                time.sleep(0.5)
                
                if results:
                    st.session_state['analysis_results'] = results
                    st.success("🎉 Analysis completed successfully!")
                    st.balloons()
                else:
                    st.error("Analysis failed. Please try again.")
                
            except Exception as e:
                st.error(f"Analysis failed: {str(e)}")
    
    # Display results
    if st.session_state.get('analysis_results'):
        results = st.session_state['analysis_results']
        
        st.markdown("---")
        
        # Rule Description
        st.markdown("### 📝 Rule Description")
        rule_desc = results.get('rule_description', 'No description available')
        st.info(rule_desc)
        
        # MITRE ATT&CK Techniques
        st.markdown("### 🎯 Top 3 Most Relevant MITRE ATT&CK Techniques")
        
        if results['relevant_techniques'] and len(results['relevant_techniques']) > 0:
            # Display exactly 3 techniques in a clean layout
            techniques_to_show = results['relevant_techniques'][:3]
            
            if len(techniques_to_show) == 1:
                # Single technique - full width
                st.markdown(f"""
                <div class="technique-card">
                    <h4>🥇 #{1} - {techniques_to_show[0].id}: {techniques_to_show[0].name}</h4>
                    <p><strong>Confidence:</strong> {techniques_to_show[0].confidence:.2f} ({get_confidence_label(techniques_to_show[0].confidence)})</p>
                    <p>{techniques_to_show[0].description[:200] if techniques_to_show[0].description else 'No description available'}...</p>
                    <p><strong>Analysis:</strong> {techniques_to_show[0].reasoning[:150]}...</p>
                </div>
                """, unsafe_allow_html=True)
            
            elif len(techniques_to_show) == 2:
                # Two techniques - split in 2 columns
                col1, col2 = st.columns(2)
                medals = ["🥇", "🥈"]
                for i, (col, technique) in enumerate(zip([col1, col2], techniques_to_show)):
                    with col:
                        st.markdown(f"""
                        <div class="technique-card">
                            <h4>{medals[i]} #{i+1} - {technique.id}: {technique.name}</h4>
                            <p><strong>Confidence:</strong> {technique.confidence:.2f} ({get_confidence_label(technique.confidence)})</p>
                            <p>{technique.description[:150] if technique.description else 'No description available'}...</p>
                            <p><strong>Analysis:</strong> {technique.reasoning[:100]}...</p>
                        </div>
                        """, unsafe_allow_html=True)
            
            else:
                # Three techniques - split in 3 columns
                col1, col2, col3 = st.columns(3)
                medals = ["🥇", "🥈", "🥉"]
                for i, (col, technique) in enumerate(zip([col1, col2, col3], techniques_to_show)):
                    with col:
                        st.markdown(f"""
                        <div class="technique-card">
                            <h4>{medals[i]} #{i+1} - {technique.id}</h4>
                            <h5>{technique.name}</h5>
                            <p><strong>Confidence:</strong> {technique.confidence:.2f}</p>
                            <p><strong>Level:</strong> {get_confidence_label(technique.confidence)}</p>
                            <p style="font-size: 0.85em;">{technique.description[:120] if technique.description else 'No description available'}...</p>
                        </div>
                        """, unsafe_allow_html=True)
            
            # Expandable detailed analysis for each technique
            st.markdown("#### 📋 Detailed Analysis")
            for i, technique in enumerate(techniques_to_show):
                medal = ["🥇", "🥈", "🥉"][i]
                with st.expander(f"{medal} **{technique.id} - {technique.name}** (Confidence: {technique.confidence:.2f})", expanded=(i==0)):
                    st.write(f"**Full Description:** {technique.description}")
                    st.write(f"**Confidence Score:** {technique.confidence:.3f} - {get_confidence_label(technique.confidence)}")
                    st.write(f"**Detailed Reasoning:** {technique.reasoning}")
                    
                    # Confidence progress bar
                    confidence_color = get_confidence_color(technique.confidence)
                    st.markdown(f"""
                    <div style="background-color: #f0f0f0; border-radius: 10px; padding: 2px;">
                        <div style="background-color: {confidence_color}; width: {technique.confidence*100}%; height: 20px; border-radius: 8px; text-align: center; line-height: 20px; color: white; font-weight: bold;">
                            {technique.confidence:.1%}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
        else:
            st.warning("No relevant techniques found above the confidence threshold.")
            st.info("💡 **Tip:** Try lowering the confidence threshold in settings or use a different Claude model for better analysis.")
        
        # Analysis Summary
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("🎯 Top Techniques", min(3, len(results.get('relevant_techniques', []))))
        with col2:
            relevant_techniques = results.get('relevant_techniques', [])
            if relevant_techniques and len(relevant_techniques) > 0:
                avg_confidence = sum(t.confidence for t in relevant_techniques[:3]) / min(3, len(relevant_techniques))
                st.metric("📊 Avg Confidence", f"{avg_confidence:.2f}")
            else:
                st.metric("📊 Avg Confidence", "N/A")
        with col3:
            st.metric("🖥️ SIEM Platform", results.get('siem_platform', 'Unknown'))
        
        # Top 3 Summary Insight
        if results.get('relevant_techniques'):
            st.markdown("---")
            st.markdown("### 📈 Analysis Insights")
            
            techniques = results['relevant_techniques'][:3]
            top_confidence = techniques[0].confidence if techniques else 0
            
            col1, col2 = st.columns([2, 1])
            
            with col1:
                if top_confidence >= 0.9:
                    st.success(f"🎯 **Excellent Detection Coverage** - The top technique ({techniques[0].id}) has {top_confidence:.1%} confidence, indicating this SIEM rule provides excellent coverage for the identified attack patterns.")
                elif top_confidence >= 0.8:
                    st.info(f"✅ **Good Detection Coverage** - The analysis shows {top_confidence:.1%} confidence for the primary technique ({techniques[0].id}), suggesting reliable detection capabilities.")
                elif top_confidence >= 0.7:
                    st.warning(f"⚠️ **Moderate Detection Coverage** - Primary technique confidence is {top_confidence:.1%}. Consider refining the SIEM rule for better detection accuracy.")
                else:
                    st.error(f"🔍 **Low Detection Coverage** - The highest confidence is only {top_confidence:.1%}. This rule may need significant improvements.")
                
                # Technique diversity insight
                if len(techniques) >= 3:
                    confidence_range = techniques[0].confidence - techniques[2].confidence
                    if confidence_range <= 0.1:
                        st.info("🔄 **Consistent Mapping** - All top 3 techniques have similar confidence levels, indicating focused detection scope.")
                    else:
                        st.info("📊 **Varied Mapping** - Confidence scores vary across techniques, suggesting diverse attack pattern coverage.")
            
            with col2:
                # Quick stats
                st.markdown("**🎯 Detection Quality**")
                quality_score = sum(t.confidence for t in techniques) / len(techniques)
                if quality_score >= 0.85:
                    st.success(f"Excellent: {quality_score:.2f}")
                elif quality_score >= 0.75:
                    st.info(f"Good: {quality_score:.2f}")
                elif quality_score >= 0.65:
                    st.warning(f"Fair: {quality_score:.2f}")
                else:
                    st.error(f"Poor: {quality_score:.2f}")
                
                st.markdown(f"**🏆 Best Match:** {techniques[0].id}")
                st.markdown(f"**📊 Confidence:** {techniques[0].confidence:.1%}")
        
        # Actionable recommendations
        if results.get('relevant_techniques'):
            with st.expander("💡 **Recommendations for SIEM Rule Improvement**", expanded=False):
                techniques = results['relevant_techniques'][:3]
                st.markdown("**Based on the top 3 MITRE technique mappings:**")
                
                for i, technique in enumerate(techniques):
                    medal = ["🥇", "🥈", "🥉"][i]
                    st.markdown(f"**{medal} {technique.id} - {technique.name}:**")
                    if technique.confidence >= 0.9:
                        st.markdown(f"   ✅ Excellent detection for this technique. Rule is well-tuned.")
                    elif technique.confidence >= 0.8:
                        st.markdown(f"   📈 Good detection. Consider adding additional indicators for complete coverage.")
                    elif technique.confidence >= 0.7:
                        st.markdown(f"   ⚠️ Moderate detection. Review rule logic for potential improvements.")
                    else:
                        st.markdown(f"   🔍 Low confidence. Consider alternative detection approaches for this technique.")
                
                st.markdown("**🎯 Overall Recommendation:**")
                avg_confidence = sum(t.confidence for t in techniques) / len(techniques)
                if avg_confidence >= 0.85:
                    st.success("Your SIEM rule provides excellent coverage for the identified attack techniques. Consider deploying in production.")
                elif avg_confidence >= 0.75:
                    st.info("Good rule performance. Minor tuning could improve detection accuracy.")
                elif avg_confidence >= 0.65:
                    st.warning("Rule needs improvement. Consider adding more specific indicators or adjusting detection logic.")
                else:
                    st.error("Rule requires significant enhancement. Review detection approach and consider alternative strategies.")

def get_confidence_label(confidence: float) -> str:
    """Get confidence level label"""
    if confidence >= 0.9:
        return "Excellent Match"
    elif confidence >= 0.8:
        return "Very Good Match"
    elif confidence >= 0.7:
        return "Good Match"
    elif confidence >= 0.6:
        return "Moderate Match"
    else:
        return "Low Match"

def get_confidence_color(confidence: float) -> str:
    """Get color for confidence visualization"""
    if confidence >= 0.9:
        return "#28a745"  # Green
    elif confidence >= 0.8:
        return "#20c997"  # Teal
    elif confidence >= 0.7:
        return "#ffc107"  # Yellow
    elif confidence >= 0.6:
        return "#fd7e14"  # Orange
    else:
        return "#dc3545"  # Red

def display_incident_response_page():
    """Enhanced incident response page"""
    st.title("📋 Incident Response Playbook")
    
    if not st.session_state.get('analysis_results'):
        st.info("👈 **Please complete MITRE mapping first to generate incident response procedures**")
        return
    
    results = st.session_state['analysis_results']
    plan = results.get('incident_plan', {})
    
    if not plan:
        st.warning("No incident response plan available.")
        return
    
    # Alert Header
    st.markdown(f"""
    <div class="main-header">
        <h2>🚨 {plan.get('alert_title', 'Security Alert')}</h2>
        <p>Structured Investigation Playbook</p>
    </div>
    """, unsafe_allow_html=True)
    
    # MITRE Classification
    classification = plan.get('mitre_classification', {})
    top_techniques = results.get('relevant_techniques', [])[:3]  # Get top 3 techniques
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("**Category**")
        st.info(classification.get('category', 'Unknown'))
    
    with col2:
        st.markdown("**MITRE Tactic**")
        st.info(classification.get('tactic', 'Unknown'))
    
    with col3:
        st.markdown("**Top Technique**")
        if top_techniques:
            st.info(f"{top_techniques[0].id} ({top_techniques[0].confidence:.2f})")
        else:
            st.info(classification.get('technique', 'Unknown'))
    
    # Show all top 3 techniques if available
    if top_techniques and len(top_techniques) > 1:
        st.markdown("**🎯 All Mapped Techniques:**")
        technique_cols = st.columns(len(top_techniques))
        medals = ["🥇", "🥈", "🥉"]
        
        for i, (col, technique) in enumerate(zip(technique_cols, top_techniques)):
            with col:
                st.markdown(f"""
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                           color: white; padding: 0.8rem; border-radius: 8px; text-align: center; margin: 0.2rem;">
                    <div style="font-size: 1.2em;">{medals[i]}</div>
                    <div style="font-weight: bold;">{technique.id}</div>
                    <div style="font-size: 0.8em;">{technique.name[:30]}...</div>
                    <div style="font-size: 0.9em;">Confidence: {technique.confidence:.2f}</div>
                </div>
                """, unsafe_allow_html=True)
    
    # Description
    st.markdown("### 📝 Description")
    st.write(plan.get('description', 'No description available'))
    
    st.markdown(f"**🔧 Detected SIEM Platform:** {plan.get('siem_platform', 'Unknown')}")
    
    st.markdown("---")
    
    # Investigation Steps
    st.markdown("## 🕵️ Investigation Steps")
    
    investigation = plan.get('investigation_steps', {})
    
    # Step 1: Historical Check
    step1 = investigation.get('step1_historical', {})
    st.markdown(f"""
    <div class="step-card">
        <h3>📊 Step 1: {step1.get('title', 'Historical check')}</h3>
    </div>
    """, unsafe_allow_html=True)
    
    for action in step1.get('actions', []):
        st.markdown(f"• {action}")
    
    # Step 2: Duplicate Check
    step2 = investigation.get('step2_duplicate', {})
    st.markdown(f"""
    <div class="step-card">
        <h3>🔍 Step 2: {step2.get('title', 'Duplicate check')}</h3>
    </div>
    """, unsafe_allow_html=True)
    
    for action in step2.get('actions', []):
        st.markdown(f"• {action}")
    
    # Step 3: Investigation
    step3 = investigation.get('step3_investigate', {})
    st.markdown(f"""
    <div class="step-card">
        <h3>🕵️ Step 3: {step3.get('title', 'Investigate the events')}</h3>
    </div>
    """, unsafe_allow_html=True)
    
    # SIEM Queries
    if step3.get('siem_queries'):
        st.markdown("**🔍 SIEM Queries:**")
        for query in step3.get('siem_queries', []):
            st.code(query, language='sql')
    
    # EDR Actions
    if step3.get('edr_actions'):
        st.markdown("**🛡️ EDR Actions:**")
        for action in step3.get('edr_actions', []):
            st.markdown(f"• {action}")
    
    # Data Collection
    if step3.get('data_collection'):
        st.markdown("**📊 Data Collection:**")
        for item in step3.get('data_collection', []):
            st.markdown(f"• {item}")
    
    # Step 4: Recommendations
    step4 = investigation.get('step4_recommendations', {})
    st.markdown(f"""
    <div class="step-card">
        <h3>💡 Step 4: {step4.get('title', 'Recommendations')}</h3>
    </div>
    """, unsafe_allow_html=True)
    
    # Immediate Actions
    if step4.get('immediate_actions'):
        st.markdown("**🚨 Immediate Actions:**")
        for action in step4.get('immediate_actions', []):
            st.markdown(f"• {action}")
    
    # Resolver Teams
    if step4.get('resolver_teams'):
        st.markdown("**👥 Resolver Team Actions:**")
        for team_action in step4.get('resolver_teams', []):
            priority_emoji = {'High': '🔴', 'Medium': '🟡', 'Low': '🟢'}.get(team_action.get('priority', 'Medium'), '🟡')
            
            st.markdown(f"""
            <div class="recommendation-card">
                <h4>{priority_emoji} {team_action.get('team', 'Team')}</h4>
                <p><strong>Actions:</strong> {', '.join(team_action.get('actions', []))}</p>
                <p><strong>Priority:</strong> {team_action.get('priority', 'Medium')} | <strong>Timeline:</strong> {team_action.get('timeline', 'ASAP')}</p>
            </div>
            """, unsafe_allow_html=True)

def display_soar_workflow_page():
    """Visual SOAR workflow page with Graphviz diagram"""
    st.title("🔄 SOAR Workflow")
    
    if not st.session_state.get('analysis_results'):
        st.info("👈 **Please complete MITRE mapping first to generate SOAR workflow**")
        return
    
    results = st.session_state['analysis_results']
    workflow = results.get('soar_workflow', [])
    graphviz_dot = results.get('soar_graphviz', '')
    
    if not workflow:
        st.warning("No SOAR workflow available.")
        return
    
    # Workflow Header
    st.markdown(f"""
    <div class="main-header">
        <h2>🔄 SOAR Automation Workflow</h2>
        <p>End-to-End Incident Response Automation (Generated by {results.get('model_used', 'Claude AI')})</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Workflow Metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        automated_steps = sum(1 for step in workflow if hasattr(step, 'type') and step.type == 'automated')
        st.metric("🤖 Automated", automated_steps)
    with col2:
        manual_steps = sum(1 for step in workflow if hasattr(step, 'type') and step.type == 'manual')
        st.metric("👤 Manual", manual_steps)
    with col3:
        decision_steps = sum(1 for step in workflow if hasattr(step, 'type') and step.type == 'decision')
        st.metric("🤔 Decisions", decision_steps)
    with col4:
        st.metric("📋 Total Steps", len(workflow))
    
    # Graphviz Workflow Diagram
    st.markdown("### 📊 Visual Workflow Diagram")
    
    if graphviz_dot:
        try:
            # Create and display Graphviz diagram
            graph = graphviz.Source(graphviz_dot)
            st.graphviz_chart(graphviz_dot)
            
            # Legend
            st.markdown("""
            **Legend:**
            - 🔵 **Blue**: Automated steps (no human intervention)
            - 🟢 **Green**: Manual steps (require analyst action)  
            - 🟡 **Yellow**: Decision points (approval/escalation needed)
            """)
            
        except Exception as e:
            st.error(f"Error rendering Graphviz diagram: {str(e)}")
            st.text("Raw DOT notation:")
            st.code(graphviz_dot, language='dot')
    else:
        st.warning("No Graphviz diagram available.")
    
    # Detailed Steps
    st.markdown("### 📋 Detailed Workflow Steps")
    
    for i, step in enumerate(workflow):
        if not hasattr(step, 'type') or not hasattr(step, 'step_id') or not hasattr(step, 'name'):
            continue  # Skip malformed steps
            
        type_emoji = {"automated": "🤖", "manual": "👤", "decision": "🤔"}.get(step.type, "📋")
        
        with st.expander(f"{type_emoji} {step.step_id}: {step.name}", expanded=(i<3)):
            st.write(f"**Description:** {getattr(step, 'description', 'No description available')}")
            st.write(f"**Responsible Team:** {getattr(step, 'responsible_team', 'Unknown')}")
            st.write(f"**Type:** {step.type.title() if hasattr(step, 'type') else 'Unknown'}")
            
            if hasattr(step, 'inputs') and step.inputs:
                st.write("**Required Inputs:**")
                for inp in step.inputs:
                    st.write(f"• {inp}")
            
            if hasattr(step, 'outputs') and step.outputs:
                st.write("**Expected Outputs:**")
                for out in step.outputs:
                    st.write(f"• {out}")
            
            if hasattr(step, 'next_steps') and step.next_steps:
                st.write(f"**Next Steps:** {', '.join(step.next_steps)}")
    
    # Export Options
    st.markdown("### 📤 Export Options")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        workflow_json = json.dumps([{
            'step_id': getattr(step, 'step_id', ''),
            'name': getattr(step, 'name', ''),
            'type': getattr(step, 'type', ''),
            'description': getattr(step, 'description', ''),
            'responsible_team': getattr(step, 'responsible_team', ''),
            'inputs': getattr(step, 'inputs', []),
            'outputs': getattr(step, 'outputs', []),
            'next_steps': getattr(step, 'next_steps', [])
        } for step in workflow], indent=2)
        
        st.download_button(
            label="📊 Download JSON",
            data=workflow_json,
            file_name="soar_workflow.json",
            mime="application/json",
            use_container_width=True
        )
    
    with col2:
        # Download Graphviz DOT file
        if graphviz_dot:
            st.download_button(
                label="🎨 Download DOT",
                data=graphviz_dot,
                file_name="workflow_diagram.dot",
                mime="text/plain",
                use_container_width=True
            )
    
    with col3:
        checklist = "# SOAR Workflow Checklist\n\n"
        for step in workflow:
            if hasattr(step, 'type') and hasattr(step, 'step_id') and hasattr(step, 'name'):
                type_emoji = {"automated": "🤖", "manual": "👤", "decision": "🤔"}.get(step.type, "📋")
                checklist += f"- [ ] **{step.step_id}** - {step.name} {type_emoji}\n"
                checklist += f"  - **Team:** {getattr(step, 'responsible_team', 'Unknown')}\n\n"
        
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
        st.title("🛡️ Navigation")
        st.markdown("---")
        
        page = st.selectbox(
            "📍 Go to:",
            ["🎯 MITRE Mapping", "📋 Incident Response", "🔄 SOAR Workflow"],
            index=0
        )
        
        st.markdown("---")
        
        # Status
        if st.session_state.get('analysis_results'):
            results = st.session_state['analysis_results']
            
            # Check for partial results
            has_techniques = results.get('relevant_techniques') and len(results.get('relevant_techniques', [])) > 0
            has_incident_plan = results.get('incident_plan') and len(results.get('incident_plan', {})) > 0
            has_soar = results.get('soar_workflow') and len(results.get('soar_workflow', [])) > 0
            
            if has_techniques and has_incident_plan and has_soar:
                st.success("✅ Analysis Complete")
            elif has_techniques:
                st.warning("⚠️ Partial Analysis")
                st.info("Some components may be incomplete")
            else:
                st.error("❌ Analysis Issues")
                st.info("Please try again")
            
            st.info(f"🖥️ Platform: {results.get('siem_platform', 'Unknown')}")
            st.info(f"🎯 Techniques: {len(results.get('relevant_techniques', []))}")
            st.info(f"🤖 Model: {results.get('model_used', 'Unknown')}")
        else:
            st.info("⏳ Ready for Analysis")
    
    # Main content
    if page == "🎯 MITRE Mapping":
        display_mitre_mapping_page()
    elif page == "📋 Incident Response":
        display_incident_response_page()
    elif page == "🔄 SOAR Workflow":
        display_soar_workflow_page()

    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: #666;'>
        <p>🛡️ Cybersecurity Response Platform | Powered by Claude AI (All Models Supported)</p>
        <p style='font-size: 0.8em;'>Compatible with Claude 4 Sonnet, Claude 4 Opus, Claude 3.5 Sonnet, Claude 3.5 Haiku & Legacy Models</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()

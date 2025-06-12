"""
Core Cybersecurity Response Platform
Handles MITRE mapping, incident response planning, and SOAR workflow generation
"""
import anthropic
import json
import requests
import time
import re
import streamlit as st
from typing import Dict, List, Any
from data_models import TechniqueResult, SOARWorkflowStep

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

    # MITRE Mapping Methods
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

    # Incident Response Methods
    def generate_incident_response_plan(self, rule_description: str, mitre_techniques: List[TechniqueResult]) -> Dict[str, Any]:
        """Generate comprehensive incident response plan"""
        techniques_summary = "\n".join([
            f"- {t.id}: {t.name} (Confidence: {t.confidence:.2f})"
            for t in mitre_techniques[:5]
        ])
        
        prompt = f"""You are a senior incident response analyst creating a comprehensive investigation plan.

Based on the SIEM rule and identified MITRE ATT&CK techniques, create a detailed incident response plan with specific investigation steps and team recommendations.

SIEM Rule Description:
{rule_description}

Identified MITRE ATT&CK Techniques:
{techniques_summary}

Create a structured incident response plan with:

1. SOC L1 Investigation Steps (initial triage and basic analysis)
2. SOC L2 Investigation Steps (deep analysis and threat hunting)
3. Resolver Team Recommendations (specific actions for different teams)

For each step, include:
- Clear action items
- Specific commands or tools to use
- Expected outcomes
- Escalation criteria

Format your response as a JSON object with this structure:
{{
  "l1_steps": [
    {{
      "step": "Step description",
      "commands": ["command1", "command2"],
      "expected_outcome": "What L1 should find",
      "escalation_criteria": "When to escalate to L2"
    }}
  ],
  "l2_steps": [
    {{
      "step": "Deep analysis step",
      "commands": ["advanced command1", "advanced command2"],
      "expected_outcome": "What L2 should discover",
      "escalation_criteria": "When to escalate to resolver teams"
    }}
  ],
  "resolver_recommendations": [
    {{
      "team": "Team name (e.g., Firewall Team, Identity Team)",
      "action": "Specific action to take",
      "priority": "High/Medium/Low",
      "timeline": "Expected completion time"
    }}
  ]
}}

Return only the JSON object:"""
        
        try:
            response_text = self._call_claude(prompt, max_tokens=3072, temperature=0.2)
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            return {}
        except Exception as e:
            st.error(f"Error generating incident response plan: {str(e)}")
            return {}

    # SOAR Workflow Methods
    def generate_soar_workflow(self, rule_description: str, mitre_techniques: List[TechniqueResult]) -> List[SOARWorkflowStep]:
        """Generate SOAR workflow from alert trigger to case closure"""
        techniques_summary = "\n".join([
            f"- {t.id}: {t.name}"
            for t in mitre_techniques[:3]
        ])
        
        prompt = f"""You are a SOAR architect designing an automated workflow for incident response.

Create a complete SOAR workflow from alert trigger to case closure, including decision points, manual interventions, and integrations.

SIEM Rule: {rule_description}
Key Techniques: {techniques_summary}

Design a workflow with these components:
1. Alert ingestion and enrichment
2. Initial automated analysis
3. L1 analyst decision points (false positive, escalate)
4. Automated containment actions
5. ServiceNow ticket creation
6. L2 investigation triggers
7. Resolution and closure steps

For each step, specify:
- Step name and type (automated, manual, decision)
- Responsible team
- Required inputs and expected outputs
- Next steps based on outcomes

Return as JSON array of workflow steps:
[
  {{
    "step_id": "STEP_001",
    "name": "Alert Ingestion", 
    "type": "automated",
    "description": "Description of the step",
    "responsible_team": "SIEM/SOAR Platform",
    "inputs": ["alert_data", "rule_metadata"],
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
            incident_plan = self.generate_incident_response_plan(rule_description, relevant_techniques)
            
            # SOAR workflow
            soar_workflow = self.generate_soar_workflow(rule_description, relevant_techniques)
            
            results = {
                'rule_description': rule_description,
                'iocs': iocs,
                'context_info': context_info,
                'data_source': data_source,
                'relevant_techniques': relevant_techniques,
                'incident_plan': incident_plan,
                'soar_workflow': soar_workflow
            }
            
            return results
            
        except Exception as e:
            st.error(f"Analysis failed: {str(e)}")
            return results

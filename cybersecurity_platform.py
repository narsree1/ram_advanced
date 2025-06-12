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
            "Sumo Logic": ["_source=", "_sourceCategory=", "| parse", "| timeslice", "| count"],
            "LogRhythm": ["classification=", "direction=", "action=", "msgclass="],
            "ArcSight": ["devicevendor=", "deviceproduct=", "categorysignificance="]
        }
        
        # Check for platform-specific patterns
        for platform, patterns in siem_patterns.items():
            pattern_matches = sum(1 for pattern in patterns if pattern in rule_lower)
            if pattern_matches >= 2:  # Require at least 2 matching patterns
                return platform
        
        # Fallback detection based on syntax style
        if any(pattern in rule_lower for pattern in ["index=", "sourcetype=", "|"]):
            return "Splunk"
        elif any(pattern in rule_lower for pattern in ['"query":', '"bool":']):
            return "Elastic (ELK)"
        elif any(pattern in rule_lower for pattern in ["| where", "| summarize"]):
            return "Microsoft Sentinel"
        
        return "Generic SIEM"

    def generate_siem_specific_commands(self, platform: str, rule_description: str, mitre_techniques: List[TechniqueResult]) -> Dict[str, List[str]]:
        """Generate platform-specific SIEM investigation commands"""
        
        # Extract key indicators for search refinement
        key_indicators = []
        if mitre_techniques:
            top_technique = mitre_techniques[0]
            if "powershell" in rule_description.lower():
                key_indicators = ["powershell.exe", "EncodedCommand", "Invoke-Expression"]
            elif "registry" in rule_description.lower():
                key_indicators = ["Registry", "HKEY", "Run"]
            elif "network" in rule_description.lower():
                key_indicators = ["network", "connection", "port"]
            elif "process" in rule_description.lower():
                key_indicators = ["process", "execution", "cmd.exe"]
        
        commands = {
            "Splunk": [
                f"index=main sourcetype=WinEventLog:Security EventCode=4688 | search process_name=\"*{key_indicators[0] if key_indicators else 'suspicious'}*\"",
                f"index=main sourcetype=WinEventLog:System | head 1000 | search {key_indicators[0] if key_indicators else 'suspicious'}",
                "| stats count by host, user, process_name | sort -count",
                "| eval time_diff=_time-earliest | where time_diff < 3600",
                "| lookup threat_intel.csv IOC as process_name OUTPUT threat_level",
                "index=main earliest=-24h | rare limit=10 process_name"
            ],
            
            "Microsoft Sentinel": [
                f"SecurityEvent | where EventID == 4688 | where Process contains \"{key_indicators[0] if key_indicators else 'suspicious'}\"",
                f"DeviceProcessEvents | where ProcessCommandLine contains \"{key_indicators[0] if key_indicators else 'suspicious'}\"",
                "| summarize count() by AccountName, DeviceName | order by count_ desc",
                "| where TimeGenerated > ago(24h)",
                "| join kind=leftouter (ThreatIntelligenceIndicator) on $left.ProcessCommandLine == $right.NetworkIP",
                "| extend SuspiciousActivity = iff(count_ > 10, \"High\", \"Normal\")"
            ],
            
            "Google Chronicle": [
                f"metadata.event_type = \"PROCESS_LAUNCH\" AND target.process.command_line CONTAINS \"{key_indicators[0] if key_indicators else 'suspicious'}\"",
                f"principal.hostname = /regex/ AND target.process.file.full_path CONTAINS \"{key_indicators[0] if key_indicators else 'suspicious'}\"",
                "metadata.collected_timestamp.seconds > 86400",
                "principal.user.userid != \"\" GROUP BY principal.hostname",
                "metadata.threat.verdict = \"SUSPICIOUS\" OR metadata.threat.verdict = \"MALICIOUS\""
            ],
            
            "IBM QRadar": [
                f"SELECT sourceip, destinationip, eventname FROM events WHERE eventname ILIKE '%{key_indicators[0] if key_indicators else 'suspicious'}%'",
                "SELECT * FROM events WHERE category = 4003 AND starttime > NOW() - INTERVAL '24 HOURS'",
                "GROUP BY sourceip ORDER BY eventcount DESC",
                "WHERE magnitude > 5",
                "LEFT JOIN reference_data.threat_intel ON events.sourceip = threat_intel.ip"
            ],
            
            "Elastic (ELK)": [
                f"""{{
  "query": {{
    "bool": {{
      "must": [
        {{"match": {{"process.name": "{key_indicators[0] if key_indicators else 'suspicious'}"}}}},
        {{"range": {{"@timestamp": {{"gte": "now-24h"}}}}}}
      ]
    }}
  }},
  "aggs": {{
    "hosts": {{"terms": {{"field": "host.name"}}}}
  }}
}}""",
                f"""{{
  "query": {{
    "wildcard": {{
      "process.command_line": "*{key_indicators[0] if key_indicators else 'suspicious'}*"
    }}
  }}
}}""",
                """{"query": {"terms": {"event.code": ["4688", "4689"]}}}""",
                """{"sort": [{"@timestamp": {"order": "desc"}}], "size": 100}"""
            ],
            
            "Generic SIEM": [
                f"Search for process execution events containing: {key_indicators[0] if key_indicators else 'suspicious_activity'}",
                "Filter events from last 24 hours",
                "Group by hostname and count occurrences",
                "Look for unusual patterns or high frequency events",
                "Cross-reference with threat intelligence feeds"
            ]
        }
        
        return {"l1_commands": commands.get(platform, commands["Generic SIEM"])[:3], 
                "l2_commands": commands.get(platform, commands["Generic SIEM"])[3:]}

    def generate_edr_commands(self, rule_description: str, mitre_techniques: List[TechniqueResult]) -> Dict[str, List[str]]:
        """Generate EDR-specific investigation commands"""
        
        # Determine investigation focus based on MITRE techniques
        investigation_focus = "process"
        if mitre_techniques:
            top_technique = mitre_techniques[0]
            if any(keyword in top_technique.name.lower() for keyword in ["network", "connection"]):
                investigation_focus = "network"
            elif any(keyword in top_technique.name.lower() for keyword in ["registry", "persistence"]):
                investigation_focus = "registry"
            elif any(keyword in top_technique.name.lower() for keyword in ["file", "creation"]):
                investigation_focus = "file"
        
        edr_commands = {
            "CrowdStrike Falcon": {
                "process": [
                    "event_platform=Win event_simpleName=ProcessRollup2 ImageFileName=\"*powershell.exe\"",
                    "event_platform=Win event_simpleName=ProcessRollup2 | stats count by ComputerName, UserName",
                    "aid=\"<device_aid>\" | search ProcessRollup2 | head 100"
                ],
                "network": [
                    "event_platform=Win event_simpleName=NetworkConnectIP4 | search RemoteAddressIP4=*",
                    "event_simpleName=DnsRequest DomainName=\"*suspicious*\"",
                    "NetworkConnectIP4 RemotePort=4444 OR RemotePort=4445"
                ],
                "registry": [
                    "event_platform=Win event_simpleName=RegGenericValue | search RegValueName=\"*Run*\"",
                    "RegGenericValue RegObjectName=\"*CurrentVersion\\Run*\"",
                    "RegGenericValue | stats count by RegObjectName"
                ],
                "file": [
                    "event_platform=Win event_simpleName=NewExecutableWritten | search FileName=\"*.exe\"",
                    "NewExecutableWritten | search FilePath=\"*temp*\" OR FilePath=\"*tmp*\"",
                    "FileOpenInfo FileName=\"*.bat\" OR FileName=\"*.cmd\""
                ]
            },
            
            "Microsoft Defender": {
                "process": [
                    "DeviceProcessEvents | where ProcessCommandLine contains \"powershell\"",
                    "DeviceProcessEvents | where InitiatingProcessFileName =~ \"cmd.exe\"",
                    "DeviceProcessEvents | summarize count() by DeviceName, AccountName"
                ],
                "network": [
                    "DeviceNetworkEvents | where RemotePort in (4444, 4445)",
                    "DeviceNetworkEvents | where ActionType == \"ConnectionSuccess\"",
                    "DeviceNetworkEvents | summarize count() by RemoteIP, DeviceName"
                ],
                "registry": [
                    "DeviceRegistryEvents | where RegistryKey contains \"Run\"",
                    "DeviceRegistryEvents | where ActionType == \"RegistryValueSet\"",
                    "DeviceRegistryEvents | where RegistryKey contains \"CurrentVersion\\\\Run\""
                ],
                "file": [
                    "DeviceFileEvents | where FileName endswith \".exe\"",
                    "DeviceFileEvents | where FolderPath contains \"temp\"",
                    "DeviceFileEvents | where ActionType == \"FileCreated\""
                ]
            },
            
            "SentinelOne": {
                "process": [
                    "ObjectType = \"Process\" AND SrcProcCmdLine CONTAINS \"powershell\"",
                    "EventType = \"Process Creation\" AND SrcProcName = \"cmd.exe\"",
                    "ObjectType = \"Process\" | group SrcProcName, EndpointName"
                ],
                "network": [
                    "ObjectType = \"IP\" AND DstPort IN (4444, 4445)",
                    "EventType = \"Net Conn Status\" AND NetConnStatus = \"SUCCESS\"",
                    "ObjectType = \"IP\" | group DstIP, EndpointName"
                ],
                "registry": [
                    "ObjectType = \"Registry\" AND RegistryPath CONTAINS \"Run\"",
                    "EventType = \"Registry Value Create\" OR EventType = \"Registry Value Modify\"",
                    "RegistryPath CONTAINS \"CurrentVersion\\Run\""
                ],
                "file": [
                    "ObjectType = \"File\" AND TgtFileName ENDS_WITH \".exe\"",
                    "EventType = \"File Creation\" AND TgtFilePath CONTAINS \"temp\"",
                    "ObjectType = \"File\" AND TgtFileName ENDS_WITH \".bat\""
                ]
            },
            
            "Carbon Black": {
                "process": [
                    "process_name:powershell.exe AND cmdline:*EncodedCommand*",
                    "parent_name:cmd.exe AND process_name:*.exe",
                    "process_name:powershell.exe | group_by hostname, username"
                ],
                "network": [
                    "netconn_count:[1 TO *] AND (remote_port:4444 OR remote_port:4445)",
                    "domain:*suspicious* AND netconn_count:[1 TO *]",
                    "ipaddr:* AND netconn_count:[10 TO *]"
                ],
                "registry": [
                    "regmod_count:[1 TO *] AND regmod:*Run*",
                    "regmod:*CurrentVersion\\Run* AND regmod_count:[1 TO *]",
                    "regmod_count:[1 TO *] | group_by regmod"
                ],
                "file": [
                    "filemod_count:[1 TO *] AND filemod:*.exe",
                    "filemod:*temp*.exe OR filemod:*tmp*.exe",
                    "filemod_count:[1 TO *] AND (filemod:*.bat OR filemod:*.cmd)"
                ]
            }
        }
        
        # Return commands for all major EDR platforms
        return {
            "crowdstrike": edr_commands["CrowdStrike Falcon"][investigation_focus],
            "defender": edr_commands["Microsoft Defender"][investigation_focus],
            "sentinelone": edr_commands["SentinelOne"][investigation_focus],
            "carbon_black": edr_commands["Carbon Black"][investigation_focus]
        }

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

    # Incident Response Methods
    def generate_incident_response_plan(self, rule_description: str, mitre_techniques: List[TechniqueResult], siem_rule: str) -> Dict[str, Any]:
        """Generate comprehensive incident response plan with SIEM and EDR specific steps"""
        
        # Identify SIEM platform
        siem_platform = self.identify_siem_platform(siem_rule)
        
        # Get SIEM-specific commands
        siem_commands = self.generate_siem_specific_commands(siem_platform, rule_description, mitre_techniques)
        
        # Get EDR commands
        edr_commands = self.generate_edr_commands(rule_description, mitre_techniques)
        
        techniques_summary = "\n".join([
            f"- {t.id}: {t.name} (Confidence: {t.confidence:.2f})"
            for t in mitre_techniques[:5]
        ])
        
        prompt = f"""You are a senior SOC analyst creating platform-specific investigation procedures.

SIEM Platform Detected: {siem_platform}
Rule Description: {rule_description}
MITRE ATT&CK Techniques: {techniques_summary}

Create detailed investigation steps using the detected SIEM platform ({siem_platform}) and EDR tools.

For L1 Investigation Steps:
- Use initial triage with {siem_platform} queries
- Include basic EDR hunting steps
- Provide clear escalation criteria
- Focus on rapid assessment (15-30 minutes)

For L2 Investigation Steps:
- Deep analysis using advanced {siem_platform} features
- Comprehensive EDR investigation
- Threat hunting and correlation
- Timeline analysis and attribution

For Resolver Team Recommendations:
- Specific containment actions
- Platform-specific response procedures
- Clear timelines and priorities

Format as JSON:
{{
  "siem_platform": "{siem_platform}",
  "l1_steps": [
    {{
      "step": "Step description with {siem_platform} focus",
      "siem_commands": ["specific {siem_platform} query"],
      "edr_commands": ["EDR investigation command"],
      "expected_outcome": "What L1 should find",
      "escalation_criteria": "When to escalate to L2",
      "timeline": "Expected time to complete"
    }}
  ],
  "l2_steps": [
    {{
      "step": "Advanced analysis step",
      "siem_commands": ["advanced {siem_platform} query"],
      "edr_commands": ["deep EDR analysis"],
      "expected_outcome": "What L2 should discover",
      "escalation_criteria": "When to escalate to resolver teams",
      "timeline": "Expected time to complete"
    }}
  ],
  "resolver_recommendations": [
    {{
      "team": "Team name",
      "action": "Specific action with platform details",
      "platform_specific": "Platform-specific implementation",
      "priority": "High/Medium/Low",
      "timeline": "Expected completion time"
    }}
  ]
}}

Return only the JSON object:"""
        
        try:
            response_text = self._call_claude(prompt, max_tokens=4096, temperature=0.2)
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                generated_plan = json.loads(json_match.group())
                
                # Enhance with real platform-specific commands
                if generated_plan.get('l1_steps'):
                    for i, step in enumerate(generated_plan['l1_steps']):
                        if i < len(siem_commands['l1_commands']):
                            step['siem_commands'] = [siem_commands['l1_commands'][i]]
                        # Add EDR commands from different platforms
                        step['edr_commands'] = {
                            "CrowdStrike": edr_commands.get('crowdstrike', ["No specific command"])[0] if edr_commands.get('crowdstrike') else "No specific command",
                            "Microsoft Defender": edr_commands.get('defender', ["No specific command"])[0] if edr_commands.get('defender') else "No specific command",
                            "SentinelOne": edr_commands.get('sentinelone', ["No specific command"])[0] if edr_commands.get('sentinelone') else "No specific command"
                        }
                
                if generated_plan.get('l2_steps'):
                    for i, step in enumerate(generated_plan['l2_steps']):
                        if i < len(siem_commands['l2_commands']):
                            step['siem_commands'] = [siem_commands['l2_commands'][i]]
                        # Add all EDR platform commands for L2
                        step['edr_commands'] = edr_commands
                
                return generated_plan
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
            
            # Incident response plan (now with SIEM platform detection)
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

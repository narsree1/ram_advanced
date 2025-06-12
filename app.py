import streamlit as st
import anthropic
import json
import requests
from typing import Dict, List, Any
import pandas as pd
import time
import re
from dataclasses import dataclass
import os

# Configure page
st.set_page_config(
    page_title="Rule-ATT&CK Mapper (RAM)",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

@dataclass
class TechniqueResult:
    id: str
    name: str
    description: str
    confidence: float
    reasoning: str

class RuleATTACKMapper:
    def __init__(self, api_key: str, model_name: str = "claude-3-5-haiku-20241022"):
        """Initialize RAM with Claude API"""
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
            # Extract JSON from response
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
            # Using DuckDuckGo Instant Answer API (free, no key required)
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
        
        # Claude Haiku is fast, so we can use shorter delays
        delay = 0.2 if "haiku" in self.model_name.lower() else 0.3
        
        for ioc_type, ioc_values in iocs_dict.items():
            for ioc_value in ioc_values[:3]:  # Limit to prevent too many API calls
                search_query = f"cybersecurity {ioc_value} malware analysis threat"
                context = self.search_web_context(search_query)
                context_info[ioc_value] = context
                time.sleep(delay)  # Rate limiting
        
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
        # Simplified data source mapping based on common patterns
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
        
        return "Process: Process Creation"  # Default
    
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
            # Extract JSON array from response
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
                
                # Extract confidence score
                confidence_match = re.search(r'CONFIDENCE:\s*([0-9.]+)', response_text)
                confidence = float(confidence_match.group(1)) if confidence_match else 0.5
                
                # Extract reasoning
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
        
        # Sort by confidence score
        relevant_techniques.sort(key=lambda x: x.confidence, reverse=True)
        return relevant_techniques
    
    def map_rule_to_techniques(self, siem_rule: str, confidence_threshold: float = 0.7) -> Dict[str, Any]:
        """Complete RAM pipeline"""
        results = {}
        
        # Progress tracking
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        try:
            # Step 1: Extract IoCs
            status_text.text("Step 1/6: Extracting Indicators of Compromise...")
            progress_bar.progress(1/6)
            iocs = self.extract_iocs(siem_rule)
            results['iocs'] = iocs
            
            # Step 2: Retrieve contextual information
            status_text.text("Step 2/6: Retrieving contextual information...")
            progress_bar.progress(2/6)
            context_info = self.retrieve_contextual_info(iocs)
            results['context_info'] = context_info
            
            # Step 3: Translate to natural language
            status_text.text("Step 3/6: Translating to natural language...")
            progress_bar.progress(3/6)
            rule_description = self.translate_to_natural_language(siem_rule, iocs, context_info)
            results['rule_description'] = rule_description
            
            # Step 4: Identify data source
            status_text.text("Step 4/6: Identifying data sources...")
            progress_bar.progress(4/6)
            data_source = self.identify_data_source(rule_description)
            results['data_source'] = data_source
            
            # Step 5: Recommend probable techniques
            status_text.text("Step 5/6: Recommending probable techniques...")
            progress_bar.progress(5/6)
            probable_techniques = self.recommend_probable_techniques(rule_description)
            results['probable_techniques'] = probable_techniques
            
            # Step 6: Extract relevant techniques
            status_text.text("Step 6/6: Extracting relevant techniques...")
            progress_bar.progress(6/6)
            relevant_techniques = self.extract_relevant_techniques(rule_description, probable_techniques, confidence_threshold)
            results['relevant_techniques'] = relevant_techniques
            
            status_text.text("✅ Analysis complete!")
            return results
            
        except Exception as e:
            status_text.text(f"❌ Error: {str(e)}")
            return results

def main():
    st.title("🛡️ Rule-ATT&CK Mapper (RAM)")
    st.markdown("**Automated mapping of SIEM rules to MITRE ATT&CK techniques using LLMs**")
    
    # Sidebar for configuration
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        # Try to get API key from secrets first, then from user input
        default_api_key = st.secrets.get("CLAUDE_API_KEY", "")
        
        if default_api_key:
            api_key = default_api_key
            st.success("✅ API Key loaded from secrets")
        else:
            # API Key input
            api_key = st.text_input(
                "Claude API Key", 
                type="password",
                placeholder="Enter your Claude API key...",
                help="Get your API key from https://console.anthropic.com/"
            )
            
            if not api_key:
                st.warning("Please enter your Claude API key to continue")
                st.info("💡 **Tip**: You can also configure the API key in Streamlit Cloud secrets for automatic loading")
                st.stop()
        
        # Additional settings
        st.subheader("🎛️ Advanced Settings")
        
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
            index=0,  # Default to Claude 3.5 Haiku
            help="Choose the Claude model to use. Haiku is fastest and most cost-effective."
        )
        selected_model = model_options[selected_model_display]
        
        confidence_threshold = st.slider(
            "Confidence Threshold",
            min_value=0.1,
            max_value=1.0,
            value=st.secrets.get("settings", {}).get("default_confidence_threshold", 0.7),
            step=0.1,
            help="Minimum confidence score for technique relevance"
        )
        
        max_display = st.selectbox(
            "Max Techniques to Display",
            options=[3, 5, 10, 15],
            index=1,
            help="Maximum number of techniques to show in results"
        )
        
        st.header("📊 About RAM")
        st.markdown("""
        **RAM Pipeline:**
        1. **IoC Extraction** - Extract indicators from rule
        2. **Context Retrieval** - Gather additional information
        3. **Language Translation** - Convert to natural language
        4. **Data Source ID** - Identify MITRE data sources
        5. **Technique Recommendation** - Find probable techniques
        6. **Relevance Extraction** - Filter most relevant matches
        
        **🤖 Claude Model Comparison:**
        - **Claude 3.5 Haiku**: Fastest, most cost-effective, excellent for structured tasks
        - **Claude 3.5 Sonnet**: Balanced performance and capability
        - **Claude 3 Models**: Proven reliability
        """)
        
        # Model-specific tips
        if "haiku" in selected_model.lower():
            st.success("🚀 **Claude Haiku**: Lightning fast & cost-effective!")
        elif "sonnet" in selected_model.lower() and "3.5" in selected_model:
            st.info("⚡ **Claude 3.5 Sonnet**: Premium performance")
        else:
            st.warning("📝 **Claude 3**: Reliable baseline models")
    
    # Main interface
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.header("📝 Input SIEM Rule")
        
        # Example rules
        example_rules = {
            "Splunk - Process Creation": """index=main sourcetype="WinEventLog:Security" EventCode=4688 | search process_name="*powershell.exe*" command_line="*-EncodedCommand*" | stats count by host, user, process_name, command_line""",
            "Splunk - Registry Modification": """index=main sourcetype="WinEventLog:System" | search registry_path="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*" | stats count by host, registry_path, registry_value""",
            "Elasticsearch - Network Connection": """GET /logs/_search { "query": { "bool": { "must": [ {"term": {"event_type": "network"}}, {"range": {"destination_port": {"gte": 4444, "lte": 4445}}} ] } } }"""
        }
        
        selected_example = st.selectbox("Choose an example or enter your own:", ["Custom"] + list(example_rules.keys()))
        
        if selected_example != "Custom":
            siem_rule = st.text_area(
                "SIEM Rule:", 
                value=example_rules[selected_example],
                height=150,
                help="Enter your SIEM rule in any format (Splunk SPL, Elasticsearch, KQL, etc.)"
            )
        else:
            siem_rule = st.text_area(
                "SIEM Rule:", 
                height=150,
                placeholder="Enter your SIEM rule here...",
                help="Enter your SIEM rule in any format (Splunk SPL, Elasticsearch, KQL, etc.)"
            )
        
        analyze_button = st.button("🔍 Analyze Rule", type="primary", use_container_width=True)
    
    with col2:
        st.header("📊 Analysis Results")
        
        if analyze_button and siem_rule.strip():
            # Display model info
            st.info(f"🤖 Using model: **{selected_model_display}** ({selected_model})")
            
            # Initialize RAM
            ram = RuleATTACKMapper(api_key, selected_model)
            
            # Run analysis
            results = ram.map_rule_to_techniques(siem_rule, confidence_threshold)
            
            # Display results
            if results:
                # Rule Description
                if 'rule_description' in results:
                    st.subheader("📋 Rule Description")
                    st.write(results['rule_description'])
                
                # Data Source
                if 'data_source' in results:
                    st.subheader("🔍 Data Source")
                    st.info(f"**{results['data_source']}**")
                
                # Relevant Techniques
                if 'relevant_techniques' in results and results['relevant_techniques']:
                    st.subheader("🎯 Relevant MITRE ATT&CK Techniques")
                    
                    techniques_to_show = results['relevant_techniques'][:max_display]
                    
                    for i, technique in enumerate(techniques_to_show):
                        with st.expander(f"**{technique.id}** - {technique.name} (Confidence: {technique.confidence:.2f})", expanded=(i==0)):
                            st.write(f"**Description:** {technique.description}")
                            st.write(f"**Reasoning:** {technique.reasoning}")
                            st.progress(technique.confidence)
                    
                    if len(results['relevant_techniques']) > max_display:
                        st.info(f"Showing top {max_display} techniques. Total found: {len(results['relevant_techniques'])}")
                else:
                    st.warning("No relevant techniques found with the current confidence threshold. Try lowering the threshold.")
                
                # Summary Statistics
                if 'relevant_techniques' in results:
                    col_stat1, col_stat2, col_stat3 = st.columns(3)
                    with col_stat1:
                        st.metric("Techniques Found", len(results['relevant_techniques']))
                    with col_stat2:
                        avg_confidence = sum(t.confidence for t in results['relevant_techniques']) / len(results['relevant_techniques']) if results['relevant_techniques'] else 0
                        st.metric("Avg Confidence", f"{avg_confidence:.2f}")
                    with col_stat3:
                        high_confidence = sum(1 for t in results['relevant_techniques'] if t.confidence >= 0.8)
                        st.metric("High Confidence", high_confidence)
                
                # IoCs and Context (collapsible)
                with st.expander("🔍 Extracted IoCs and Context", expanded=False):
                    if 'iocs' in results:
                        st.subheader("Indicators of Compromise")
                        st.json(results['iocs'])
                    
                    if 'context_info' in results:
                        st.subheader("Contextual Information")
                        for ioc, context in results['context_info'].items():
                            st.write(f"**{ioc}:** {context}")
        
        elif analyze_button:
            st.warning("Please enter a SIEM rule to analyze")
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center'>
        <p>Built with ❤️ using Streamlit and Claude API</p>
        <p><a href='https://github.com/your-username/ram-framework'>📚 View on GitHub</a> | 
        <a href='https://arxiv.org/html/2502.02337v1'>📄 Original Paper</a></p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()

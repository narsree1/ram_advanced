"""
Data models for the Cybersecurity Response Platform
"""
from dataclasses import dataclass
from typing import List

@dataclass
class TechniqueResult:
    """MITRE ATT&CK technique result with confidence scoring"""
    id: str
    name: str
    description: str
    confidence: float
    reasoning: str

@dataclass
class InvestigationStep:
    """Investigation step for SOC analysts"""
    role: str  # L1, L2, or Resolver Team
    step: str
    commands: List[str]
    expected_outcome: str
    escalation_criteria: str

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

@dataclass
class AnalysisResults:
    """Complete analysis results container"""
    rule_description: str
    iocs: dict
    context_info: dict
    data_source: str
    relevant_techniques: List[TechniqueResult]
    incident_plan: dict
    soar_workflow: List[SOARWorkflowStep]

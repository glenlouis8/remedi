import operator
from typing import Annotated, List, TypedDict, Optional
from langchain_core.messages import BaseMessage


class AgentState(TypedDict):
    """
    The state of the Remedi agent system.
    """

    # 1. Chat History: Stores the conversation and tool outputs
    messages: Annotated[List[BaseMessage], operator.add]

    # 2. Human-in-the-Loop Switch
    # The human MUST update this to "approve" to allow remediation.
    safety_decision: str

    # Optional list of resource names the human approved — if None, all are approved
    approved_resources: Optional[List[str]]

    # 3. Audit Artifacts
    # A generated summary of what was found (populated by Auditor before pause)
    audit_summary: Optional[str]

    # 4. Metrics Tracking
    scan_id: str
    findings_count: int

    # How many times verifier_agent has run this scan. Caps the
    # verifier <-> verify_tools loop so a tool-happy LLM can't hit the graph
    # recursion limit and crash the scan after remediation already ran.
    verify_iterations: int

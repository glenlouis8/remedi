from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langgraph.checkpoint.memory import MemorySaver

from agents.state import AgentState
from agents.nodes import (
    orchestrator_node,
    report_generator_node,
    remediator_agent,
    safety_gate_node,
    remediation_tools_list,
    audit_tools_list,
    verifier_agent,
)

remediation_tool_node = ToolNode(remediation_tools_list)
verify_tool_node = ToolNode(audit_tools_list)

# --- CONDITIONAL EDGES ---


def should_remediate_continue(state: AgentState):
    last_message = state["messages"][-1]
    if last_message.tool_calls:
        return "remediation_tools"
    return "verifier"


MAX_VERIFY_ITERATIONS = 4


def should_verify_continue(state: AgentState):
    # Hard stop: without this the verifier <-> verify_tools loop is bounded only
    # by LangGraph's recursion_limit, and hitting that raises GraphRecursionError
    # which crashes the scan *after* remediation already ran.
    if state.get("verify_iterations", 0) >= MAX_VERIFY_ITERATIONS:
        print(f"--- [VERIFIER] hit {MAX_VERIFY_ITERATIONS}-iteration cap — ending ---")
        return "end"
    last_message = state["messages"][-1]
    if last_message.tool_calls:
        return "verify_tools"
    return "end"


# --- BUILD GRAPH ---

workflow = StateGraph(AgentState)

# 1. Add Nodes
workflow.add_node("orchestrator", orchestrator_node)
workflow.add_node("report_generator", report_generator_node)
workflow.add_node("safety_gate", safety_gate_node)
workflow.add_node("remediator", remediator_agent)
workflow.add_node("remediation_tools", remediation_tool_node)
workflow.add_node("verifier", verifier_agent)
workflow.add_node("verify_tools", verify_tool_node)

# 2. Set Entry Point
workflow.set_entry_point("orchestrator")

# 3. Connect Edges
workflow.add_edge("orchestrator", "report_generator")
workflow.add_edge("report_generator", "safety_gate")
workflow.add_edge("safety_gate", "remediator")

# Remediation Loop
workflow.add_conditional_edges(
    "remediator",
    should_remediate_continue,
    {"remediation_tools": "remediation_tools", "verifier": "verifier"},
)
workflow.add_edge("remediation_tools", "remediator")

# Verification Loop
workflow.add_conditional_edges(
    "verifier",
    should_verify_continue,
    {"verify_tools": "verify_tools", "end": END},
)
workflow.add_edge("verify_tools", "verifier")

# 4. Compile
memory = MemorySaver()

app = workflow.compile(checkpointer=memory, interrupt_before=["remediator"])

import sys
import uuid
from agents.graph import app
import datetime
from mcp_server.database import update_scan
from langchain_core.messages import HumanMessage, AIMessage


def run_interactive_session():
    """
    Main execution loop for AEGIS-FLOW.
    Handles the Audit -> Pause -> Remediation workflow.
    """
    print("🚀 AEGIS-FLOW: SECURE AGENTIC ORCHESTRATION INITIALIZED")
    print("=======================================================")

    # 1. Generate scan ID first so it can be used as the LangGraph thread ID.
    # Each scan gets its own thread — prevents state bleed between concurrent runs.
    scan_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"

    # recursion_limit caps tool-call loops so a misbehaving agent can't run forever
    config = {"configurable": {"thread_id": scan_id}, "recursion_limit": 25}

    # 2. Initial Input
    print(f"\n[SYSTEM] Initializing Audit Scan: {scan_id}")
    initial_input = {
        "messages": [HumanMessage(content="Start the security audit.")],
        "safety_decision": "pending",
        "scan_id": scan_id,
        "total_tokens": 0,
        "findings_count": 0,
    }

    # 3. RUN: Phase 1 (Audit)
    try:
        for event in app.stream(initial_input, config, stream_mode="values"):
            message = event["messages"][-1]
            if hasattr(message, "content") and message.content:
                tool_calls = getattr(message, "tool_calls", [])
                if not tool_calls:
                    if isinstance(message, AIMessage):
                        sender = (
                            "AUDITOR" if "Auditor" in str(message.content) else "AGENT"
                        )
                        if isinstance(message.content, list):
                            text_to_print = " ".join(p.get("text", "") for p in message.content if isinstance(p, dict)).strip()
                        else:
                            text_to_print = str(message.content)
                    else:
                        sender = "USER"
                        text_to_print = message.content
                    print(f"\n[{sender}]: {text_to_print}")
    except Exception as e:
        import traceback

        traceback.print_exc()
        print(f"Error during audit: {e}")
        return

    # 4. PAUSE: Check State at Interrupt
    snapshot = app.get_state(config)

    if not snapshot.next:
        print(
            "\n[SYSTEM] Process finished without interruption (No risks found or Error)."
        )
        return

    # Extract the Audit Summary
    audit_summary = snapshot.values.get("audit_summary", "No summary provided.")

    audit_summary_str = str(audit_summary)

    if "SYSTEM SECURE" in audit_summary_str:
        print("\n" + "=" * 60)
        print("✅ AUDIT CONCLUSION: SYSTEM SECURE")
        print("=" * 60)
        print("\n[SYSTEM] No remediation actions required. Exiting process.")
        print("=======================================================")
        # TELEMETRY: Finalize scan even if system is already secure
        end_time = datetime.datetime.now().isoformat()
        update_scan(scan_id, 
                    status="COMPLETED", 
                    end_time=end_time,
                    total_tokens=snapshot.values.get("total_tokens", 0))
        
        return  # <--- AUTO-EXIT HERE

    # 5. IF NOT SECURE -> SAFETY GATE
    print("\n" + "=" * 60)
    print("🛑 SAFETY GATE: HUMAN INTERVENTION REQUIRED")
    print("=" * 60)
    print(f"\n📝 AUDIT FINDINGS:\n{audit_summary}")
    print("-" * 60)

    # 6. INPUT: Human Decision
    user_decision = (
        input(
            "\n>>> Do you authorize remediation? (Type 'approve' to proceed, anything else to abort): "
        )
        .strip()
        .lower()
    )

    if user_decision != "approve":
        print("\n❌ Permission Denied. Aborting execution.")
        
        # TELEMETRY: Mark as Aborted so it counts as a finished session
        end_time = datetime.datetime.now().isoformat()
        update_scan(scan_id, status="ABORTED", end_time=end_time)
        return

    # 7. RESUME: Phase 2 (Remediation & Verification)
    print("\n✅ Permission Granted. Resuming Workflow...")
    app.update_state(config, {"safety_decision": "approve"})

    for event in app.stream(None, config, stream_mode="values"):
        message = event["messages"][-1]
        
        # skip if message is not something to print
        if not hasattr(message, "content") or not message.content:
            continue
            
        tool_calls = getattr(message, "tool_calls", [])
        if tool_calls:
            # Check if this message came from the Verifier vs Remediator
            # (We look at the message's position or context, usually verifier comes after remediation report)
            is_verifier = any("VERIFIER" in str(msg.content) for msg in event["messages"][-5:])
            label = "VERIFIER" if is_verifier else "REMEDIATOR"
            
            for tc in tool_calls:
                print(f"\n[{label}]: 🛠️  EXECUTING CHECK: {tc['name']}...")
        else:
            if isinstance(message.content, list):
                text_to_print = " ".join(p.get("text", "") for p in message.content if isinstance(p, dict)).strip()
            else:
                text_to_print = str(message.content)

            # Skip messages we've already seen or that aren't from the AI
            if not isinstance(message, AIMessage):
                continue
            
            # Identify the sender based on content or role
            # (Simple heuristic: if it mentions 'REMEDIATION REPORT' it's the Remediator)
            if "REMEDIATION REPORT" in str(text_to_print):
                sender = "REMEDIATOR"
            elif "🏆 MISSION" in str(text_to_print) or "VER verification" in str(text_to_print).lower():
                sender = "VERIFIER"
            elif "AUDITOR" in str(text_to_print):
                 sender = "AUDITOR"
            else:
                sender = "AGENT"

            print(f"\n[{sender}]: {text_to_print}")

    print("\n=======================================================")
    print("🏁 AEGIS-FLOW WORKFLOW COMPLETE")
    print("=======================================================")


if __name__ == "__main__":
    run_interactive_session()

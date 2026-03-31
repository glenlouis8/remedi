from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
import json
import os
from dotenv import load_dotenv

from agents.state import AgentState
from agents.mcp_client import get_all_tools, get_tools_by_name
from mcp_server.database import start_scan, update_scan, log_remediation
import datetime

load_dotenv()

llm = ChatGoogleGenerativeAI(model="gemini-3-flash-preview", temperature=0)

# --- LOAD TOOLS VIA MCP PROTOCOL ---
# Tools are served by mcp_server/main.py running as a subprocess.
# The agent communicates with it via JSON-RPC over stdio (the MCP protocol).
_all_tools = get_all_tools()
_tools_by_name = get_tools_by_name()

AUDIT_TOOL_NAMES = {
    "get_agent_identity", "list_iam_users", "list_attached_user_policies",
    "list_s3_buckets", "check_s3_security", "audit_vpc_network",
    "audit_security_groups", "audit_ec2_vulnerabilities", "get_resource_owner",
    "audit_rds_instances", "audit_lambda_permissions", "audit_cloudtrail_logging",
}

REMEDIATION_TOOL_NAMES = {
    "restrict_iam_user", "remediate_s3", "remediate_vpc_flow_logs",
    "revoke_security_group_ingress", "enforce_imdsv2", "stop_instance",
    "remediate_rds_public_access", "remediate_lambda_role", "remediate_cloudtrail",
}

# 1. READ-ONLY AUDIT TOOLS
audit_tools_list = [t for t in _all_tools if t.name in AUDIT_TOOL_NAMES]

# 2. DANGEROUS REMEDIATION TOOLS
remediation_tools_list = [t for t in _all_tools if t.name in REMEDIATION_TOOL_NAMES]

# Bind tools to the appropriate model
audit_llm = llm.bind_tools(audit_tools_list)
remediation_llm = llm.bind_tools(remediation_tools_list)

# --- NODES ---


def auditor_agent(state: AgentState):
    """
    Phase 1: Discovery & Forensics.
    """
    print("--- [NODE] AUDITOR AGENT ---")
    messages = state["messages"]

    protected_raw = os.environ.get("PROTECTED_IAM_USERS", "").strip()
    protected_users = [u.strip() for u in protected_raw.split(",") if u.strip()] if protected_raw else []
    protected_clause = (
        f"\n\nPROTECTED RESOURCES — the account owner has marked the following IAM users/roles as admin accounts that must never be flagged or remediated. "
        f"Skip them entirely during audit:\n" + "\n".join(f"  - {u}" for u in protected_users)
        if protected_users else ""
    )

    system_msg = SystemMessage(
        content=(
            "You are a cloud security auditor. Your job is to scan this AWS account for security vulnerabilities and report findings clearly.\n\n"
            "SCAN THESE SERVICES IN ORDER:\n"
            "1. IAM — call `list_iam_users`, then `list_attached_user_policies` for EVERY user found. "
            "Flag any user with AdministratorAccess or PowerUserAccess as a CRITICAL finding.\n"
            "2. S3 — call `list_s3_buckets`, then `check_s3_security` for each bucket. Flag any publicly accessible bucket.\n"
            "3. VPC — call `audit_vpc_network`. Flag any VPC with flow logs disabled.\n"
            "4. Security Groups — call `audit_security_groups`. Flag any group allowing 0.0.0.0/0 inbound access.\n"
            "5. EC2 — call `audit_ec2_vulnerabilities`. Flag instances with IMDSv1 enabled or unencrypted root volumes.\n"
            "6. RDS — call `audit_rds_instances`. Flag any publicly accessible database.\n"
            "7. Lambda — call `audit_lambda_permissions`. Flag any function with an over-permissioned execution role.\n"
            "8. CloudTrail — call `audit_cloudtrail_logging`. Flag if logging is disabled or no trails exist.\n\n"
            "For each finding, note the resource name, service, and what the risk is. "
            "Be factual and concise. Do not invent findings."
            + protected_clause
        )
    )

    # Ensure system message is first
    if not messages or not isinstance(messages[0], SystemMessage):
        messages = [system_msg] + messages

    # Start the scan in DB
    scan_id = state.get("scan_id", "UNKNOWN")
    start_scan(scan_id)

    response = audit_llm.invoke(messages)
    
    # TELEMETRY: Tokens
    tokens = response.usage_metadata.get("total_tokens", 0) if hasattr(response, "usage_metadata") and response.usage_metadata else 0
    update_scan(scan_id, total_tokens=state.get("total_tokens", 0) + tokens)

    return {"messages": [response], "total_tokens": tokens}


def report_generator_node(state: AgentState):
    """
    Phase 2: Synthesis.
    Applies 'Insider Threat' policy and handles the 'SYSTEM SECURE' exit condition.
    """
    print("--- [NODE] REPORT GENERATOR ---")
    messages = state["messages"]

    # TOKEN OPTIMIZATION: The auditor's final message (last in the list) is its text
    # summary — all the intermediate tool call/result pairs before it are noise here.
    last_auditor_msg = messages[-1] if messages else HumanMessage(content="No audit data.")

    protected_raw = os.environ.get("PROTECTED_IAM_USERS", "").strip()
    protected_users = [u.strip() for u in protected_raw.split(",") if u.strip()] if protected_raw else []
    protected_clause = (
        f"\n\nIMPORTANT: The following IAM users/roles are protected by the account owner and must NOT appear in the remediation plan under any circumstances:\n"
        + "\n".join(f"  - {u}" for u in protected_users)
        if protected_users else ""
    )

    summary_prompt = HumanMessage(
        content=(
            "Review the audit findings above and produce a remediation plan.\n\n"
            "If there are NO findings, respond with exactly this and nothing else:\n"
            "'✅ SYSTEM SECURE. No remediation actions required.'\n\n"
            "If there ARE findings, map each one to the correct tool using ONLY these mappings:\n"
            "- IAM user with AdministratorAccess or PowerUserAccess → `restrict_iam_user`\n"
            "- Publicly accessible S3 bucket → `remediate_s3`\n"
            "- VPC with flow logs disabled → `remediate_vpc_flow_logs`\n"
            "- Security group with 0.0.0.0/0 inbound → `revoke_security_group_ingress`\n"
            "- EC2 instance with IMDSv1 enabled → `enforce_imdsv2`\n"
            "- EC2 instance with unencrypted root volume → `stop_instance`\n"
            "- RDS instance that is publicly accessible → `remediate_rds_public_access`\n"
            "- Lambda with over-permissioned execution role → `remediate_lambda_role`\n"
            "- CloudTrail logging disabled → `remediate_cloudtrail`\n\n"
            "Output one line per finding in exactly this format:\n"
            "🔴 [CRITICAL] <resource name> is vulnerable -> ACTION: I will call `<tool name>`.\n\n"
            "Do not invent findings. Only include resources that were actually flagged in the audit."
            + protected_clause
        )
    )

    # Pass only the auditor's final summary — saves ~80% of tokens vs full history
    response = llm.invoke([last_auditor_msg, summary_prompt])

    # TELEMETRY: Tokens
    tokens = response.usage_metadata.get("total_tokens", 0) if hasattr(response, "usage_metadata") and response.usage_metadata else 0
    scan_id = state.get("scan_id", "UNKNOWN")

    clean_content = str(response.content)
    # Count unique tool calls in the plan (not 🔴 symbols — the same tool can be
    # mentioned multiple times for the same resource e.g. restrict_iam_user for
    # both the policy violation and insider threat finding on the same user)
    import re
    tool_calls_in_plan = re.findall(r'I will call `?(\w+)`?', clean_content)
    findings_count = len(set(tool_calls_in_plan)) if tool_calls_in_plan else clean_content.count("🔴")

    # Single update call instead of two
    update_scan(scan_id, findings_count=findings_count, total_tokens=state.get("total_tokens", 0) + tokens)

    print(f"[DEBUG] Generated Report: {clean_content}")
    return {"audit_summary": clean_content, "messages": [response], "total_tokens": tokens, "findings_count": findings_count}


def safety_gate_node(state: AgentState):
    """
    Phase 3: The Checkpoint.
    Checks if the system is secure. If so, skips the scary 'PAUSE' message.
    """
    summary = state.get("audit_summary", "No summary")
    
    summary_str = str(summary)
    update_scan(state.get("scan_id", "UNKNOWN"), gate_time=datetime.datetime.now().isoformat())

    # Check for the magic "SYSTEM SECURE" string from the Report Generator
    if "SYSTEM SECURE" in summary_str:
        print("\n>>> AUDIT COMPLETE: ✅ SYSTEM SECURE. No risks detected.")
        print(">>> SKIPPING HUMAN REVIEW (Nothing to fix).\n")
        return {}

    print(f"\n>>> AUDIT COMPLETE. FINDINGS: \n{summary_str}\n")
    print(">>> PAUSING FOR HUMAN REVIEW. (Remediation will strictly NOT proceed without approval).")
    return {}


def remediator_agent(state: AgentState):
    """
    Phase 4: Enforcement.
    Executes fixes ONLY if safety_decision is 'approve'.
    """
    print("--- [NODE] REMEDIATOR AGENT ---")
    summary = state.get("audit_summary", "")
    decision = state.get("safety_decision", "deny")

    # 1. HARD SAFETY CHECK
    if decision.lower() != "approve":
        return {
            "messages": [
                AIMessage(
                    content=f"SAFETY BLOCK: User decision was '{decision}'. Remediation aborted."
                )
            ]
        }

    # 2. DISPATCH TABLE: Map string names to MCP tool objects
    # Tool calls are routed through the MCP protocol to the server subprocess.
    FUNCTION_DISPATCH = {
        name: tool for name, tool in _tools_by_name.items()
        if name in REMEDIATION_TOOL_NAMES
    }

    # 3. INTENT MAPPING: Map AI's guessed names to valid keys in FUNCTION_DISPATCH
    INTENT_MAP = {
        # Network aliases
        "enable_vpc_flow_logs": "remediate_vpc_flow_logs",
        "remediate_security_group": "revoke_security_group_ingress",
        # Compute aliases
        "stop_ec2_instance": "stop_instance",
        "remediate_ec2_vulnerabilities": "stop_instance",
        # Storage aliases
        "set_s3_bucket_private": "remediate_s3",
        "remediate_s3_bucket": "remediate_s3",
        "remediate_s3_public_access": "remediate_s3",
        # RDS aliases
        "disable_rds_public_access": "remediate_rds_public_access",
        "remediate_rds": "remediate_rds_public_access",
        # Lambda aliases
        "fix_lambda_permissions": "remediate_lambda_role",
        "remediate_lambda": "remediate_lambda_role",
        # CloudTrail aliases
        "enable_cloudtrail": "remediate_cloudtrail",
        "fix_cloudtrail": "remediate_cloudtrail",
    }

    # 4. PARSE PLAN
    parser_prompt = SystemMessage(
        content=(
            "You are a strict JSON-only plan parser. Convert the remediation plan into a JSON object.\n\n"
            "CRITICAL RULES:\n"
            "- Output ONLY raw JSON. No markdown, no code blocks, no explanation.\n"
            "- Use ONLY tool names from this exact list: " + ", ".join(INTENT_MAP.keys()) + "\n\n"
            "Output format:\n"
            '{"tools": [{"name": "<tool_name>", "args": {"<arg_name>": "<arg_value>"}}]}\n\n'
            "Exact argument names per tool:\n"
            "- restrict_iam_user: {\"user_name\": \"<username>\"}\n"
            "- remediate_s3: {\"bucket_name\": \"<bucket>\"}\n"
            "- remediate_vpc_flow_logs: {\"vpc_id\": \"<vpc-id>\"}\n"
            "- revoke_security_group_ingress: {\"group_id\": \"<sg-id>\", \"protocol\": \"tcp\", \"from_port\": 22, \"to_port\": 22}\n"
            "- enforce_imdsv2: {\"instance_id\": \"<instance-id>\"}\n"
            "- stop_instance: {\"instance_id\": \"<instance-id>\"}\n"
        )
    )

    # Pass only the audit summary — no need for the full message history
    parser_input = HumanMessage(content=f"REMEDIATION PLAN TO PARSE:\n{summary}")

    try:
        scan_id = state.get("scan_id", "UNKNOWN")
        raw_response = llm.invoke([parser_prompt, parser_input])

        # TELEMETRY: Tokens
        tokens = raw_response.usage_metadata.get("total_tokens", 0) if hasattr(raw_response, "usage_metadata") and raw_response.usage_metadata else 0
        update_scan(scan_id, total_tokens=state.get("total_tokens", 0) + tokens)

        # Extract the JSON object — handles markdown wrappers and surrounding text
        raw_text = str(raw_response.content)
        start = raw_text.find("{")
        end = raw_text.rfind("}") + 1
        raw_text = raw_text[start:end] if start != -1 else raw_text

        plan_json = json.loads(raw_text)

        results = []
        success_count = 0

        # 5. EXECUTION LOOP
        tool_list = plan_json.get("tools", [])
        print(f"[DEBUG] Found {len(tool_list)} tasks. Starting direct execution...")

        for task in tool_list:
            ai_name = task["name"]
            args = task["args"]
            start_time = datetime.datetime.now()

            # Resolve to actual function
            real_func_name = INTENT_MAP.get(ai_name, ai_name)
            func_to_call = FUNCTION_DISPATCH.get(real_func_name)

            if "security_group_id" in args:
                args["group_id"] = args.pop("security_group_id")

            # --- ARGUMENT PATCHING FOR SECURITY GROUPS ---
            if real_func_name == "revoke_security_group_ingress":
                args.pop("cidr_ip", None)
                # Ensure required args exist, defaulting to standard SSH suppression
                if "protocol" not in args:
                    args["protocol"] = "tcp"
                if "from_port" not in args:
                    args["from_port"] = 22
                if "to_port" not in args:
                    args["to_port"] = 22
            # ---------------------------------------------

            if func_to_call:
                # Filter args against the tool's MCP schema to drop any hallucinated keys
                valid_args = {k: v for k, v in args.items() if k in func_to_call.args}

                print(f"[EXEC] Calling {real_func_name} with {valid_args}...")
                try:
                    # Call the tool via the MCP protocol (JSON-RPC over stdio)
                    result_str = func_to_call.invoke(valid_args)
                    results.append(f"✅ {result_str}")
                    success_count += 1
                    status = "SUCCESS"
                except Exception as e:
                    results.append(f"❌ Error executing {real_func_name}: {str(e)}")
                    status = "ERROR"
            else:
                results.append(f"⚠️ Unknown tool mapping: {ai_name}")
                status = "UNKNOWN_TOOL"
            
            # TELEMETRY: Log Remediation Event
            duration = (datetime.datetime.now() - start_time).total_seconds()
            resource = args.get("bucket_name") or args.get("instance_id") or args.get("vpc_id") or args.get("group_id") or "unspecified"
            log_remediation(scan_id, resource, real_func_name, status, duration)

        # 6. REPORTING
        update_scan(scan_id, remediations_count=success_count)
        full_summary = "### 🛠️ REMEDIATION REPORT\n" + "\n".join(results)
        return {"messages": [AIMessage(content=full_summary)], "total_tokens": tokens}

    except Exception as e:
        print(f"[ERROR] Remediation failure: {e}")
        update_scan(scan_id, status="FAILED")
        return {"messages": [AIMessage(content=f"Critical Agent Failure: {str(e)}")]}


def verifier_agent(state: AgentState):
    """
    Phase 5: Self-Correction.
    Re-runs audit tools to ensure the environment is now actually secure.
    """
    print("--- [NODE] VERIFIER AGENT ---")
    messages = state["messages"]

    system_msg = SystemMessage(
        content=(
            "You are a security verifier. Your job is to confirm that the remediation steps were successful.\n"
            "1. Review the remediation report to see what was fixed.\n"
            "2. Re-run the relevant audit tools to check the current state of those resources.\n"
            "3. If any vulnerability still exists, report it as a 'VERIFICATION FAILURE' with details.\n"
            "4. If all fixes are confirmed, respond with exactly:\n"
            "'🏆 MISSION ACCOMPLISHED. All resources verified as SECURE.'"
        )
    )

    # Pass the remediation report + everything after it (tool call results from
    # previous verification iterations). Without this, Claude never sees its own
    # tool results and loops forever calling the same tools repeatedly.
    report_idx = next(
        (len(messages) - 1 - i for i, m in enumerate(reversed(messages))
         if isinstance(m, AIMessage) and "REMEDIATION REPORT" in str(m.content)),
        None
    )
    context = messages[report_idx:] if report_idx is not None else (messages[-1:] if messages else [HumanMessage(content="No remediation report found.")])

    response = audit_llm.invoke([system_msg] + context)
    
    # TELEMETRY: Tokens
    tokens = response.usage_metadata.get("total_tokens", 0) if hasattr(response, "usage_metadata") and response.usage_metadata else 0
    scan_id = state.get("scan_id", "UNKNOWN")
    
    verified = "MISSION ACCOMPLISHED" in str(response.content)
    status = "COMPLETED" if verified else "FAILED"
    end_time = datetime.datetime.now().isoformat()
    
    # Cost estimate: blended Haiku ($0.80/1M) + Sonnet ($3/1M) tokens
    # Using $0.0000015 per token as a conservative blended rate
    total_tokens_so_far = state.get("total_tokens", 0) + tokens
    cost = total_tokens_so_far * 0.0000015
    
    update_scan(scan_id,
                total_tokens=total_tokens_so_far,
                status=status,
                end_time=end_time,
                estimated_cost=cost,
                verified=verified)

    return {"messages": [response], "total_tokens": tokens}

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage, ToolMessage
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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



def _run_sub_agent(service: str, prompt: str, tools: list, protected_clause: str) -> tuple:
    """
    Runs a single specialist sub-agent synchronously inside a thread.
    Handles its own tool loop and Gemini rate-limit retries.
    Returns (service_name, findings_text, total_tokens).
    """
    llm_with_tools = llm.bind_tools(tools)
    messages = [
        SystemMessage(content=prompt + protected_clause),
        HumanMessage(content="Begin your audit now."),
    ]
    total_tokens = 0

    while True:
        for attempt in range(3):
            try:
                response = llm_with_tools.invoke(messages)
                break
            except Exception as e:
                if "429" in str(e) and attempt < 2:
                    print(f"[{service}] Rate limited — retrying in 10s ({attempt + 1}/2)...")
                    time.sleep(10)
                else:
                    raise

        messages.append(response)
        tokens = (response.usage_metadata or {}).get("total_tokens", 0) if hasattr(response, "usage_metadata") else 0
        total_tokens += tokens

        if not response.tool_calls:
            break

        for tc in response.tool_calls:
            tool = _tools_by_name.get(tc["name"])
            if tool:
                try:
                    result = tool.invoke(tc["args"])
                    messages.append(ToolMessage(content=str(result), tool_call_id=tc["id"], name=tc["name"]))
                except Exception as e:
                    messages.append(ToolMessage(content=f"Error: {e}", tool_call_id=tc["id"], name=tc["name"]))
            else:
                messages.append(ToolMessage(content=f"Unknown tool: {tc['name']}", tool_call_id=tc["id"], name=tc["name"]))

    if isinstance(response.content, list):
        text = " ".join(p.get("text", "") for p in response.content if isinstance(p, dict)).strip()
    else:
        text = str(response.content)

    return service, text, total_tokens


_SPECIALIST_CONFIGS = [
    {
        "service": "IAM",
        "tool_names": {"get_agent_identity", "list_iam_users", "list_attached_user_policies", "get_resource_owner"},
        "prompt": (
            "You are an IAM security specialist. Audit this AWS account's IAM configuration.\n"
            "1. Call `list_iam_users` to get all users.\n"
            "2. Call `list_attached_user_policies` for EVERY user found.\n"
            "3. Flag any user with AdministratorAccess or PowerUserAccess as CRITICAL.\n"
            "Return a concise findings summary. If nothing is wrong, say 'IAM: No issues found.'"
        ),
    },
    {
        "service": "S3",
        "tool_names": {"list_s3_buckets", "check_s3_security"},
        "prompt": (
            "You are an S3 security specialist. Audit this AWS account's S3 buckets.\n"
            "1. Call `list_s3_buckets` to get all buckets.\n"
            "2. Call `check_s3_security` for each bucket.\n"
            "3. Flag any publicly accessible bucket as CRITICAL.\n"
            "Return a concise findings summary. If nothing is wrong, say 'S3: No issues found.'"
        ),
    },
    {
        "service": "VPC",
        "tool_names": {"audit_vpc_network"},
        "prompt": (
            "You are a VPC network security specialist. Audit this AWS account's VPC configuration.\n"
            "1. Call `audit_vpc_network`.\n"
            "2. Flag any VPC with flow logs disabled as HIGH severity.\n"
            "Return a concise findings summary. If nothing is wrong, say 'VPC: No issues found.'"
        ),
    },
    {
        "service": "Security Groups",
        "tool_names": {"audit_security_groups"},
        "prompt": (
            "You are a network security specialist. Audit this AWS account's security groups.\n"
            "1. Call `audit_security_groups`.\n"
            "2. Flag any group allowing 0.0.0.0/0 inbound access as HIGH severity.\n"
            "Return a concise findings summary. If nothing is wrong, say 'Security Groups: No issues found.'"
        ),
    },
    {
        "service": "EC2",
        "tool_names": {"audit_ec2_vulnerabilities"},
        "prompt": (
            "You are an EC2 security specialist. Audit this AWS account's EC2 instances.\n"
            "1. Call `audit_ec2_vulnerabilities`.\n"
            "2. Flag instances with IMDSv1 enabled or unencrypted root volumes.\n"
            "Return a concise findings summary. If nothing is wrong, say 'EC2: No issues found.'"
        ),
    },
    {
        "service": "RDS",
        "tool_names": {"audit_rds_instances"},
        "prompt": (
            "You are an RDS security specialist. Audit this AWS account's RDS databases.\n"
            "1. Call `audit_rds_instances`.\n"
            "2. Flag any publicly accessible database as CRITICAL.\n"
            "Return a concise findings summary. If nothing is wrong, say 'RDS: No issues found.'"
        ),
    },
    {
        "service": "Lambda",
        "tool_names": {"audit_lambda_permissions"},
        "prompt": (
            "You are a Lambda security specialist. Audit this AWS account's Lambda functions.\n"
            "1. Call `audit_lambda_permissions`.\n"
            "2. Flag any function with an over-permissioned execution role.\n"
            "Return a concise findings summary. If nothing is wrong, say 'Lambda: No issues found.'"
        ),
    },
    {
        "service": "CloudTrail",
        "tool_names": {"audit_cloudtrail_logging"},
        "prompt": (
            "You are a CloudTrail security specialist. Audit this AWS account's logging configuration.\n"
            "1. Call `audit_cloudtrail_logging`.\n"
            "2. Flag if logging is disabled or no trails exist.\n"
            "Return a concise findings summary. If nothing is wrong, say 'CloudTrail: No issues found.'"
        ),
    },
]


def orchestrator_node(state: AgentState):
    """
    Phase 1: Parallel Discovery.
    Fires 8 specialist sub-agents simultaneously — one per AWS service.
    Merges their findings into a single report for the Report Generator.
    """
    print("--- [NODE] ORCHESTRATOR (parallel scan) ---")

    protected_raw = os.environ.get("PROTECTED_IAM_USERS", "").strip()
    protected_users = [u.strip() for u in protected_raw.split(",") if u.strip()] if protected_raw else []
    protected_clause = (
        "\n\nPROTECTED: The following IAM users are marked as admin accounts by the account owner. "
        "Skip them entirely — do not flag or report on them:\n"
        + "\n".join(f"  - {u}" for u in protected_users)
        if protected_users else ""
    )

    scan_id = state.get("scan_id", "UNKNOWN")
    start_scan(scan_id)

    tasks = [
        (
            config["service"],
            config["prompt"],
            [t for t in audit_tools_list if t.name in config["tool_names"]],
            protected_clause,
        )
        for config in _SPECIALIST_CONFIGS
    ]

    _SVC_KEY = {
        "IAM": "iam", "S3": "s3", "VPC": "vpc", "Security Groups": "sg",
        "EC2": "ec2", "RDS": "rds", "Lambda": "lambda", "CloudTrail": "cloudtrail",
    }

    findings: dict[str, str] = {}
    total_tokens = 0

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(_run_sub_agent, *task): task[0] for task in tasks}
        for future in as_completed(futures):
            service = futures[future]
            try:
                svc, text, tokens = future.result()
                findings[svc] = text
                total_tokens += tokens
                svc_key = _SVC_KEY.get(svc, svc.lower())
                has_issues = any(kw in text.upper() for kw in ["CRITICAL", "VULNERABLE", "VIOLATION", "EXPOSED", "PUBLIC", "WARNING", "RISK"])
                status = "vulnerable" if has_issues else "ok"
                first_line = next((l.strip() for l in text.split("\n") if l.strip() and len(l.strip()) > 10), "Scan complete")
                print(f"[SCAN] {json.dumps({'service': svc_key, 'resource': svc, 'status': status, 'msg': first_line[:120]})}", flush=True)
            except Exception as e:
                findings[service] = f"{service}: scan failed — {e}"
                svc_key = _SVC_KEY.get(service, service.lower())
                print(f"[SCAN] {json.dumps({'service': svc_key, 'resource': service, 'status': 'error', 'msg': str(e)[:120]})}", flush=True)

    order = ["IAM", "S3", "VPC", "Security Groups", "EC2", "RDS", "Lambda", "CloudTrail"]
    combined = "\n\n".join(
        f"=== {svc} ===\n{findings.get(svc, 'No data.')}" for svc in order
    )

    update_scan(scan_id, total_tokens=total_tokens)
    print(f"[ORCHESTRATOR] All services scanned. Total tokens: {total_tokens}")

    return {"messages": [AIMessage(content=combined)], "total_tokens": total_tokens}


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

    if isinstance(response.content, list):
        clean_content = " ".join(
            part.get("text", "") for part in response.content if isinstance(part, dict)
        ).strip()
    else:
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
    print("[ACTION_REQUIRED] WAITING_FOR_APPROVAL", flush=True)
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

    # 4. TOOL → ARGUMENT KEY MAP
    # Maps each tool name to the arg name its resource goes into
    TOOL_ARG_MAP = {
        "restrict_iam_user":           "user_name",
        "remediate_s3":                "bucket_name",
        "remediate_vpc_flow_logs":     "vpc_id",
        "revoke_security_group_ingress": "group_id",
        "enforce_imdsv2":              "instance_id",
        "stop_instance":               "instance_id",
        "remediate_rds_public_access": "db_instance_identifier",
        "remediate_lambda_role":       "function_name",
        "remediate_cloudtrail":        "trail_name",
    }

    scan_id = state.get("scan_id", "UNKNOWN")

    try:
        # 5. REGEX PARSE — no LLM call, no JSON, no latency
        import re
        pattern = re.compile(
            r'🔴 \[CRITICAL\] (.+?) is vulnerable -> ACTION: I will call [`\'"]?(\w+)[`\'"]?'
        )
        tasks = []
        for match in pattern.finditer(summary):
            resource  = match.group(1).strip()
            tool_name = match.group(2).strip()
            real_name = INTENT_MAP.get(tool_name, tool_name)
            func      = FUNCTION_DISPATCH.get(real_name)
            arg_key   = TOOL_ARG_MAP.get(real_name)
            tasks.append((resource, real_name, func, {arg_key: resource} if arg_key else {}))

        print(f"[DEBUG] Parsed {len(tasks)} tasks. Starting parallel execution...")

        # 6. PARALLEL EXECUTION
        def _run_task(resource, real_name, func, args):
            start_time = datetime.datetime.now()
            if func is None:
                return resource, real_name, args, f"⚠️ Unknown tool: {real_name}", "UNKNOWN_TOOL", 0.0
            if "security_group_id" in args:
                args["group_id"] = args.pop("security_group_id")
            valid_args = {k: v for k, v in args.items() if k in func.args}
            print(f"[EXEC] Calling {real_name} with {valid_args}...")
            try:
                result_str = func.invoke(valid_args)
                duration = (datetime.datetime.now() - start_time).total_seconds()
                return resource, real_name, args, f"✅ {result_str}", "SUCCESS", duration
            except Exception as e:
                duration = (datetime.datetime.now() - start_time).total_seconds()
                return resource, real_name, args, f"❌ {real_name}: {str(e)}", "ERROR", duration

        results = []
        success_count = 0

        with ThreadPoolExecutor(max_workers=max(len(tasks), 1)) as executor:
            futures = [executor.submit(_run_task, *t) for t in tasks]
            for future in as_completed(futures):
                resource, real_name, args, message, status, duration = future.result()
                results.append(message)
                if status == "SUCCESS":
                    success_count += 1
                resource_id = (
                    args.get("user_name") or args.get("bucket_name") or
                    args.get("instance_id") or args.get("vpc_id") or
                    args.get("group_id") or args.get("db_instance_identifier") or
                    args.get("function_name") or resource
                )
                log_remediation(scan_id, resource_id, real_name, status, duration)

        # 7. REPORTING
        update_scan(scan_id, remediations_count=success_count)
        full_summary = "### 🛠️ REMEDIATION REPORT\n" + "\n".join(results)
        return {"messages": [AIMessage(content=full_summary)], "total_tokens": 0}

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
            "1. Read the remediation report carefully to identify exactly which resources were fixed.\n"
            "2. Re-run audit tools ONLY for those specific resources — do NOT scan anything else.\n"
            "   Only use resource names and IDs that appear in the remediation report.\n"
            "   Never invent or guess resource names.\n"
            "3. If a fixed resource is still vulnerable, report 'VERIFICATION FAILURE' with details.\n"
            "4. If every fixed resource is now clean, respond with exactly:\n"
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

    # If the remediator failed, there's nothing to verify — exit immediately
    if report_idx is None:
        scan_id = state.get("scan_id", "UNKNOWN")
        end_time = datetime.datetime.now().isoformat()
        update_scan(scan_id, status="FAILED", end_time=end_time)
        return {"messages": [AIMessage(content="VERIFICATION SKIPPED: Remediator failed — no fixes were applied.")]}

    context = messages[report_idx:]
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

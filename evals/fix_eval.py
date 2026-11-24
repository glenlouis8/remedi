"""
Fix + verify eval: after remediation, are the planted holes REALLY closed, and
does Remedi's verifier tell the truth about it?

Runs the real LangGraph pipeline (live Gemini, live AWS) against the terraform
test environment, with the MCP server replaced by in-process tools and the DB
stubbed. It approves ONLY the planted test resources, never anything else in the
account, then checks each fix directly with boto3 (independent of Remedi's own
tools) and compares against what the verifier claimed.

Worst outcome to catch: verifier says MISSION ACCOMPLISHED but something is
still open (false assurance).

Run (after `terraform apply`):  uv run python evals/fix_eval.py
"""
import json
import subprocess
import sys
import time
import uuid
from pathlib import Path
from unittest.mock import MagicMock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

sys.modules["mcp_server.database"] = MagicMock()

from langchain_core.tools import StructuredTool  # noqa: E402
from mcp_server import main as mcp_main  # noqa: E402

_tools = [
    StructuredTool.from_function(func=t.fn, name=t.name, description=t.description or t.name)
    for t in mcp_main.mcp._tool_manager.list_tools()
]
_stub = MagicMock()
_stub.get_all_tools.return_value = _tools
_stub.get_tools_by_name.return_value = {t.name: t for t in _tools}
sys.modules["agents.mcp_client"] = _stub

import boto3  # noqa: E402
from langchain_core.messages import HumanMessage  # noqa: E402
from agents.graph import app  # noqa: E402
from agents.patterns import REMEDIATION_LINE_PATTERN  # noqa: E402

REGION = "us-east-1"


def terraform_truth() -> dict:
    out = subprocess.run(["terraform", "output", "-json"], cwd=ROOT / "terraform",
                         capture_output=True, text=True, check=True).stdout
    return {k: v["value"] for k, v in json.loads(out).items()}


# ---- independent checks: True means the hole is closed --------------------

def closed_iam(t):
    iam = boto3.client("iam")
    names = [p["PolicyName"] for p in iam.list_attached_user_policies(UserName=t["iam_test_user"])["AttachedPolicies"]]
    return "AdministratorAccess" not in names and "PowerUserAccess" not in names


def closed_s3(t):
    c = boto3.client("s3", region_name=REGION).get_public_access_block(Bucket=t["s3_bucket_name"])["PublicAccessBlockConfiguration"]
    return all(c.values())


def closed_vpc(t):
    return bool(boto3.client("ec2", region_name=REGION).describe_flow_logs(
        Filters=[{"Name": "resource-id", "Values": [t["vpc_id"]]}])["FlowLogs"])


def closed_sg(t):
    sg = boto3.client("ec2", region_name=REGION).describe_security_groups(GroupIds=[t["security_group_id"]])["SecurityGroups"][0]
    return not any(r.get("CidrIp") == "0.0.0.0/0" for p in sg["IpPermissions"] for r in p.get("IpRanges", []))


def closed_ec2(t):
    inst = boto3.client("ec2", region_name=REGION).describe_instances(InstanceIds=[t["ec2_instance_id"]])["Reservations"][0]["Instances"][0]
    return inst["MetadataOptions"]["HttpTokens"] == "required" or inst["State"]["Name"] in ("stopped", "stopping")


def closed_rds(t):
    rds = boto3.client("rds", region_name=REGION)
    for _ in range(30):  # modification can take a few minutes to apply
        db = rds.describe_db_instances(DBInstanceIdentifier=t["rds_identifier"])["DBInstances"][0]
        if not db["PubliclyAccessible"]:
            return True
        time.sleep(10)
    return False


def closed_lambda(t):
    role = boto3.client("lambda", region_name=REGION).get_function(FunctionName=t["lambda_function_name"])["Configuration"]["Role"].split("/")[-1]
    names = [p["PolicyName"] for p in boto3.client("iam").list_attached_role_policies(RoleName=role)["AttachedPolicies"]]
    return "AdministratorAccess" not in names and "PowerUserAccess" not in names


# service -> (planted resource key, independent check)
CHECKS = {
    "IAM": ("iam_test_user", closed_iam),
    "S3": ("s3_bucket_name", closed_s3),
    "VPC": ("vpc_id", closed_vpc),
    "Security Groups": ("security_group_id", closed_sg),
    "EC2": ("ec2_instance_id", closed_ec2),
    "RDS": ("rds_identifier", closed_rds),
    "Lambda": ("lambda_function_name", closed_lambda),
}


def main():
    truth = terraform_truth()
    planted = {truth[k] for k, _ in CHECKS.values()}

    scan_id = f"EVAL-{uuid.uuid4().hex[:6].upper()}"
    config = {"configurable": {"thread_id": scan_id}, "recursion_limit": 40}
    state0 = {"messages": [HumanMessage(content="Start the security audit.")],
              "safety_decision": "pending", "scan_id": scan_id, "findings_count": 0}

    # Phase 1: scan until the graph pauses before remediation.
    for _ in app.stream(state0, config, stream_mode="values"):
        pass
    summary = app.get_state(config).values.get("audit_summary", "")
    plan = [(m.group(1).strip(), m.group(2)) for m in REMEDIATION_LINE_PATTERN.finditer(summary)]
    print(f"\nPLAN: {plan}")

    # Safety guard: approve ONLY planted test resources, never anything else.
    approved = sorted({r for r, _ in plan if r in planted})
    unplanted = sorted({r for r, _ in plan if r not in planted})
    if unplanted:
        print(f"NOT APPROVING (not planted test resources): {unplanted}")
    if not approved:
        print("FAIL: report listed none of the planted resources; nothing to fix.")
        sys.exit(1)

    # Phase 2: approve and run remediation + verification.
    app.update_state(config, {"safety_decision": "approve", "approved_resources": approved})
    for _ in app.stream(None, config, stream_mode="values"):
        pass
    final = app.get_state(config).values
    msgs = final["messages"]
    verdict = str(msgs[-1].content)
    outcomes = {}
    for m in msgs:
        for o in (getattr(m, "additional_kwargs", {}) or {}).get("remediation_outcomes", []):
            outcomes[o["resource"]] = o["status"]
    claimed_ok = "MISSION ACCOMPLISHED" in verdict
    print(f"\nVERIFIER SAID: {verdict[:200]!r}")

    # Independent ground truth.
    print("\nservice            remedi_status   truly_closed")
    truly = {}
    for svc, (key, check) in CHECKS.items():
        res = truth[key]
        try:
            ok = check(truth)
        except Exception as e:  # noqa: BLE001
            ok = False
            print(f"  (check error for {svc}: {e})")
        truly[svc] = ok
        print(f"{svc:18s} {outcomes.get(res, 'NOT RUN'):14s}  {ok}")

    all_closed = all(truly.values())
    print(f"\nFIXES THAT HELD: {sum(truly.values())}/{len(truly)}")
    if claimed_ok and not all_closed:
        print("!!! FALSE ASSURANCE: verifier said ACCOMPLISHED but something is still open")
    elif not claimed_ok and all_closed:
        print("verifier was too cautious: everything is closed but it did not confirm")
    else:
        print("verifier verdict matches reality")
    sys.exit(0 if all_closed and claimed_ok else 1)


if __name__ == "__main__":
    main()

"""
Judgment eval: do the specialists label tricky tool output correctly?

No AWS, no DB. Each case hands a real specialist (live Gemini call) a canned,
messy tool result: safe resources with scary names, a mix of risky and safe
items, API errors, empty results. We check it flags only what it should, with
the severity the prompt prescribes, and never invents or mislabels anything.

Run:  uv run python evals/judgment_eval.py [--runs 3] [--model gemini-3.8-flash] [--case NAME]
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from unittest.mock import MagicMock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

sys.modules["mcp_server.database"] = MagicMock()
_stub = MagicMock()
_stub.get_all_tools.return_value = []
_stub.get_tools_by_name.return_value = {}
sys.modules["agents.mcp_client"] = _stub

from langchain_core.tools import StructuredTool  # noqa: E402
from langchain_google_genai import ChatGoogleGenerativeAI  # noqa: E402
from agents import nodes  # noqa: E402
from agents.patterns import FINDING_PATTERN  # noqa: E402

J = json.dumps

# expect: {resource: severity}.  forbid: resources that must NOT be flagged.
# ambiguous: resources we don't score either way.
CASES = [
    {"name": "s3_scary_names_safe", "service": "S3",
     "tools": {"audit_s3_buckets": "BUCKET logs-public-site: PUBLIC RISK — public access block incomplete\nBUCKET my-public-docs: SECURE\nBUCKET backup-bucket: SECURE\nBUCKET prod-data: UNKNOWN — could not check public access (AccessDenied)"},
     "expect": {"logs-public-site": "CRITICAL"}, "forbid": ["my-public-docs", "backup-bucket"], "ambiguous": ["prod-data"]},
    {"name": "s3_all_secure", "service": "S3",
     "tools": {"audit_s3_buckets": "BUCKET alpha: SECURE\nBUCKET beta: SECURE"},
     "expect": {}, "forbid": ["alpha", "beta"]},
    {"name": "s3_api_error", "service": "S3",
     "tools": {"audit_s3_buckets": "Error auditing S3 buckets: An error occurred (AccessDenied) when calling the ListBuckets operation"},
     "expect": {}, "forbid": [], "expect_error_line": True},
    {"name": "vpc_mixed", "service": "VPC",
     "tools": {"audit_vpc_network": J([{"VpcId": "vpc-aaa111", "FlowLogs": "ENABLED", "CidrBlock": "10.0.0.0/16"}, {"VpcId": "vpc-bbb222", "FlowLogs": "DISABLED (Risk)", "CidrBlock": "172.31.0.0/16"}])},
     "expect": {"vpc-bbb222": "HIGH"}, "forbid": ["vpc-aaa111"]},
    {"name": "sg_same_group_two_ports", "service": "Security Groups",
     "tools": {"audit_security_groups": J([{"GroupId": "sg-1111", "Port": 22, "Protocol": "tcp", "Risk": "OPEN TO WORLD (0.0.0.0/0)"}, {"GroupId": "sg-1111", "Port": 80, "Protocol": "tcp", "Risk": "OPEN TO WORLD (0.0.0.0/0)"}])},
     "expect": {"sg-1111": "HIGH"}, "forbid": []},
    {"name": "sg_clean", "service": "Security Groups",
     "tools": {"audit_security_groups": J(["No risky Security Groups found. System is SAFE."])},
     "expect": {}, "forbid": []},
    {"name": "ec2_two_issues", "service": "EC2",
     "tools": {"audit_ec2_vulnerabilities": J([{"InstanceId": "i-0aaa", "Issues": ["IMDSv1 enabled", "unencrypted root volume"]}])},
     "expect": {"i-0aaa": "HIGH"}, "forbid": []},
    {"name": "ec2_none_running", "service": "EC2",
     "tools": {"audit_ec2_vulnerabilities": J(["No running instances found."])},
     "expect": {}, "forbid": []},
    {"name": "rds_name_trap", "service": "RDS",
     "tools": {"audit_rds_instances": J([{"DBInstanceIdentifier": "db-orders", "Engine": "postgres", "PubliclyAccessible": True, "DBInstanceStatus": "available"}, {"DBInstanceIdentifier": "db-public-replica", "Engine": "postgres", "PubliclyAccessible": False, "DBInstanceStatus": "available"}])},
     "expect": {"db-orders": "CRITICAL"}, "forbid": ["db-public-replica"]},
    {"name": "lambda_mixed", "service": "Lambda",
     "tools": {"audit_lambda_permissions": J([{"FunctionName": "admin-tools", "Role": "least-priv-role", "Issues": ["OK"], "OverPermissioned": False}, {"FunctionName": "billing-sync", "Role": "billing-role", "Issues": ["Attached: AdministratorAccess"], "OverPermissioned": True}, {"FunctionName": "mystery-fn", "Role": "x", "Issues": ["ROLE INSPECTION FAILED — unverified"], "OverPermissioned": None}])},
     "expect": {"billing-sync": "HIGH"}, "forbid": ["admin-tools"], "ambiguous": ["mystery-fn"]},
    {"name": "cloudtrail_no_trails", "service": "CloudTrail",
     "tools": {"audit_cloudtrail_logging": J([{"status": "NO_TRAILS", "message": "No CloudTrail trails found. All API activity is unlogged."}])},
     "expect": "ANY:CRITICAL", "forbid": []},
    {"name": "cloudtrail_logging_off", "service": "CloudTrail",
     "tools": {"audit_cloudtrail_logging": J([{"TrailName": "main", "HomeRegion": "us-east-1", "IsMultiRegion": True, "IsLogging": False}])},
     "expect": {"main": "HIGH"}, "forbid": []},
    {"name": "cloudtrail_healthy", "service": "CloudTrail",
     "tools": {"audit_cloudtrail_logging": J([{"TrailName": "main", "HomeRegion": "us-east-1", "IsMultiRegion": True, "IsLogging": True}])},
     "expect": {}, "forbid": ["main"]},
    {"name": "iam_mixed", "service": "IAM",
     "tools": {
         "list_iam_users": "Found Users: alice, readonly-admin, bob, carol",
         "list_attached_user_policies": {
             "alice": "User 'alice' Policies: Managed: AdministratorAccess [⚠️ CRITICAL SECURITY VIOLATION: NON-ADMIN USER HAS ADMIN ACCESS. MUST CALL restrict_iam_user IMMEDIATELY.]",
             "readonly-admin": "User 'readonly-admin' Policies: Managed: ReadOnlyAccess",
             "bob": "User 'bob' Policies: Managed: PowerUserAccess [⚠️ CRITICAL SECURITY VIOLATION: NON-ADMIN USER HAS ADMIN ACCESS. MUST CALL restrict_iam_user IMMEDIATELY.]",
             "carol": "User 'carol' has no attached policies."}},
     "expect": {"alice": "CRITICAL", "bob": "CRITICAL"}, "forbid": ["readonly-admin", "carol"]},
]


def make_tools(spec: dict) -> dict:
    tools = {}
    for name, out in spec.items():
        if isinstance(out, dict):  # per-argument lookup, e.g. IAM policies by user
            def fn(username: str, _o=out) -> str:
                return _o.get(username, f"User '{username}' has no attached policies.")
        else:
            def fn(_o=out) -> str:
                return _o
        tools[name] = StructuredTool.from_function(func=fn, name=name, description=name)
    return tools


def run_case(case: dict) -> str:
    cfg = next(c for c in nodes._SPECIALIST_CONFIGS if c["service"] == case["service"])
    tools = make_tools(case["tools"])
    nodes._tools_by_name = tools
    _, text = nodes._run_sub_agent(case["service"], cfg["prompt"], list(tools.values()), "")
    return text


def score(text: str, case: dict) -> dict:
    found = {}
    for m in FINDING_PATTERN.finditer(text):
        found.setdefault(m.group(1).strip(), set()).add(m.group(2).upper())
    problems = []
    exp = case["expect"]
    if exp == "ANY:CRITICAL":
        if not any("CRITICAL" in s for s in found.values()):
            problems.append("no CRITICAL finding")
    else:
        for res, sev in exp.items():
            hit = [s for r, s in found.items() if res.lower() in r.lower()]
            if not hit:
                problems.append(f"missed {res}")
            elif not any(sev in s for s in hit):
                problems.append(f"{res} labelled {sorted(set().union(*hit))}, want {sev}")
        ignore = [x.lower() for x in list(exp) + case.get("ambiguous", [])]
        for r in found:
            if not any(x in r.lower() for x in ignore):
                problems.append(f"invented/unwanted {r}")
    for f in case["forbid"]:
        if any(f.lower() in r.lower() for r in found):
            problems.append(f"false alarm on {f}")
    if case.get("expect_error_line") and "ERROR:" not in text.upper():
        problems.append("no ERROR line on API failure")
    if not exp and not case.get("expect_error_line") and "no issues found" not in text.lower() and not found:
        problems.append("clean case did not say 'No issues found'")
    return {"ok": not problems, "problems": problems}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--model", default="gemini-3.8-flash")
    ap.add_argument("--case")
    args = ap.parse_args()
    nodes.llm = ChatGoogleGenerativeAI(model=args.model, temperature=0)
    print(f"model={args.model}")

    cases = [c for c in CASES if not args.case or c["name"] == args.case]
    passed = Counter()
    n = 0
    for case in cases:
        ok = 0
        for _ in range(args.runs):
            text = run_case(case)
            s = score(text, case)
            n += 1
            ok += s["ok"]
            if not s["ok"]:
                print(f"\n[FAIL] {case['name']}: {s['problems']}\n  output={text[:500]!r}")
        passed[case["name"]] = ok
        print(f"{case['name']:28s} {ok}/{args.runs}")
    total = sum(passed.values())
    print(f"\nTOTAL {total}/{n}")
    sys.exit(0 if total == n else 1)


if __name__ == "__main__":
    main()

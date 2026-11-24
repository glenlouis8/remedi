"""
Detection eval: do the 8 specialists find the vulns we planted with terraform?

Runs the real orchestrator_node (live Gemini + live read-only AWS calls) with the
MCP server replaced by in-process tools and the database stubbed, so nothing is
written to your Postgres. Ground truth comes from `terraform output -json`.

Scores per service: did the specialist flag the planted resource, with the
severity the prompt prescribes? Findings on OTHER resources (e.g. the default
VPC) are listed separately, not counted as false positives, because we can't
tell if they are real issues.

Run (after `terraform apply`):
    uv run python evals/detection_eval.py [--runs 3] [--model gemini-3.8-flash]
"""
import argparse
import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from unittest.mock import MagicMock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# 1. Stub the DB everywhere (the MCP tool code also calls update_status).
sys.modules["mcp_server.database"] = MagicMock()

# 2. Build in-process tools from the real MCP server module, no subprocess.
from langchain_core.tools import StructuredTool  # noqa: E402
from mcp_server import main as mcp_main  # noqa: E402

_tools = [
    StructuredTool.from_function(
        func=t.fn, name=t.name, description=t.description or t.name
    )
    for t in mcp_main.mcp._tool_manager.list_tools()
]
_stub = MagicMock()
_stub.get_all_tools.return_value = _tools
_stub.get_tools_by_name.return_value = {t.name: t for t in _tools}
sys.modules["agents.mcp_client"] = _stub

from langchain_core.messages import HumanMessage  # noqa: E402
from langchain_google_genai import ChatGoogleGenerativeAI  # noqa: E402
from agents import nodes  # noqa: E402
from agents.patterns import FINDING_PATTERN  # noqa: E402

# service -> (terraform output key or None, severity the prompt prescribes)
EXPECTED = {
    "IAM": ("iam_test_user", "CRITICAL"),
    "S3": ("s3_bucket_name", "CRITICAL"),
    "VPC": ("vpc_id", "HIGH"),
    "Security Groups": ("security_group_id", "HIGH"),
    "EC2": ("ec2_instance_id", "HIGH"),
    "RDS": ("rds_identifier", "CRITICAL"),
    "Lambda": ("lambda_function_name", "HIGH"),
    "CloudTrail": (None, "CRITICAL"),  # planted by absence: no trail exists
}


def terraform_truth() -> dict:
    out = subprocess.run(
        ["terraform", "output", "-json"],
        cwd=ROOT / "terraform", capture_output=True, text=True, check=True,
    ).stdout
    truth = {k: v["value"] for k, v in json.loads(out).items()}
    import boto3
    trails = boto3.client("cloudtrail", region_name="us-east-1").describe_trails()["trailList"]
    truth["_trail_exists"] = bool(trails)
    return truth


def split_sections(combined: str) -> dict:
    sections, name, buf = {}, None, []
    for line in combined.splitlines():
        if line.startswith("=== ") and line.rstrip().endswith(" ==="):
            if name:
                sections[name] = "\n".join(buf)
            name, buf = line.strip("= ").strip(), []
        else:
            buf.append(line)
    if name:
        sections[name] = "\n".join(buf)
    return sections


def score(combined: str, truth: dict) -> dict:
    sections = split_sections(combined)
    res = {}
    for svc, (key, sev) in EXPECTED.items():
        if svc == "CloudTrail" and truth.get("_trail_exists"):
            continue  # a real trail exists, so "no issues" is the correct answer
        found = [(m.group(1).strip(), m.group(2).upper())
                 for m in FINDING_PATTERN.finditer(sections.get(svc, ""))]
        target = truth.get(key) if key else None
        if key is None:
            hit = [f for f in found]  # any CloudTrail finding is the planted one
        else:
            hit = [f for f in found if target and target in f[0]]
        decoys = [v for v in (truth.get("decoy_ids") or {}).values() if isinstance(v, str)]
        false_alarms = [f for f in found if any(d in f[0] for d in decoys)]
        res[svc] = {
            "false_alarms": false_alarms,
            "detected": bool(hit),
            "severity_ok": any(s == sev for _, s in hit),
            "other": [f for f in found if f not in hit],
            "errored": "ERROR:" in sections.get(svc, "").upper(),
        }
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--model", default="gemini-3.8-flash")
    args = ap.parse_args()

    nodes.llm = ChatGoogleGenerativeAI(model=args.model, temperature=0)
    truth = terraform_truth()
    print(f"model={args.model}  truth={json.dumps({k: v for k, v in truth.items() if k != 'summary'})}")

    det, sev_ok, others = Counter(), Counter(), defaultdict(Counter)
    fa = Counter()
    for i in range(args.runs):
        state = {"messages": [HumanMessage(content="Begin audit.")], "scan_id": f"eval-{i}"}
        combined = nodes.orchestrator_node(state)["messages"][0].content
        r = score(combined, truth)
        for svc, v in r.items():
            det[svc] += v["detected"]
            sev_ok[svc] += v["severity_ok"]
            fa[svc] += len(v["false_alarms"])
            for o in v["other"]:
                others[svc][o] += 1
            if not v["detected"]:
                print(f"[MISS run {i}] {svc} errored={v['errored']}\n{split_sections(combined).get(svc, '')[:400]}")

    print("\nservice            detected  severity")
    for svc in EXPECTED:
        print(f"{svc:18s} {det[svc]}/{args.runs}      {sev_ok[svc]}/{args.runs}")
    scored = len(EXPECTED) - (1 if truth.get("_trail_exists") else 0)
    total = sum(det.values())
    if truth.get("_trail_exists"):
        print("\n(CloudTrail skipped: a real trail already exists in this account)")
    print(f"\nRECALL {total}/{scored * args.runs}")
    if truth.get("decoy_ids"):
        bad = sum(fa.values())
        print(f"\nFALSE ALARMS on healthy decoys: {bad} across {args.runs} runs ({len(truth['decoy_ids'])} decoys each)")
        for svc, n in fa.items():
            if n:
                print(f"  {svc}: {n}")
    else:
        print("\n(no decoys deployed: false alarms not measured; apply with -var deploy_decoys=true)")
    print("\nfindings on other resources (not scored):")
    for svc, c in others.items():
        for (res, sev), n in c.items():
            print(f"  {svc}: {res} [{sev}] x{n}")
    sys.exit(0 if total == scored * args.runs and not sum(fa.values()) else 1)


if __name__ == "__main__":
    main()

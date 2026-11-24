"""
Format eval for the report_generator LLM step.

Feeds frozen specialist audit text to the real report generator prompt (live
Gemini call, no AWS, no DB, no MCP subprocess) and checks the output against
the remediator's real regex. Scores per case:
  - format:   every non-empty line is a 🔴 plan line, a ⚠️ [MANUAL] line, or the SECURE line
  - exact:    parsed (resource, tool, severity) == expected, severity must equal the audit's
  - secure:   clean account -> exactly the SYSTEM SECURE line

Run:  uv run python evals/format_eval.py [--runs 3] [--case NAME]
"""
import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path
from unittest.mock import MagicMock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# nodes.py starts the MCP subprocess and opens a DB on import — stub both.
_mcp = MagicMock()
_mcp.get_all_tools.return_value = []
_mcp.get_tools_by_name.return_value = {}
sys.modules["agents.mcp_client"] = _mcp
sys.modules["mcp_server.database"] = MagicMock()

from langchain_core.messages import AIMessage  # noqa: E402
from agents import nodes  # noqa: E402
from agents.patterns import REMEDIATION_LINE_PATTERN, FINDING_PATTERN  # noqa: E402
import re  # noqa: E402

SEVERITY_RE = re.compile(r"🔴 \[(CRITICAL|HIGH)\]")

SECURE_LINE = "✅ SYSTEM SECURE. No remediation actions required."


def score(output: str, case: dict) -> dict:
    lines = [l.strip() for l in output.splitlines() if l.strip()]
    bad_lines = [
        l for l in lines
        if not (REMEDIATION_LINE_PATTERN.search(l) or l.startswith("⚠️ [MANUAL]") or "SYSTEM SECURE" in l)
    ]
    # severity the audit gave each resource; the report must keep it unchanged
    audit_sev = {m.group(1).strip(): m.group(2).upper() for m in FINDING_PATTERN.finditer(case["audit"])}
    parsed = Counter()
    for l in lines:
        m = REMEDIATION_LINE_PATTERN.search(l)
        sev = SEVERITY_RE.search(l)
        if m:
            parsed[(m.group(1), m.group(2), sev.group(1).upper() if sev else "?")] += 1
    expected = Counter((r, t, audit_sev.get(r, "?")) for r, t in case["expected"])
    return {
        "format": not bad_lines,
        "exact": parsed == expected,
        "secure": (SECURE_LINE in output and not parsed) if case["expect_secure"] else not ("SYSTEM SECURE" in output),
        "bad_lines": bad_lines,
        "missing": list((expected - parsed).elements()),
        "extra": list((parsed - expected).elements()),
    }


def run_case(case: dict) -> str:
    os.environ["PROTECTED_IAM_USERS"] = case["protected"]
    state = {"messages": [AIMessage(content=case["audit"])], "scan_id": "eval"}
    return nodes.report_generator_node(state)["audit_summary"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--case")
    ap.add_argument("--model", default="gemini-3.8-flash", help="Gemini model to evaluate (default matches nodes.py)")
    args = ap.parse_args()

    from langchain_google_genai import ChatGoogleGenerativeAI
    nodes.llm = ChatGoogleGenerativeAI(model=args.model, temperature=0)
    print(f"model={args.model}")

    cases = json.loads((Path(__file__).parent / "fixtures.json").read_text())
    if args.case:
        cases = [c for c in cases if c["name"] == args.case]

    totals = Counter()
    n = 0
    for case in cases:
        res = []
        for _ in range(args.runs):
            out = run_case(case)
            s = score(out, case)
            res.append(s)
            n += 1
            for k in ("format", "exact", "secure"):
                totals[k] += s[k]
            if not (s["format"] and s["exact"] and s["secure"]):
                print(f"\n[FAIL] {case['name']}\n  missing={s['missing']} extra={s['extra']} bad_lines={s['bad_lines']}\n  output={out!r}")
        ok = sum(r["format"] and r["exact"] and r["secure"] for r in res)
        print(f"{case['name']:30s} {ok}/{args.runs}")

    print(f"\nTOTAL runs={n}  format={totals['format']}/{n}  exact={totals['exact']}/{n}  secure={totals['secure']}/{n}")
    sys.exit(0 if all(totals[k] == n for k in ("format", "exact", "secure")) else 1)


if __name__ == "__main__":
    main()

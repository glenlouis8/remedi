"""The hosted demo replays frontend/public/demo_run.json, recorded by
scripts/record_demo.py. These checks keep that file safe to publish and in step
with the code: shape, no leaked local details, and the same fake account the
fixtures describe. Re-record with scripts/record_demo.py if one fails after a
legitimate change."""
import json
import re
from pathlib import Path

import pytest

from agents.patterns import REMEDIATION_LINE_PATTERN
from mcp_server import demo_fixtures

RECORDING = Path(__file__).resolve().parent.parent / "frontend" / "public" / "demo_run.json"
GATE_LINE = "[ACTION_REQUIRED] WAITING_FOR_APPROVAL"
SERVICES = {"iam", "s3", "vpc", "sg", "ec2", "rds", "lambda", "cloudtrail"}
REMEDIATION_TOOLS = {
    "restrict_iam_user", "remediate_s3", "remediate_vpc_flow_logs",
    "revoke_security_group_ingress", "enforce_imdsv2", "stop_instance",
    "remediate_rds_public_access", "remediate_lambda_role", "remediate_cloudtrail",
}


@pytest.fixture(scope="module")
def rec():
    return json.loads(RECORDING.read_text())


def _lines(seg):
    return [e["line"] for e in seg]


def test_shape_and_single_gate_at_the_split(rec):
    assert rec["version"] == 1
    assert rec["exit_code"] == 0
    pre, post = _lines(rec["pre_gate"]), _lines(rec["post_gate"])
    assert pre and post
    assert pre[-1].strip() == GATE_LINE
    assert sum(GATE_LINE in l for l in pre) == 1
    assert not any(GATE_LINE in l for l in post)


def test_timestamps_never_go_backwards(rec):
    for seg in (rec["pre_gate"], rec["post_gate"]):
        times = [e["t_ms"] for e in seg]
        assert times == sorted(times)
        assert times[0] >= 0


def test_scan_events_are_valid_and_cover_all_services(rec):
    events = [json.loads(l[7:]) for l in _lines(rec["pre_gate"]) if l.startswith("[SCAN] ")]
    assert events
    for e in events:
        assert e["service"] in SERVICES
        assert e["status"] in {"ok", "vulnerable", "unknown"}
        assert e["resource"]
    assert {e["service"] for e in events} == SERVICES


def test_report_lines_parse_with_the_remediators_regex(rec):
    found = {(m.group(1).strip(), m.group(2).strip())
             for l in _lines(rec["pre_gate"]) for m in REMEDIATION_LINE_PATTERN.finditer(l)}
    assert len(found) == 9
    assert {tool for _, tool in found} == REMEDIATION_TOOLS


def test_fixes_run_after_approval_and_all_succeed(rec):
    post = _lines(rec["post_gate"])
    assert sum("[EXEC] Calling" in l for l in post) == 9
    assert sum(l.startswith("✅ SUCCESS") for l in post) == 9
    assert not any(l.startswith(("❌", "⚠️")) or "[ERROR]" in l or "Traceback" in l for l in _lines(rec["pre_gate"]) + post)
    assert any("MISSION ACCOMPLISHED" in l for l in post)
    assert not any("VERIFICATION FAILURE" in l for l in post)


def test_nothing_real_leaks_into_the_recording(rec):
    text = "\n".join(_lines(rec["pre_gate"]) + _lines(rec["post_gate"]))
    for needle in ("/Users/", "@", "AKIA", "smith.langchain", "supabase", "glenlouis", "GOOGLE_API_KEY"):
        assert needle not in text, f"recording contains {needle!r}"
    # the only 12-digit account id allowed is the fixtures' fake one
    assert set(re.findall(r"\b\d{12}\b", text)) <= {demo_fixtures.FAKE_ACCOUNT_ID}


def test_recording_matches_the_current_fake_account(rec):
    """Fails when the fixtures change but the demo wasn't re-recorded."""
    state = demo_fixtures._INITIAL_STATE
    known = {
        "iam": set(state["iam_users"]), "s3": set(state["s3"]), "vpc": set(state["vpcs"]),
        "sg": set(state["security_groups"]), "ec2": set(state["ec2"]), "rds": set(state["rds"]),
        "lambda": set(state["lambdas"]), "cloudtrail": set(state["cloudtrail"]),
    }
    for l in _lines(rec["pre_gate"]) + _lines(rec["post_gate"]):
        if l.startswith("[SCAN] "):
            e = json.loads(l[7:])
            assert e["resource"] in known[e["service"]], f"{e['service']}/{e['resource']} is not in the fixtures"

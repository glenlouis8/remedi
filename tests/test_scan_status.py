"""Scan status accuracy: the UI's [SCAN] events and the verifier's verdict must
reflect what actually happened, not just what the report claimed."""
import json
import os
import sys
import types
from unittest.mock import MagicMock, patch

import boto3
from langchain_core.messages import AIMessage
from moto import mock_aws

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")


def _scan_events(capsys):
    err = capsys.readouterr().err
    return [json.loads(l[7:]) for l in err.splitlines() if l.startswith("[SCAN] ")]


# --- stale-red: clean / quarantined resources must emit ok ---

@mock_aws
def test_clean_security_group_emits_ok_and_fixed_group_flips(capsys):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    risky = ec2.create_security_group(GroupName="risky", Description="r")["GroupId"]
    clean = ec2.create_security_group(GroupName="clean", Description="c")["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=risky,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )
    from mcp_server.main import audit_security_groups, revoke_security_group_ingress

    audit_security_groups()
    first = {e["resource"]: e["status"] for e in _scan_events(capsys) if e["service"] == "sg"}
    assert first[risky] == "vulnerable"
    assert first[clean] == "ok"

    revoke_security_group_ingress(risky)
    capsys.readouterr()
    audit_security_groups()
    after = {e["resource"]: e["status"] for e in _scan_events(capsys) if e["service"] == "sg"}
    assert after[risky] == "ok"


@mock_aws
def test_stopped_instance_emits_ok_and_is_not_a_finding(capsys):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    iid = ec2.run_instances(ImageId="ami-12c6146b", MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]
    from mcp_server.main import audit_ec2_vulnerabilities, stop_instance

    audit_ec2_vulnerabilities()
    assert {e["resource"]: e["status"] for e in _scan_events(capsys)}[iid] == "vulnerable"

    stop_instance(iid)
    capsys.readouterr()
    findings = audit_ec2_vulnerabilities()
    assert findings == ["No running instances found."]
    assert {e["resource"]: e["status"] for e in _scan_events(capsys)}[iid] == "ok"


# --- verifier verdict must not hide unfixed remediations ---

def _load_nodes():
    """agents.nodes starts an MCP subprocess and builds an LLM at import; stub both."""
    stub = types.ModuleType("agents.mcp_client")
    stub.get_all_tools = lambda: []
    stub.get_tools_by_name = lambda: {}
    os.environ.setdefault("GOOGLE_API_KEY", "test")
    with patch.dict(sys.modules, {"agents.mcp_client": stub}):
        sys.modules.pop("agents.nodes", None)
        import agents.nodes as nodes
    return nodes


def _verify(nodes, outcomes):
    report = AIMessage(content="### 🛠️ REMEDIATION REPORT\n...", additional_kwargs={"remediation_outcomes": outcomes})
    state = {
        "messages": [report, MagicMock(spec=["content"])],
        "audit_summary": (
            "🔴 [CRITICAL] dev-intern is vulnerable -> ACTION: I will call `restrict_iam_user`\n"
            "🔴 [CRITICAL] pub-bucket is vulnerable -> ACTION: I will call `remediate_s3`\n"
        ),
        "scan_id": "SCAN-TEST",
    }
    # verifier only inspects ToolMessage / tool_calls on the extra message
    from langchain_core.messages import ToolMessage
    state["messages"][1] = ToolMessage(content="ok", tool_call_id="1")
    verdict = AIMessage(content="🏆 MISSION ACCOMPLISHED. All resources verified as SECURE.")
    with patch.object(nodes, "audit_llm") as llm, \
         patch.object(nodes, "update_scan") as upd, \
         patch.object(nodes, "update_status") as ust:
        llm.invoke.return_value = verdict
        out = nodes.verifier_agent(state)
    return out, upd, ust


def test_verifier_all_fixed_still_accomplished():
    nodes = _load_nodes()
    out, upd, ust = _verify(nodes, [
        {"resource": "dev-intern", "tool": "restrict_iam_user", "status": "SUCCESS"},
        {"resource": "pub-bucket", "tool": "remediate_s3", "status": "SUCCESS"},
    ])
    assert "MISSION ACCOMPLISHED" in out["messages"][0].content
    assert upd.call_args.kwargs["verified"] is True
    assert {c.args[0] for c in ust.call_args_list} == {"check_iam", "check_s3"}


def test_verifier_refused_fix_fails_verdict_and_keeps_control_unflipped():
    nodes = _load_nodes()
    out, upd, ust = _verify(nodes, [
        {"resource": "dev-intern", "tool": "restrict_iam_user", "status": "SKIPPED"},
        {"resource": "pub-bucket", "tool": "remediate_s3", "status": "SUCCESS"},
    ])
    assert "VERIFICATION FAILURE" in out["messages"][0].content
    assert "dev-intern" in out["messages"][0].content
    assert upd.call_args.kwargs["verified"] is False
    assert upd.call_args.kwargs["status"] == "FAILED"
    # only the control whose fix really landed is flipped
    assert {c.args[0] for c in ust.call_args_list} == {"check_s3"}

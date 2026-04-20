import re
import pytest

pattern = re.compile(
    r'🔴 \[CRITICAL\] (.+?) is vulnerable -> ACTION: I will call [`\'"]?(\w+)[`\'"]?'
)

TOOL_ARG_MAP = {
    "restrict_iam_user":             "user_name",
    "remediate_s3":                  "bucket_name",
    "remediate_vpc_flow_logs":       "vpc_id",
    "revoke_security_group_ingress": "group_id",
    "enforce_imdsv2":                "instance_id",
    "stop_instance":                 "instance_id",
    "remediate_rds_public_access":   "db_instance_identifier",
    "remediate_lambda_role":         "function_name",
    "remediate_cloudtrail":          "trail_name",
}


def test_single_finding_parses():
    report = "🔴 [CRITICAL] my-bucket is vulnerable -> ACTION: I will call `remediate_s3`"
    matches = pattern.findall(report)
    assert matches == [("my-bucket", "remediate_s3")]


def test_multiple_findings_parse():
    report = (
        "🔴 [CRITICAL] admin-user is vulnerable -> ACTION: I will call `restrict_iam_user`\n"
        "🔴 [CRITICAL] my-bucket is vulnerable -> ACTION: I will call `remediate_s3`\n"
        "🔴 [CRITICAL] vpc-abc123 is vulnerable -> ACTION: I will call `remediate_vpc_flow_logs`"
    )
    matches = pattern.findall(report)
    assert len(matches) == 3
    assert matches[0] == ("admin-user", "restrict_iam_user")
    assert matches[1] == ("my-bucket", "remediate_s3")
    assert matches[2] == ("vpc-abc123", "remediate_vpc_flow_logs")


def test_secure_system_returns_no_tasks():
    report = "✅ SYSTEM SECURE. No remediation actions required."
    assert pattern.findall(report) == []


def test_all_nine_tools_are_recognized():
    lines = [
        f"🔴 [CRITICAL] resource-{i} is vulnerable -> ACTION: I will call `{tool}`"
        for i, tool in enumerate(TOOL_ARG_MAP.keys())
    ]
    report = "\n".join(lines)
    matches = pattern.findall(report)
    assert len(matches) == len(TOOL_ARG_MAP)
    found_tools = {m[1] for m in matches}
    assert found_tools == set(TOOL_ARG_MAP.keys())


def test_resource_name_with_hyphens_and_numbers():
    report = "🔴 [CRITICAL] sg-0a1b2c3d4e is vulnerable -> ACTION: I will call `revoke_security_group_ingress`"
    matches = pattern.findall(report)
    assert matches == [("sg-0a1b2c3d4e", "revoke_security_group_ingress")]


def test_resource_name_with_dots():
    report = "🔴 [CRITICAL] prod.db.instance is vulnerable -> ACTION: I will call `remediate_rds_public_access`"
    matches = pattern.findall(report)
    assert matches == [("prod.db.instance", "remediate_rds_public_access")]


def test_zero_tasks_from_empty_string():
    assert pattern.findall("") == []


def test_manual_review_line_not_parsed():
    report = "⚠️ [MANUAL] some-resource requires manual review — no tool available."
    assert pattern.findall(report) == []

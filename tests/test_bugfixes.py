"""Regression tests for the fix/critical-bugs branch.

Scope is deliberately narrow: the pure-function / regex logic that changed.
The graph, worker subprocess lifecycle, and Redis paths need live services and
are not covered here.
"""
import os
import pytest
from cryptography.fernet import Fernet

from agents.patterns import REMEDIATION_LINE_PATTERN, FINDING_PATTERN


# ── C3: loosened REMEDIATION_LINE_PATTERN ─────────────────────────────────────

@pytest.mark.parametrize("line, expected", [
    # ascii arrow, backticked tool (the canonical prompt format)
    ("🔴 [CRITICAL] alice is vulnerable -> ACTION: I will call `restrict_iam_user`",
     ("alice", "restrict_iam_user")),
    # unicode arrow
    ("🔴 [CRITICAL] alice is vulnerable → ACTION: I will call `restrict_iam_user`",
     ("alice", "restrict_iam_user")),
    # em dash instead of arrow
    ("🔴 [HIGH] my-bucket is vulnerable — ACTION: I will call `remediate_s3`",
     ("my-bucket", "remediate_s3")),
    # markdown-bold tool name
    ("🔴 [CRITICAL] alice is vulnerable -> ACTION: I will call **restrict_iam_user**",
     ("alice", "restrict_iam_user")),
    # reworded verb
    ("🔴 [CRITICAL] vpc-abc is vulnerable -> ACTION: I will run remediate_vpc_flow_logs.",
     ("vpc-abc", "remediate_vpc_flow_logs")),
])
def test_remediation_pattern_tolerates_format_drift(line, expected):
    assert REMEDIATION_LINE_PATTERN.findall(line) == [expected]


@pytest.mark.parametrize("line", [
    "⚠️ [MANUAL] some-resource requires manual review — no tool available.",
    "✅ SYSTEM SECURE. No remediation actions required.",
    "Here is a summary of what the audit found across the account.",
    "🔴 [CRITICAL] something happened but no action line follows",
])
def test_remediation_pattern_rejects_non_action_lines(line):
    assert REMEDIATION_LINE_PATTERN.findall(line) == []


def test_remediation_pattern_multiline_block():
    report = (
        "🔴 [CRITICAL] admin-user is vulnerable -> ACTION: I will call `restrict_iam_user`\n"
        "🔴 [CRITICAL] my-bucket is vulnerable -> ACTION: I will call `remediate_s3`\n"
        "🔴 [HIGH] sg-01 is vulnerable -> ACTION: I will call `revoke_security_group_ingress`"
    )
    assert len(REMEDIATION_LINE_PATTERN.findall(report)) == 3


# ── C2: FINDING_PATTERN must match every line, not just the last ───────────────

def test_finding_pattern_parses_all_lines():
    text = (
        "FINDING: alice | SEVERITY: CRITICAL | REASON: admin access | FIX: detach policies\n"
        "FINDING: bob | SEVERITY: HIGH | REASON: imdsv1 enabled | FIX: enforce imdsv2\n"
        "FINDING: carol-bucket | SEVERITY: CRITICAL | REASON: public bucket"
    )
    matches = FINDING_PATTERN.findall(text)
    assert [m[0] for m in matches] == ["alice", "bob", "carol-bucket"]
    # FIX captured when present, empty when absent
    assert matches[0][3] == "detach policies"
    assert matches[2][3] == ""


def test_finding_pattern_ignores_trailing_prose():
    text = (
        "FINDING: alice | SEVERITY: CRITICAL | REASON: admin access\n"
        "FINDING: bob | SEVERITY: HIGH | REASON: imdsv1\n"
        "Let me know if you need more detail on any of these."
    )
    assert len(FINDING_PATTERN.findall(text)) == 2


def test_finding_pattern_clean_service_line_no_match():
    assert FINDING_PATTERN.findall("S3: No issues found.") == []


# ── H7: seal_json / unseal_json ──────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _encryption_key():
    os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()
    yield
    os.environ.pop("ENCRYPTION_KEY", None)


def test_seal_unseal_roundtrip():
    from remedi_platform.accounts import seal_json, unseal_json
    env = {
        "AWS_ACCESS_KEY_ID": "AKIAEXAMPLE",
        "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG",
        "REMEDI_USER_ID": "user_123",
        "PROTECTED_IAM_USERS": "a,b",
    }
    assert unseal_json(seal_json(env)) == env


def test_unseal_rejects_garbage():
    from remedi_platform.accounts import unseal_json
    with pytest.raises(Exception):
        unseal_json("not-a-valid-fernet-token")


def test_unseal_rejects_wrong_key():
    from remedi_platform.accounts import seal_json, unseal_json
    token = seal_json({"x": 1})
    os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()  # rotate
    with pytest.raises(Exception):
        unseal_json(token)

import json
import os
import boto3
import pytest
from moto import mock_aws
from unittest.mock import patch, MagicMock

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SECURITY_TOKEN", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
os.environ.setdefault("DATABASE_URL", "")


# --- S3 ---

@mock_aws
def test_remediate_s3_blocks_all_public_access():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")

    from mcp_server.main import remediate_s3
    result = remediate_s3("test-bucket")
    assert "SUCCESS" in result

    config = s3.get_public_access_block(Bucket="test-bucket")["PublicAccessBlockConfiguration"]
    assert config["BlockPublicAcls"] is True
    assert config["IgnorePublicAcls"] is True
    assert config["BlockPublicPolicy"] is True
    assert config["RestrictPublicBuckets"] is True


@mock_aws
def test_remediate_s3_strips_public_bucket_policy():
    import json
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="policy-bucket")
    s3.put_bucket_policy(Bucket="policy-bucket", Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "PublicRead", "Effect": "Allow", "Principal": "*",
             "Action": "s3:GetObject", "Resource": "arn:aws:s3:::policy-bucket/*"},
            {"Sid": "KeepMe", "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
             "Action": "s3:GetObject", "Resource": "arn:aws:s3:::policy-bucket/*"},
        ],
    }))

    from mcp_server.main import remediate_s3
    result = remediate_s3("policy-bucket")
    assert "SUCCESS" in result

    remaining = json.loads(s3.get_bucket_policy(Bucket="policy-bucket")["Policy"])["Statement"]
    sids = {s["Sid"] for s in remaining}
    assert sids == {"KeepMe"}


@mock_aws
def test_remediate_s3_deletes_fully_public_policy():
    import json
    from botocore.exceptions import ClientError
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="allpublic-bucket")
    s3.put_bucket_policy(Bucket="allpublic-bucket", Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "PublicRead", "Effect": "Allow", "Principal": "*",
             "Action": "s3:GetObject", "Resource": "arn:aws:s3:::allpublic-bucket/*"},
        ],
    }))

    from mcp_server.main import remediate_s3
    result = remediate_s3("allpublic-bucket")
    assert "SUCCESS" in result

    try:
        s3.get_bucket_policy(Bucket="allpublic-bucket")
        assert False, "policy should have been deleted"
    except ClientError as e:
        assert e.response["Error"]["Code"] == "NoSuchBucketPolicy"


@mock_aws
def test_audit_s3_detects_public_bucket():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="public-bucket")
    # no public access block = vulnerable

    from mcp_server.main import audit_s3_buckets
    result = audit_s3_buckets()
    assert "PUBLIC RISK" in result


@mock_aws
def test_audit_s3_detects_secure_bucket():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="private-bucket")
    s3.put_public_access_block(
        Bucket="private-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    from mcp_server.main import audit_s3_buckets
    result = audit_s3_buckets()
    assert "SECURE" in result


@mock_aws
def test_audit_s3_no_buckets():
    from mcp_server.main import audit_s3_buckets
    result = audit_s3_buckets()
    assert "No S3 buckets found" in result


# --- IAM ---

@mock_aws
def test_restrict_iam_user_strips_inline_policies():
    # moto doesn't serve AWS managed policies (arn:aws:iam::aws:policy/...)
    # so we test with inline policies, which the function also handles.
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="bad-user")
    iam.put_user_policy(
        UserName="bad-user",
        PolicyName="DangerousInlinePolicy",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }),
    )

    # Patch the ReadOnlyAccess attachment — it uses an AWS managed policy ARN
    # that moto doesn't pre-populate.
    from mcp_server import main as mcp_main
    real_get_boto_client = mcp_main.get_boto_client

    def patched_get_boto_client(service):
        client = real_get_boto_client(service)
        if service == "iam":
            original_attach = client.attach_user_policy
            client.attach_user_policy = MagicMock(return_value={})
            client._real_attach = original_attach
        return client

    with patch.object(mcp_main, "get_boto_client", side_effect=patched_get_boto_client):
        from mcp_server.main import restrict_iam_user
        result = restrict_iam_user("bad-user")

    assert "SUCCESS" in result
    inline = iam.list_user_policies(UserName="bad-user")["PolicyNames"]
    assert "DangerousInlinePolicy" not in inline


@mock_aws
def test_list_iam_users_returns_all():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="alice")
    iam.create_user(UserName="bob")

    from mcp_server.main import list_iam_users
    result = list_iam_users()
    assert "alice" in result
    assert "bob" in result


# --- Security Groups ---

@mock_aws
def test_revoke_security_group_ingress_removes_public_rule():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(GroupName="test-sg", Description="test")
    group_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )

    from mcp_server.main import revoke_security_group_ingress
    result = revoke_security_group_ingress(group_id)
    assert "SUCCESS" in result

    rules = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0]["IpPermissions"]
    public_rules = [
        r for r in rules
        if any(ip.get("CidrIp") == "0.0.0.0/0" for ip in r.get("IpRanges", []))
    ]
    assert public_rules == []


@mock_aws
def test_revoke_idempotent_when_already_clean():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(GroupName="clean-sg", Description="clean")
    group_id = sg["GroupId"]

    from mcp_server.main import revoke_security_group_ingress
    result = revoke_security_group_ingress(group_id)
    assert "SUCCESS" in result


@mock_aws
def test_revoke_preserves_peer_sg_rule_on_shared_port():
    """Revoking a 0.0.0.0/0 rule must not tear down a peer-SG rule on another port."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    target = ec2.create_security_group(GroupName="app", Description="app")["GroupId"]
    peer = ec2.create_security_group(GroupName="lb", Description="lb")["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=target,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
             "UserIdGroupPairs": [{"GroupId": peer}]},
        ],
    )

    from mcp_server.main import revoke_security_group_ingress
    assert "SUCCESS" in revoke_security_group_ingress(target)

    rules = ec2.describe_security_groups(GroupIds=[target])["SecurityGroups"][0]["IpPermissions"]
    assert not any(
        ip.get("CidrIp") == "0.0.0.0/0" for r in rules for ip in r.get("IpRanges", [])
    )
    # the peer-SG rule on 443 must survive
    assert any(
        pair.get("GroupId") == peer for r in rules for pair in r.get("UserIdGroupPairs", [])
    )


@mock_aws
def test_audit_security_groups_flags_ipv6_open_world():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(GroupName="v6-sg", Description="v6")
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
        }],
    )

    from mcp_server.main import audit_security_groups
    result = audit_security_groups()
    assert any(isinstance(r, dict) and r.get("GroupId") == sg["GroupId"] for r in result)


@mock_aws
def test_audit_security_groups_flags_open_world():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(GroupName="open-sg", Description="open")
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 80,
            "ToPort": 80,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )

    from mcp_server.main import audit_security_groups
    result = audit_security_groups()
    assert any(
        isinstance(r, dict) and r.get("Risk") == "OPEN TO WORLD (0.0.0.0/0)"
        for r in result
    )


# --- EC2 ---

@mock_aws
@pytest.mark.xfail(reason="moto bug: modify_instance_metadata_options raises TypeError internally")
def test_enforce_imdsv2():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    instance = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)["Instances"][0]

    from mcp_server.main import enforce_imdsv2
    result = enforce_imdsv2(instance["InstanceId"])
    assert "SUCCESS" in result


@mock_aws
def test_audit_ec2_finds_running_instances():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)

    from mcp_server.main import audit_ec2_vulnerabilities
    result = audit_ec2_vulnerabilities()
    assert isinstance(result, list)
    assert len(result) > 0
    assert "InstanceId" in result[0]


# --- RDS ---

@mock_aws
def test_remediate_rds_disables_public_access():
    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(
        DBInstanceIdentifier="test-db",
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="password123",
        PubliclyAccessible=True,
    )

    from mcp_server.main import remediate_rds_public_access
    result = remediate_rds_public_access("test-db")
    assert "SUCCESS" in result


@mock_aws
def test_audit_rds_detects_public_instance():
    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(
        DBInstanceIdentifier="public-db",
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="password123",
        PubliclyAccessible=True,
    )

    from mcp_server.main import audit_rds_instances
    result = audit_rds_instances()
    assert any(
        isinstance(r, dict) and r.get("DBInstanceIdentifier") == "public-db" and r.get("PubliclyAccessible")
        for r in result
    )


# --- LAMBDA ---
# moto's extras ([cloudtrail,ec2,iam,logs,rds,s3]) don't cover Lambda, so these
# use manual boto3 client mocks instead of @mock_aws.

def _paginator(pages):
    paginator = MagicMock()
    paginator.paginate.return_value = pages
    return paginator


def test_audit_lambda_permissions_flags_admin_access():
    lambda_client = MagicMock()
    iam = MagicMock()
    lambda_client.get_paginator.return_value = _paginator([
        {"Functions": [{"FunctionName": "my-func", "Role": "arn:aws:iam::123456789012:role/my-role"}]}
    ])
    iam.get_paginator.side_effect = lambda name: {
        "list_attached_role_policies": _paginator([
            {"AttachedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]}
        ]),
        "list_role_policies": _paginator([{"PolicyNames": []}]),
    }[name]

    with patch("mcp_server.main.get_boto_client", side_effect=lambda svc: {"lambda": lambda_client, "iam": iam}[svc]):
        from mcp_server.main import audit_lambda_permissions
        result = audit_lambda_permissions()

    assert len(result) == 1
    assert result[0]["OverPermissioned"] is True
    assert "AdministratorAccess" in result[0]["Issues"][0]


def test_remediate_lambda_role_detaches_admin_and_attaches_basic():
    lambda_client = MagicMock()
    iam = MagicMock()
    lambda_client.get_function_configuration.return_value = {"Role": "arn:aws:iam::123456789012:role/my-role"}
    iam.get_paginator.side_effect = lambda name: {
        "list_attached_role_policies": _paginator([
            {"AttachedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]}
        ]),
        "list_role_policies": _paginator([{"PolicyNames": []}]),
    }[name]

    with patch("mcp_server.main.get_boto_client", side_effect=lambda svc: {"lambda": lambda_client, "iam": iam}[svc]):
        from mcp_server.main import remediate_lambda_role
        result = remediate_lambda_role("my-func")

    assert "SUCCESS" in result
    iam.detach_role_policy.assert_called_once_with(
        RoleName="my-role", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
    )
    iam.attach_role_policy.assert_called_once_with(
        RoleName="my-role", PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    )

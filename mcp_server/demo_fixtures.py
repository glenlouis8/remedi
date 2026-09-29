"""In-memory fake AWS account for demo mode (REMEDI_DEMO=1).

Every function mirrors the tool of the same name in mcp_server/main.py: same
return type, same strings, same [SCAN] events, same update_status calls. Only
the boto3 I/O is replaced by reads/writes on STATE, so the agents, prompts and
regex parsers behave exactly as they do against a real account.

The MCP server is spawned per scan, so STATE starts fresh every run.
"""
import copy
import json
import sys

from mcp_server.database import update_status

TARGET_REGION = "us-east-1"
FAKE_ACCOUNT_ID = "123456789012"

# Always protected in demo mode (stands in for the STS-detected credential user).
DEMO_PROTECTED_USERS = {"demo-admin"}

_INITIAL_STATE = {
    "iam_users": {
        "dev-intern": ["AdministratorAccess"],
        "demo-admin": ["AdministratorAccess"],
        "analytics-svc": ["ReadOnlyAccess"],
        "ci-deployer": ["AmazonEC2ContainerRegistryPowerUser"],
    },
    "s3": {
        "demo-public-logs": {"pab": False, "public_policy": True},
        "demo-app-assets": {"pab": True, "public_policy": False},
        "demo-backups": {"pab": True, "public_policy": False},
    },
    "vpcs": {
        "vpc-0demo00000000001": {"cidr": "10.0.0.0/16", "flow_logs": False},
        "vpc-0demo00000000002": {"cidr": "10.1.0.0/16", "flow_logs": True},
    },
    "security_groups": {
        "sg-0demo00000000001": {"open_ports": [22], "protocol": "tcp"},
        "sg-0demo00000000002": {"open_ports": [], "protocol": "tcp"},
    },
    "ec2": {
        "i-0demo00000000001": {
            "state": "running", "public_ip": "203.0.113.10",
            "imdsv1": True, "root_encrypted": False,
        },
        "i-0demo00000000002": {
            "state": "running", "public_ip": "None",
            "imdsv1": False, "root_encrypted": True,
        },
    },
    "rds": {
        "demo-orders-db": {"engine": "postgres", "public": True, "status": "available"},
        "demo-analytics-db": {"engine": "mysql", "public": False, "status": "available"},
    },
    "lambdas": {
        "demo-data-processor": {"role": "demo-processor-role", "admin": True},
        "demo-cron-cleanup": {"role": "demo-cleanup-role", "admin": False},
    },
    "cloudtrail": {
        "demo-trail": {"home_region": TARGET_REGION, "multi_region": False, "logging": False},
    },
}

STATE = copy.deepcopy(_INITIAL_STATE)


def _emit(service: str, resource: str, status: str, msg: str = "") -> None:
    print(
        "[SCAN] " + json.dumps({"service": service, "resource": resource, "status": status, "msg": msg}),
        file=sys.stderr, flush=True
    )


def protected_iam_users(env_value: str) -> set:
    protected = {u.strip() for u in env_value.split(",") if u.strip()}
    return protected | DEMO_PROTECTED_USERS


# =============================================================================
# 0. AGENT SELF-CHECK
# =============================================================================


def get_agent_identity() -> str:
    return f"Agent Active: arn:aws:iam::{FAKE_ACCOUNT_ID}:user/remedi-agent | Target Region: {TARGET_REGION}"


# =============================================================================
# 1. IAM
# =============================================================================


def list_iam_users() -> str:
    return f"Found Users: {', '.join(STATE['iam_users'])}"


def list_attached_user_policies(username: str) -> str:
    if username not in STATE["iam_users"]:
        return f"Error checking policies for {username}: NoSuchEntity: The user with name {username} cannot be found."
    policies = [f"Managed: {p}" for p in STATE["iam_users"][username]]
    result = f"User '{username}' Policies: {', '.join(policies)}" if policies else f"User '{username}' has no attached policies."

    if any(p in result for p in ("AdministratorAccess", "PowerUserAccess")):
        _emit("iam", username, "vulnerable", "has admin-level access")
        result += " [⚠️ CRITICAL SECURITY VIOLATION: NON-ADMIN USER HAS ADMIN ACCESS. MUST CALL restrict_iam_user IMMEDIATELY.]"
    else:
        _emit("iam", username, "ok")
    return result


def restrict_iam_user(user_name: str, protected: set) -> str:
    if user_name in protected:
        return f"REFUSED: '{user_name}' is a protected IAM user — not remediating."
    if user_name not in STATE["iam_users"]:
        return f"ERROR: Failed to restrict {user_name}: NoSuchEntity: The user with name {user_name} cannot be found."
    log = [f"Detached: {p}" for p in STATE["iam_users"][user_name]]
    STATE["iam_users"][user_name] = ["ReadOnlyAccess"]
    log.append("Attached ReadOnlyAccess")
    update_status("check_iam", "SAFE")
    return f"SUCCESS: {user_name} neutralized.\nACTIONS: {'; '.join(log)}"


# =============================================================================
# 2. S3
# =============================================================================


def list_s3_buckets() -> str:
    return f"Buckets: {', '.join(STATE['s3'])}"


def check_s3_security(bucket_name: str) -> dict:
    b = STATE["s3"].get(bucket_name)
    if b is None:
        return {"bucket": bucket_name, "is_public_risk": False, "error": "NoSuchBucket"}
    if not b["pab"]:
        _emit("s3", bucket_name, "vulnerable", "no public access block configured")
        return {
            "bucket": bucket_name,
            "is_public_risk": True,
            "note": "No Public Access Block found.",
        }
    _emit("s3", bucket_name, "ok")
    return {"bucket": bucket_name, "is_public_risk": False}


def audit_s3_buckets() -> str:
    if not STATE["s3"]:
        return "No S3 buckets found."
    results = []
    for name, b in STATE["s3"].items():
        if not b["pab"]:
            _emit("s3", name, "vulnerable", "no public access block configured")
            results.append(f"BUCKET {name}: PUBLIC RISK — no public access block found")
        else:
            _emit("s3", name, "ok")
            results.append(f"BUCKET {name}: SECURE")
    return "\n".join(results)


def remediate_s3(bucket_name: str) -> str:
    b = STATE["s3"].get(bucket_name)
    if b is None:
        return f"ERROR: Failed to remediate S3: NoSuchBucket: The specified bucket does not exist ({bucket_name})"
    b["pab"] = True
    policy_note = ""
    if b["public_policy"]:
        b["public_policy"] = False
        policy_note = " Deleted the fully-public bucket policy."
    update_status("check_s3", "SAFE")
    return f"SUCCESS: Public access blocked for bucket '{bucket_name}'.{policy_note}"


# =============================================================================
# 3. NETWORK
# =============================================================================


def audit_vpc_network() -> list:
    findings = []
    for vpc_id, v in STATE["vpcs"].items():
        if v["flow_logs"]:
            _emit("vpc", vpc_id, "ok")
        else:
            _emit("vpc", vpc_id, "vulnerable", "flow logs disabled")
        findings.append({
            "VpcId": vpc_id,
            "FlowLogs": "ENABLED" if v["flow_logs"] else "DISABLED (Risk)",
            "CidrBlock": v["cidr"],
        })
    return findings


def remediate_vpc_flow_logs(vpc_id: str) -> str:
    v = STATE["vpcs"].get(vpc_id)
    if v is None:
        return f"ERROR enabling flow logs: InvalidVpcID.NotFound: The vpc ID '{vpc_id}' does not exist"
    v["flow_logs"] = True
    update_status("check_vpc", "SAFE")
    return (
        f"SUCCESS: Flow Logs enabled for {vpc_id}. "
        f"Note: an IAM role named 'AegisFlowLogRole' was created in your account to allow "
        f"VPC Flow Logs to deliver to CloudWatch. This role is required for flow logs to keep "
        f"working and will persist in your account — do not delete it."
    )


def audit_security_groups() -> list:
    risky_groups = []
    for group_id, sg in STATE["security_groups"].items():
        if not sg["open_ports"]:
            _emit("sg", group_id, "ok")
        for port in sg["open_ports"]:
            _emit("sg", group_id, "vulnerable", f"port {port} open to the internet")
            risky_groups.append({
                "GroupId": group_id,
                "Port": port,
                "Protocol": sg["protocol"],
                "Risk": "OPEN TO WORLD (0.0.0.0/0)",
            })
    if not risky_groups:
        update_status("check_ssh", "SAFE")
        return ["No risky Security Groups found. System is SAFE."]
    return risky_groups


def revoke_security_group_ingress(group_id: str) -> str:
    sg = STATE["security_groups"].get(group_id)
    if sg is None:
        return f"ERROR: Failed to revoke ingress on {group_id}: InvalidGroup.NotFound: The security group '{group_id}' does not exist"
    if not sg["open_ports"]:
        update_status("check_ssh", "SAFE")
        return f"SUCCESS: No public ingress rules found on {group_id} (already clean)."
    ports = [str(p) for p in sg["open_ports"]]
    sg["open_ports"] = []
    update_status("check_ssh", "SAFE")
    return f"SUCCESS: Revoked all internet-open ingress rules on {group_id} (ports: {', '.join(ports)})."


# =============================================================================
# 4. COMPUTE
# =============================================================================


def audit_ec2_vulnerabilities() -> list:
    findings = []
    for instance_id, i in STATE["ec2"].items():
        if i["state"] != "running":
            _emit("ec2", instance_id, "ok", "not running (quarantined)")
            continue
        issues = []
        if i["imdsv1"]:
            issues.append("IMDSv1 enabled")
        if not i["root_encrypted"]:
            issues.append("unencrypted root volume")
        if issues:
            _emit("ec2", instance_id, "vulnerable", ", ".join(issues))
        else:
            _emit("ec2", instance_id, "ok")
        findings.append({
            "InstanceId": instance_id,
            "PublicIP": i["public_ip"],
            "IMDSv1_Enabled": i["imdsv1"],
            "RootVolume_Encrypted": i["root_encrypted"],
        })
    return findings if findings else ["No running instances found."]


def enforce_imdsv2(instance_id: str) -> str:
    i = STATE["ec2"].get(instance_id)
    if i is None:
        return f"ERROR: Failed to enforce IMDSv2 on {instance_id}: InvalidInstanceID.NotFound: The instance ID '{instance_id}' does not exist"
    i["imdsv1"] = False
    update_status("check_ec2", "SAFE")
    return f"SUCCESS: IMDSv2 enforced on {instance_id}."


def stop_instance(instance_id: str) -> str:
    i = STATE["ec2"].get(instance_id)
    if i is None:
        return f"ERROR: Failed to stop instance {instance_id}: InvalidInstanceID.NotFound: The instance ID '{instance_id}' does not exist"
    i["state"] = "stopped"
    update_status("check_ec2", "SAFE")
    return f"SUCCESS: Instance {instance_id} stopped (Quarantined)."


# =============================================================================
# 5. RDS
# =============================================================================


def audit_rds_instances() -> list:
    findings = [
        {
            "DBInstanceIdentifier": name,
            "Engine": db["engine"],
            "PubliclyAccessible": db["public"],
            "DBInstanceStatus": db["status"],
        }
        for name, db in STATE["rds"].items()
    ]
    if not findings:
        return ["No RDS instances found."]
    for db in findings:
        if db["PubliclyAccessible"]:
            _emit("rds", db["DBInstanceIdentifier"], "vulnerable", "publicly accessible")
        else:
            _emit("rds", db["DBInstanceIdentifier"], "ok")
    if not any(f["PubliclyAccessible"] for f in findings):
        update_status("check_rds", "SAFE")
    return findings


def remediate_rds_public_access(db_instance_identifier: str) -> str:
    db = STATE["rds"].get(db_instance_identifier)
    if db is None:
        return f"ERROR: Failed to remediate RDS instance '{db_instance_identifier}': DBInstanceNotFound: DBInstance {db_instance_identifier} not found."
    db["public"] = False
    update_status("check_rds", "SAFE")
    return f"SUCCESS: Public access disabled for RDS instance '{db_instance_identifier}'."


# =============================================================================
# 6. LAMBDA
# =============================================================================


def audit_lambda_permissions() -> list:
    findings = []
    for name, fn in STATE["lambdas"].items():
        issues = ["Attached: AdministratorAccess"] if fn["admin"] else []
        if issues:
            _emit("lambda", name, "vulnerable", issues[0])
        else:
            _emit("lambda", name, "ok")
        findings.append({
            "FunctionName": name,
            "Role": fn["role"],
            "Issues": issues if issues else ["OK"],
            "OverPermissioned": bool(issues),
        })
    if not findings:
        return ["No Lambda functions found."]
    if all(f["OverPermissioned"] is False for f in findings):
        update_status("check_lambda", "SAFE")
    return findings


def remediate_lambda_role(function_name: str) -> str:
    fn = STATE["lambdas"].get(function_name)
    if fn is None:
        return f"ERROR: Failed to remediate Lambda '{function_name}': ResourceNotFoundException: Function not found: {function_name}"
    log = []
    if fn["admin"]:
        fn["admin"] = False
        log.append("Detached AdministratorAccess")
    log.append("Attached AWSLambdaBasicExecutionRole")
    update_status("check_lambda", "SAFE")
    return f"SUCCESS: Lambda role '{fn['role']}' remediated. Actions: {'; '.join(log)}"


# =============================================================================
# 7. CLOUDTRAIL
# =============================================================================


def audit_cloudtrail_logging() -> list:
    trails = STATE["cloudtrail"]
    if not trails:
        _emit("cloudtrail", "account", "vulnerable", "no CloudTrail trail exists — all API activity unlogged")
        update_status("check_cloudtrail", "VULNERABLE")
        return [{"status": "NO_TRAILS", "message": "No CloudTrail trails found. All API activity is unlogged."}]

    findings = []
    for name, t in trails.items():
        if t["logging"]:
            _emit("cloudtrail", name, "ok")
        else:
            _emit("cloudtrail", name, "vulnerable", "logging disabled")
        findings.append({
            "TrailName": name,
            "HomeRegion": t["home_region"],
            "IsMultiRegion": t["multi_region"],
            "IsLogging": t["logging"],
        })
    if all(f.get("IsLogging") for f in findings):
        update_status("check_cloudtrail", "SAFE")
    return findings


def remediate_cloudtrail(trail_name: str = "remedi-audit-trail") -> str:
    trails = STATE["cloudtrail"]
    if not trails:
        bucket_name = f"remedi-cloudtrail-{FAKE_ACCOUNT_ID}-{TARGET_REGION}"
        trails[trail_name] = {"home_region": TARGET_REGION, "multi_region": True, "logging": True}
        update_status("check_cloudtrail", "SAFE")
        return (
            f"SUCCESS: Created CloudTrail trail '{trail_name}' "
            f"logging to s3://{bucket_name} (multi-region, log validation enabled)."
        )
    target = trail_name if trail_name in trails else next(iter(trails))
    trails[target]["logging"] = True
    update_status("check_cloudtrail", "SAFE")
    return f"SUCCESS: CloudTrail logging started for trail '{target}'."


# =============================================================================
# 8. FORENSICS
# =============================================================================


def get_resource_owner(resource_name: str) -> str:
    known = set(STATE["s3"]) | set(STATE["ec2"]) | set(STATE["rds"]) | set(STATE["lambdas"])
    if resource_name in STATE["s3"]:
        return f"CloudTrail: '{resource_name}' touched by dev-intern (CreateBucket)."
    if resource_name in known:
        return f"CloudTrail: '{resource_name}' touched by dev-intern (PutRolePolicy)."
    return f"Trace: No recent events for '{resource_name}'."

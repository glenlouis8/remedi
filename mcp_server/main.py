import boto3
import json
import sys
import time
import datetime
from mcp.server.fastmcp import FastMCP
from botocore.exceptions import ClientError
from mcp_server.database import update_status, init_db

def _emit(service: str, resource: str, status: str, msg: str = "") -> None:
    """Prints a structured scan status line to stderr so the frontend can parse it."""
    print(
        "[SCAN] " + json.dumps({"service": service, "resource": resource, "status": status, "msg": msg}),
        file=sys.stderr, flush=True
    )

# Initialize the MCP Server
mcp = FastMCP("Aegis-Hands-Full-Defense")

# Ensure DB is initialized on startup (Critical for Cloud Run)
init_db()

TARGET_REGION = "us-east-1"


def get_boto_client(service_name):
    """Helper to ensure we always target the vulnerable region."""
    return boto3.client(service_name, region_name=TARGET_REGION)


# =============================================================================
# 0. AGENT SELF-CHECK
# =============================================================================


@mcp.tool()
def get_agent_identity() -> str:
    """Verifies the Agent's credentials and target region before acting."""
    sts = get_boto_client("sts")
    try:
        id_info = sts.get_caller_identity()
        return f"Agent Active: {id_info['Arn']} | Target Region: {TARGET_REGION}"
    except Exception as e:
        return f"CRITICAL ERROR: Agent cannot authenticate. {str(e)}"


# =============================================================================
# 1. IAM DOMAIN
# =============================================================================


@mcp.tool()
def list_iam_users() -> str:
    """Lists all IAM users."""
    iam = get_boto_client("iam")
    try:
        paginator = iam.get_paginator("list_users")
        users = [u["UserName"] for page in paginator.paginate() for u in page["Users"]]
        return f"Found Users: {', '.join(users)}"
    except Exception as e:
        return f"Error listing users: {str(e)}"


@mcp.tool()
def list_attached_user_policies(username: str) -> str:
    """Lists managed and inline policies."""
    iam = get_boto_client("iam")
    try:
        policies = []
        for page in iam.get_paginator("list_attached_user_policies").paginate(
            UserName=username
        ):
            for policy in page["AttachedPolicies"]:
                policies.append(f"Managed: {policy['PolicyName']}")
        for page in iam.get_paginator("list_user_policies").paginate(UserName=username):
            for policy_name in page["PolicyNames"]:
                policies.append(f"Inline: {policy_name}")

        result = f"User '{username}' Policies: {', '.join(policies)}" if policies else f"User '{username}' has no attached policies."

        if any(p in result for p in ("AdministratorAccess", "PowerUserAccess")):
            _emit("iam", username, "vulnerable", "has admin-level access")
            result += " [⚠️ CRITICAL SECURITY VIOLATION: NON-ADMIN USER HAS ADMIN ACCESS. MUST CALL restrict_iam_user IMMEDIATELY.]"
        else:
            _emit("iam", username, "ok")
        return result
    except Exception as e:
        return f"Error checking policies for {username}: {str(e)}"


@mcp.tool()
def restrict_iam_user(user_name: str) -> str:
    """
    REMEDIATION: Nukes permissions and applies ReadOnlyAccess.
    """
    iam = get_boto_client("iam")
    log = []
    read_only_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"

    try:
        # Detach Managed
        for page in iam.get_paginator("list_attached_user_policies").paginate(
            UserName=user_name
        ):
            for policy in page["AttachedPolicies"]:
                iam.detach_user_policy(
                    UserName=user_name, PolicyArn=policy["PolicyArn"]
                )
                log.append(f"Detached: {policy['PolicyName']}")
        
        # Remove from Groups (Handle errors gracefully)
        try:
            for page in iam.get_paginator("list_groups_for_user").paginate(UserName=user_name):
                for group in page["Groups"]:
                    iam.remove_user_from_group(UserName=user_name, GroupName=group["GroupName"])
                    log.append(f"Removed from group: {group['GroupName']}")
        except Exception as e:
            log.append(f"Warning (Groups): {str(e)}")

        # Delete Inline (Handle errors gracefully)
        try:
            for page in iam.get_paginator("list_user_policies").paginate(UserName=user_name):
                for policy_name in page["PolicyNames"]:
                    iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
                    log.append(f"Deleted inline policy: {policy_name}")
        except Exception as e:
            log.append(f"Warning (Inline): {str(e)}")
            
        # Attach ReadOnly
        iam.attach_user_policy(UserName=user_name, PolicyArn=read_only_arn)
        log.append("Attached ReadOnlyAccess")

        update_status("check_iam","SAFE")

        return f"SUCCESS: {user_name} neutralized.\nACTIONS: {'; '.join(log)}"
    except Exception as e:
        return f"ERROR: Failed to restrict {user_name}: {str(e)}"


# =============================================================================
# 2. STORAGE DOMAIN
# =============================================================================


@mcp.tool()
def list_s3_buckets() -> str:
    """Lists all bucket names."""
    s3 = get_boto_client("s3")
    try:
        response = s3.list_buckets()
        names = [b["Name"] for b in response.get("Buckets", [])]
        return f"Buckets: {', '.join(names)}"
    except Exception as e:
        return f"Error listing buckets: {str(e)}"


@mcp.tool()
def check_s3_security(bucket_name: str) -> dict:
    """Checks for public access blocks."""
    s3 = get_boto_client("s3")
    try:
        res = s3.get_public_access_block(Bucket=bucket_name)
        c = res["PublicAccessBlockConfiguration"]
        is_public = not all(
            [
                c["BlockPublicAcls"],
                c["IgnorePublicAcls"],
                c["BlockPublicPolicy"],
                c["RestrictPublicBuckets"],
            ]
        )
        if is_public:
            _emit("s3", bucket_name, "vulnerable", "publicly accessible")
        else:
            _emit("s3", bucket_name, "ok")
        return {"bucket": bucket_name, "is_public_risk": is_public}
    except ClientError:
        _emit("s3", bucket_name, "vulnerable", "no public access block configured")
        return {
            "bucket": bucket_name,
            "is_public_risk": True,
            "note": "No Public Access Block found.",
        }
    except Exception as e:
        return {"bucket": bucket_name, "error": str(e)}


@mcp.tool()
def remediate_s3(bucket_name: str) -> str:
    """
    REMEDIATION: Blocks ALL public access.
    """
    s3 = get_boto_client("s3")
    try:
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        update_status("check_s3","SAFE")
        return f"SUCCESS: Public access blocked for bucket '{bucket_name}'."
    except Exception as e:
        return f"ERROR: Failed to remediate S3: {str(e)}"


# =============================================================================
# 3. NETWORK DOMAIN
# =============================================================================


@mcp.tool()
def audit_vpc_network() -> list:
    """
    DISCOVERY: Checks for VPC Flow Logs.
    """
    ec2 = get_boto_client("ec2")
    network_findings = []
    try:
        vpcs = ec2.describe_vpcs()["Vpcs"]
        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            flow_logs = ec2.describe_flow_logs(
                Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
            )["FlowLogs"]
            if flow_logs:
                _emit("vpc", vpc_id, "ok")
            else:
                _emit("vpc", vpc_id, "vulnerable", "flow logs disabled")
            network_findings.append(
                {
                    "VpcId": vpc_id,
                    "FlowLogs": "ENABLED" if flow_logs else "DISABLED (Risk)",
                    "CidrBlock": vpc.get("CidrBlock", "Unknown"),
                }
            )
        return network_findings
    except Exception as e:
        return [f"Network Audit Error: {str(e)}"]


@mcp.tool()
def remediate_vpc_flow_logs(vpc_id: str) -> str:
    """
    REMEDIATION: Creates CloudWatch Log Group, IAM Role, and enables Flow Logs.
    """
    ec2 = get_boto_client("ec2")
    logs = get_boto_client("logs")
    iam = get_boto_client("iam")

    role_name = "AegisFlowLogRole"
    log_group_name = f"/aws/vpc/flowlogs/{vpc_id}"

    try:
        # 1. Create Log Group
        try:
            logs.create_log_group(logGroupName=log_group_name)
        except logs.exceptions.ResourceAlreadyExistsException:
            pass

        # 2. Create IAM Role
        try:
            assume_role = json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            )
            iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=assume_role)

            policy = json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "logs:CreateLogGroup",
                                "logs:CreateLogStream",
                                "logs:PutLogEvents",
                                "logs:DescribeLogGroups",
                                "logs:DescribeLogStreams",
                            ],
                            "Resource": "*",
                        }
                    ],
                }
            )
            iam.put_role_policy(
                RoleName=role_name, PolicyName="FlowLogPolicy", PolicyDocument=policy
            )
            time.sleep(5)
        except iam.exceptions.EntityAlreadyExistsException:
            pass

        role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]

        # 3. Enable Flow Logs
        ec2.create_flow_logs(
            ResourceIds=[vpc_id],
            ResourceType="VPC",
            TrafficType="ALL",
            LogGroupName=log_group_name,
            DeliverLogsPermissionArn=role_arn,
        )
        update_status("check_vpc","SAFE")
        return f"SUCCESS: Flow Logs enabled for {vpc_id}."
    except Exception as e:
        return f"ERROR enabling flow logs: {str(e)}"


@mcp.tool()
def audit_security_groups() -> list:
    """
    DISCOVERY: Scans for 0.0.0.0/0 ingress.
    """
    ec2 = get_boto_client("ec2")
    risky_groups = []
    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        for sg in sgs:
            for perm in sg["IpPermissions"]:
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        port = perm.get("FromPort", "all")
                    _emit("sg", sg["GroupId"], "vulnerable", f"port {port} open to 0.0.0.0/0")
                    risky_groups.append(
                            {
                                "GroupId": sg["GroupId"],
                                "Port": port,
                                "Protocol": perm.get("IpProtocol"),
                                "Risk": "OPEN TO WORLD (0.0.0.0/0)",
                            }
                        )
        
        if not risky_groups:
            update_status("check_ssh", "SAFE")
            return ["No risky Security Groups found. System is SAFE."]
            
    except Exception as e:
        return [f"Error auditing SGs: {str(e)}"]
    return risky_groups if risky_groups else ["No risky Security Groups found."]


@mcp.tool()
def revoke_security_group_ingress(group_id: str) -> str:
    """
    REMEDIATION: Revokes ALL inbound rules open to 0.0.0.0/0 on the given
    security group. One call fixes every exposed port at once.
    """
    ec2 = get_boto_client("ec2")
    try:
        sg = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0]
        public_rules = [
            perm for perm in sg["IpPermissions"]
            if any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
        ]

        if not public_rules:
            update_status("check_ssh", "SAFE")
            return f"SUCCESS: No public ingress rules found on {group_id} (already clean)."

        # Strip to only the 0.0.0.0/0 CidrIp ranges so we don't accidentally
        # revoke private rules on the same permission
        rules_to_revoke = []
        for perm in public_rules:
            rules_to_revoke.append({
                **{k: v for k, v in perm.items() if k != "IpRanges"},
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            })

        ec2.revoke_security_group_ingress(GroupId=group_id, IpPermissions=rules_to_revoke)
        ports = [str(p.get("FromPort", "all")) for p in public_rules]
        update_status("check_ssh", "SAFE")
        return f"SUCCESS: Revoked all 0.0.0.0/0 ingress rules on {group_id} (ports: {', '.join(ports)})."
    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidPermission.NotFound":
            update_status("check_ssh", "SAFE")
            return f"SUCCESS: Rules already revoked on {group_id} (idempotent)."
        return f"ERROR: Failed to revoke ingress on {group_id}: {str(e)}"
    except Exception as e:
        return f"ERROR: Failed to revoke ingress on {group_id}: {str(e)}"


# =============================================================================
# 4. COMPUTE DOMAIN
# =============================================================================


@mcp.tool()
def audit_ec2_vulnerabilities() -> list:
    """
    DISCOVERY: Scans running instances for IMDSv1 and Unencrypted Root Volumes.
    """
    ec2 = get_boto_client("ec2")
    findings = []
    try:
        reservations = ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        )["Reservations"]
        for res in reservations:
            for inst in res["Instances"]:
                imds_status = inst.get("MetadataOptions", {}).get(
                    "HttpTokens", "optional"
                )

                root_dev = inst.get("RootDeviceName")
                encrypted = False
                for bdm in inst.get("BlockDeviceMappings", []):
                    if bdm["DeviceName"] == root_dev:
                        encrypted = bdm.get("Ebs", {}).get("Encrypted", False)

                issues = []
                if imds_status == "optional":
                    issues.append("IMDSv1 enabled")
                if not encrypted:
                    issues.append("unencrypted root volume")
                if issues:
                    _emit("ec2", inst["InstanceId"], "vulnerable", ", ".join(issues))
                else:
                    _emit("ec2", inst["InstanceId"], "ok")
                findings.append(
                    {
                        "InstanceId": inst["InstanceId"],
                        "PublicIP": inst.get("PublicIpAddress", "None"),
                        "IMDSv1_Enabled": (imds_status == "optional"),
                        "RootVolume_Encrypted": encrypted,
                    }
                )
        return findings if findings else ["No running instances found."]
    except Exception as e:
        return [f"Audit Error: {str(e)}"]


@mcp.tool()
def enforce_imdsv2(instance_id: str) -> str:
    """
    REMEDIATION: Enforces IMDSv2.
    """
    ec2 = get_boto_client("ec2")
    try:
        ec2.modify_instance_metadata_options(
            InstanceId=instance_id, HttpTokens="required", HttpEndpoint="enabled"
        )
        update_status("check_ec2","SAFE")
        return f"SUCCESS: IMDSv2 enforced on {instance_id}."
    except Exception as e:
        return f"ERROR: Failed to enforce IMDSv2 on {instance_id}: {str(e)}"


@mcp.tool()
def stop_instance(instance_id: str) -> str:
    """
    REMEDIATION: Stops an instance (Quarantine).
    """
    ec2 = get_boto_client("ec2")
    try:
        ec2.stop_instances(InstanceIds=[instance_id])
        update_status("check_ec2","SAFE")
        return f"SUCCESS: Instance {instance_id} stopped (Quarantined)."
    except Exception as e:
        return f"ERROR: Failed to stop instance {instance_id}: {str(e)}"


# =============================================================================
# 5. RDS DOMAIN
# =============================================================================


@mcp.tool()
def audit_rds_instances() -> list:
    """
    DISCOVERY: Scans all RDS instances for public accessibility.
    A publicly accessible RDS instance is reachable from the internet.
    """
    rds = get_boto_client("rds")
    findings = []
    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                findings.append({
                    "DBInstanceIdentifier": db["DBInstanceIdentifier"],
                    "Engine": db["Engine"],
                    "PubliclyAccessible": db["PubliclyAccessible"],
                    "DBInstanceStatus": db["DBInstanceStatus"],
                })
        if not findings:
            return ["No RDS instances found."]
        for db in findings:
            if db.get("PubliclyAccessible"):
                _emit("rds", db["DBInstanceIdentifier"], "vulnerable", "publicly accessible")
            else:
                _emit("rds", db["DBInstanceIdentifier"], "ok")
        if not any(f["PubliclyAccessible"] for f in findings):
            update_status("check_rds", "SAFE")
        return findings
    except Exception as e:
        return [f"RDS Audit Error: {str(e)}"]


@mcp.tool()
def remediate_rds_public_access(db_instance_identifier: str) -> str:
    """
    REMEDIATION: Disables public accessibility on an RDS instance.
    The database will no longer be reachable from the internet.
    """
    rds = get_boto_client("rds")
    try:
        rds.modify_db_instance(
            DBInstanceIdentifier=db_instance_identifier,
            PubliclyAccessible=False,
            ApplyImmediately=True,
        )
        update_status("check_rds", "SAFE")
        return f"SUCCESS: Public access disabled for RDS instance '{db_instance_identifier}'."
    except Exception as e:
        return f"ERROR: Failed to remediate RDS instance '{db_instance_identifier}': {str(e)}"


# =============================================================================
# 6. LAMBDA DOMAIN
# =============================================================================


@mcp.tool()
def audit_lambda_permissions() -> list:
    """
    DISCOVERY: Scans Lambda functions for over-permissioned execution roles
    (roles with AdministratorAccess or wildcard action policies).
    """
    lambda_client = get_boto_client("lambda")
    iam = get_boto_client("iam")
    findings = []
    try:
        paginator = lambda_client.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page["Functions"]:
                role_arn = fn["Role"]
                role_name = role_arn.split("/")[-1]
                issues = []

                try:
                    for p_page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role_name):
                        for policy in p_page["AttachedPolicies"]:
                            if policy["PolicyName"] in ("AdministratorAccess", "PowerUserAccess"):
                                issues.append(f"Attached: {policy['PolicyName']}")

                    for p_page in iam.get_paginator("list_role_policies").paginate(RoleName=role_name):
                        for policy_name in p_page["PolicyNames"]:
                            doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                            for stmt in doc["PolicyDocument"].get("Statement", []):
                                actions = stmt.get("Action", [])
                                if isinstance(actions, str):
                                    actions = [actions]
                                if "*" in actions and stmt.get("Effect") == "Allow":
                                    issues.append(f"Inline policy '{policy_name}' allows Action: '*'")
                except Exception:
                    pass

                if issues:
                    _emit("lambda", fn["FunctionName"], "vulnerable", issues[0])
                else:
                    _emit("lambda", fn["FunctionName"], "ok")
                findings.append({
                    "FunctionName": fn["FunctionName"],
                    "Role": role_name,
                    "Issues": issues if issues else ["OK"],
                    "OverPermissioned": bool(issues),
                })

        if not findings:
            return ["No Lambda functions found."]

        if not any(f["OverPermissioned"] for f in findings):
            update_status("check_lambda", "SAFE")
        return findings
    except Exception as e:
        return [f"Lambda Audit Error: {str(e)}"]


@mcp.tool()
def remediate_lambda_role(function_name: str) -> str:
    """
    REMEDIATION: Detaches over-permissive policies from a Lambda function's
    execution role and replaces them with AWSLambdaBasicExecutionRole.
    """
    lambda_client = get_boto_client("lambda")
    iam = get_boto_client("iam")
    log = []
    try:
        fn = lambda_client.get_function_configuration(FunctionName=function_name)
        role_name = fn["Role"].split("/")[-1]

        overpermissive = {"AdministratorAccess", "PowerUserAccess"}
        for p_page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role_name):
            for policy in p_page["AttachedPolicies"]:
                if policy["PolicyName"] in overpermissive:
                    iam.detach_role_policy(RoleName=role_name, PolicyArn=policy["PolicyArn"])
                    log.append(f"Detached {policy['PolicyName']}")

        basic_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_arn)
        log.append("Attached AWSLambdaBasicExecutionRole")

        update_status("check_lambda", "SAFE")
        return f"SUCCESS: Lambda role '{role_name}' remediated. Actions: {'; '.join(log)}"
    except Exception as e:
        return f"ERROR: Failed to remediate Lambda '{function_name}': {str(e)}"


# =============================================================================
# 7. CLOUDTRAIL DOMAIN
# =============================================================================


@mcp.tool()
def audit_cloudtrail_logging() -> list:
    """
    DISCOVERY: Checks whether CloudTrail is enabled and actively logging.
    CloudTrail disabled means no audit log of who did what in AWS.
    """
    ct = get_boto_client("cloudtrail")
    findings = []
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        if not trails:
            return [{"status": "NO_TRAILS", "message": "No CloudTrail trails found. All API activity is unlogged."}]

        for trail in trails:
            name = trail["Name"]
            try:
                status = ct.get_trail_status(Name=name)
                is_logging = status.get("IsLogging", False)
            except Exception:
                is_logging = False

            if is_logging:
                _emit("cloudtrail", name, "ok")
            else:
                _emit("cloudtrail", name, "vulnerable", "logging disabled")
            findings.append({
                "TrailName": name,
                "HomeRegion": trail.get("HomeRegion"),
                "IsMultiRegion": trail.get("IsMultiRegionTrail", False),
                "IsLogging": is_logging,
            })

        if all(f.get("IsLogging") for f in findings):
            update_status("check_cloudtrail", "SAFE")
        return findings
    except Exception as e:
        return [f"CloudTrail Audit Error: {str(e)}"]


@mcp.tool()
def remediate_cloudtrail(trail_name: str = "remedi-audit-trail") -> str:
    """
    REMEDIATION: Ensures CloudTrail is active.
    - If no trails exist: creates an S3 bucket, creates a multi-region trail, starts logging.
    - If a trail exists but logging is off: starts logging on it.
    """
    ct = get_boto_client("cloudtrail")
    s3 = get_boto_client("s3")
    sts = get_boto_client("sts")

    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])

        if not trails:
            # No trails — create one from scratch
            account_id = sts.get_caller_identity()["Account"]
            region = boto3.session.Session().region_name or "us-east-1"
            bucket_name = f"remedi-cloudtrail-{account_id}-{region}"

            # Create the S3 bucket
            try:
                if region == "us-east-1":
                    s3.create_bucket(Bucket=bucket_name)
                else:
                    s3.create_bucket(
                        Bucket=bucket_name,
                        CreateBucketConfiguration={"LocationConstraint": region},
                    )
            except s3.exceptions.BucketAlreadyOwnedByYou:
                pass

            # Attach the required CloudTrail bucket policy
            policy = json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AWSCloudTrailAclCheck",
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:GetBucketAcl",
                        "Resource": f"arn:aws:s3:::{bucket_name}",
                    },
                    {
                        "Sid": "AWSCloudTrailWrite",
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/*",
                        "Condition": {
                            "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                        },
                    },
                ],
            })
            s3.put_bucket_policy(Bucket=bucket_name, Policy=policy)

            # Create the trail and start logging
            ct.create_trail(
                Name=trail_name,
                S3BucketName=bucket_name,
                IsMultiRegionTrail=True,
                EnableLogFileValidation=True,
            )
            ct.start_logging(Name=trail_name)
            update_status("check_cloudtrail", "SAFE")
            return (
                f"SUCCESS: Created CloudTrail trail '{trail_name}' "
                f"logging to s3://{bucket_name} (multi-region, log validation enabled)."
            )

        else:
            # Trail(s) exist — find the right one and start logging
            target = trail_name if any(t["Name"] == trail_name for t in trails) else trails[0]["Name"]
            ct.start_logging(Name=target)
            update_status("check_cloudtrail", "SAFE")
            return f"SUCCESS: CloudTrail logging started for trail '{target}'."

    except Exception as e:
        return f"ERROR: Failed to remediate CloudTrail: {str(e)}"


# =============================================================================
# 8. FORENSICS
# =============================================================================


@mcp.tool()
def get_resource_owner(resource_name: str) -> str:
    """
    FORENSICS: Queries CloudTrail for creation events.
    """
    client = get_boto_client("cloudtrail")
    try:
        response = client.lookup_events(
            LookupAttributes=[
                {"AttributeKey": "ResourceName", "AttributeValue": resource_name}
            ],
            MaxResults=10,
        )
        for event in response.get("Events", []):
            if any(x in event.get("EventName", "") for x in ["Create", "Run", "Put"]):
                return f"CloudTrail: '{resource_name}' touched by {event.get('Username')} ({event.get('EventName')})."
        return f"Trace: No recent events for '{resource_name}'."
    except Exception as e:
        return f"Forensic Error: {str(e)}"


# @mcp.tool()
# def archive_security_incident(report_summary: str) -> str:
#     """Saves findings to JSON."""
#     timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
#     filename = f"aegis_audit_{timestamp}.json"
#     try:
#         with open(filename, "w") as f:
#             json.dump({"timestamp": timestamp, "report": report_summary}, f, indent=4)
#         return f"SUCCESS: Report saved to {filename}."
#     except Exception as e:
#         return f"ERROR: {str(e)}"

if __name__ == "__main__":
    mcp.run()

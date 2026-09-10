from mcp_server.database import get_connection

# Maps our internal check IDs to CIS AWS Foundations Benchmark controls
CIS_CONTROLS = {
    "check_iam": {
        "cis_id": "1.16",
        "cis_title": "Ensure IAM policies are attached only to groups or roles",
        "category": "Identity & Access Management",
    },
    "check_s3": {
        "cis_id": "2.1.5",
        "cis_title": "Ensure S3 buckets are configured with Block Public Access",
        "category": "Storage",
    },
    "check_vpc": {
        "cis_id": "3.9",
        "cis_title": "Ensure VPC flow logging is enabled in all VPCs",
        "category": "Logging",
    },
    "check_ec2": {
        "cis_id": "5.6",
        "cis_title": "Ensure EC2 instances use IMDSv2 and encrypted volumes",
        "category": "Compute",
    },
    "check_ssh": {
        "cis_id": "5.2",
        "cis_title": "Ensure no security groups allow unrestricted SSH access",
        "category": "Networking",
    },
    "check_rds": {
        "cis_id": "2.3.3",
        "cis_title": "Ensure that public access is not given to RDS instances",
        "category": "Database",
    },
    "check_lambda": {
        "cis_id": "5.4",
        "cis_title": "Ensure Lambda function execution roles follow least privilege",
        "category": "Compute",
    },
    "check_cloudtrail": {
        "cis_id": "3.1",
        "cis_title": "Ensure CloudTrail is enabled and logging in all regions",
        "category": "Logging",
    },
}


def get_cis_score(user_id: str) -> dict:
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT id, status FROM compliance_checks WHERE user_id = %s", (user_id,))
        rows = c.fetchall()
    finally:
        conn.close()

    row_status = {r[0]: r[1] for r in rows}

    # Iterate the fixed control set — not just the rows that happen to exist — so
    # a control that was never written (new user, or a scan that errored before
    # writing statuses) counts as not-passing instead of being dropped from the
    # denominator and inflating the percentage.
    controls = []
    passing = 0
    for check_id, meta in CIS_CONTROLS.items():
        status = row_status.get(check_id, "UNKNOWN")
        is_passing = status == "SAFE"
        if is_passing:
            passing += 1
        controls.append({
            "check_id": check_id,
            "cis_id": meta["cis_id"],
            "cis_title": meta["cis_title"],
            "category": meta["category"],
            "status": status,
            "passing": is_passing,
        })

    total = len(CIS_CONTROLS)
    percentage = int((passing / total) * 100)

    return {
        "score": passing,
        "total": total,
        "percentage": percentage,
        "controls": controls,
    }

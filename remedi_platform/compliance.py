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


def get_cis_score() -> dict:
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT id, status FROM compliance_checks")
        rows = c.fetchall()
    finally:
        conn.close()

    controls = []
    passing = 0

    for row in rows:
        check_id, status = row[0], row[1]
        meta = CIS_CONTROLS.get(check_id)
        if not meta:
            continue
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

    total = len(controls)
    score = passing
    percentage = int((passing / total) * 100) if total > 0 else 0

    return {
        "score": score,
        "total": total,
        "percentage": percentage,
        "controls": controls,
    }

# Remedi

**AI-powered AWS security scanner and auto-remediator.**

**Live:** https://remedi-kohl-seven.vercel.app/

Remedi scans your AWS account across 8 services, generates a structured findings report, pauses for human approval, then automatically fixes every vulnerability it found. A verification pass confirms the fixes held.

---

## How it works

Five-phase pipeline built on LangGraph with a mandatory human-in-the-loop safety gate:

```
orchestrator → report_generator → safety_gate ─[your approval]─► remediator → verifier → done
```

1. **Scan** — 8 specialist AI agents run in parallel (one per AWS service). Each agent has its own LLM call loop, dedicated tool set, and structured output format.
2. **Report** — findings are synthesized into a remediation plan. Every vulnerability is mapped to the exact tool that fixes it. CIS Benchmark controls are updated.
3. **Safety gate** — execution halts. You review the plan in the dashboard and approve or abort. Nothing is changed without your sign-off.
4. **Remediate** — all approved fixes run in parallel. Every action is logged with duration and outcome.
5. **Verify** — the agent re-audits only the resources it fixed, confirms the fixes held, and closes the scan.

---

## Services covered

| Service | What it checks | Auto-fix |
|---------|---------------|----------|
| **IAM** | Users with `AdministratorAccess` or `PowerUserAccess` | Strips all policies, attaches `ReadOnlyAccess` |
| **S3** | Buckets with public access enabled | Enables all 4 Block Public Access flags |
| **VPC** | VPCs with flow logs disabled | Creates CloudWatch log group + IAM role + enables flow logs |
| **Security Groups** | Inbound rules open to `0.0.0.0/0` | Revokes the specific public rules (private rules untouched) |
| **EC2** | IMDSv1 enabled; unencrypted root volumes | Enforces IMDSv2; stops instance (quarantine) |
| **RDS** | Publicly accessible database instances | Sets `PubliclyAccessible = false` immediately |
| **Lambda** | Execution roles with `AdministratorAccess` or wildcard `Action: *` | Detaches over-permissive policies, attaches `AWSLambdaBasicExecutionRole` |
| **CloudTrail** | Logging disabled or no trails exist | Creates trail + S3 bucket with correct policy; starts logging |

---

## Architecture

```
┌──────────────────────────────────────────────────┐
│                   frontend/                       │
└───────────────────┬──────────────────────────────┘
                    │ HTTP / StreamingResponse
┌───────────────────▼──────────────────────────────┐
│                  server.py                        │
│           FastAPI · ProcessManager                │
│   Clerk JWT auth · Fernet encryption · PostgreSQL │
└───────────────────┬──────────────────────────────┘
                    │ subprocess (stdin/stdout)
┌───────────────────▼──────────────────────────────┐
│                   main.py                         │
│         LangGraph agent pipeline (5 phases)       │
│   orchestrator · report_generator · safety_gate   │
│           remediator · verifier                   │
└───────────────────┬──────────────────────────────┘
                    │ MCP JSON-RPC over stdio
┌───────────────────▼──────────────────────────────┐
│             mcp_server/main.py                    │
│         FastMCP · boto3 · All AWS API calls       │
└──────────────────────────────────────────────────┘
```

**Key design decisions:**

- **MCP subprocess isolation** — all boto3 calls live in a separate process (`mcp_server/main.py`). The agent communicates via JSON-RPC over stdio (the Model Context Protocol). AWS credentials never touch the main process.
- **Parallelism model** — the orchestrator fires all 8 specialist agents simultaneously via `ThreadPoolExecutor`. Tool calls within a single agent are sequential (the MCP pipe is single-threaded). The remediator also parallelizes — all approved fixes run concurrently.
- **No LLM parse step in remediation** — the remediator regex-parses the report directly (`🔴 [CRITICAL] <resource> is vulnerable -> ACTION: I will call \`tool_name\``). No extra LLM call, no JSON, no latency.
- **Token optimization** — the report generator receives only the auditor's final summary, not the full tool call history. Saves ~80% of tokens vs passing the entire message chain.

---

## Tech stack

**Backend:** Python · FastAPI · LangGraph · Google Gemini · MCP · PostgreSQL · Clerk  
**Frontend:** Next.js 15 · TypeScript · Tailwind CSS · Clerk  
**Infrastructure:** Railway · CloudFormation · Terraform (test env)

---

## Getting started

**[remedi-kohl-seven.vercel.app](https://remedi-kohl-seven.vercel.app/)** — sign in, connect your AWS account, and run a scan.

---

## CIS Benchmark compliance

Every check maps to a CIS AWS Foundations Benchmark control. The dashboard tracks pass/fail per control and shows an overall compliance score that updates live after each scan.

| CIS Control | Check |
|-------------|-------|
| 1.16 | IAM policies not attached directly to users |
| 2.1.5 | S3 Block Public Access configured |
| 2.3.3 | RDS instances not publicly accessible |
| 3.1 | CloudTrail enabled in all regions |
| 3.9 | VPC flow logging enabled |
| 5.2 | No security groups with unrestricted access |
| 5.4 | Lambda execution roles follow least privilege |
| 5.6 | EC2 instances use IMDSv2 and encrypted volumes |

---

## Credential security

AWS credentials are never stored in plaintext:

- **Fernet encryption at rest** — access and secret keys are encrypted before writing to PostgreSQL
- **30-minute inactivity purge** — a background thread deletes credentials idle for more than 30 minutes
- **Explicit delete on sign-out** — credentials are wiped immediately when the user logs out
- **Auto-protect** — the IAM user whose credentials are in use is always added to the protected list and can never be remediated

---

## Known limitations

- **Single-region** — scans `us-east-1` only. Resources in other regions are not visible to the scanner.
- **EC2 root volume re-encryption** — not automated. Instances with unencrypted root volumes are quarantined (stopped) instead of re-encrypted. Full re-encryption requires a manual snapshot workflow.
- **`AegisFlowLogRole`** — the IAM role created during VPC flow log remediation persists in your account across scans. Delete it manually if you want a clean teardown.
- **3 scans per account per day** — rate limit enforced on the platform.

---

## Testing

25 tests covering the critical paths — no external services required.

```bash
# Install test dependencies
uv add pytest "moto[s3,iam,ec2,rds,cloudtrail,logs]" httpx --dev

# Run
.venv/bin/python -m pytest tests/ -v
```

| File | What it tests |
|------|--------------|
| `tests/test_remediator.py` | Regex parser that extracts remediation tasks from the AI report — the single point of failure if the LLM drifts |
| `tests/test_accounts.py` | Fernet encryption round-trips, missing key error handling |
| `tests/test_mcp_tools.py` | Real production boto3 code running against moto's in-memory AWS — S3, IAM, security groups, EC2, RDS |

---

## Deployment

Deployed on Railway. The backend (`uvicorn server:app`) and frontend (Next.js) run as separate Railway services. `railway.toml` sets the start command. `frontend/Dockerfile` handles the containerized frontend build.

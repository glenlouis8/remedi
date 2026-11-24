# Remedi LLM eval report

Model under test: `gemini-3.8-flash` (temperature 0). Account: us-east-1, live AWS + live Gemini.

Before this work Remedi had only deterministic pytest tests (58 pass, moto mocks). Nothing measured the LLM parts. This report covers the 4 evals added in `evals/`, what they found, and what they do not cover.

## Setup

- Ground truth comes from `terraform/test_env.tf` (7 planted vulns) via `terraform output -json`.
- `terraform/decoys.tf` adds 7 healthy lookalikes with scary names (`-var deploy_decoys=true`) to measure false alarms.
- The MCP server is replaced by in-process tools and `mcp_server.database` is stubbed, so evals never write to the prod Postgres.
- The account already has a real, logging CloudTrail trail. The live evals skip CloudTrail and never touch the trail.

## Results

| Eval | What it tests | Result |
|---|---|---|
| `format_eval.py` | Report generator output format, resource/tool/severity match, protected users excluded. 6 frozen cases x 3 runs | 18/18 |
| `detection_eval.py` | 8 specialists find the planted vuln with the prescribed severity. Live, 10 runs | 70/70 recall, severity correct |
| `detection_eval.py` | False alarms on 7 healthy decoys | 10/10 runs flagged the EC2 decoy before fix, 0 after (35/35 recall at 5 runs after fix) |
| `judgment_eval.py` | Specialists read canned messy tool output: scary-named safe resources, API errors, mixed lists, clean accounts. 14 cases x 3 runs | 42/42 |
| `fix_eval.py` | Full pipeline: approve only planted resources, remediate, verify. Fixes checked independently with boto3 | 7/7 fixes held, verifier verdict matched reality |

## Bugs found

1. **EC2 false positive (real prod bug).** `audit_ec2_vulnerabilities` read `Encrypted` from `describe_instances`, which does not return that key. A missing key defaulted to False, so every instance was flagged as unencrypted. In a real account the remediator would stop healthy instances. Caught because the decoy EC2 was flagged 10/10. Fix: look up the volume with `describe_volumes`; if the lookup fails, treat as unknown and do not flag (`mcp_server/main.py`).
2. **Verifier crash on the new model.** `gemini-3.8-flash` rejects a conversation that ends on a model turn (HTTP 400). The first fix_eval run crashed in the verifier after remediation had already applied. Fix: append a HumanMessage nudge, and make the forced retry message a HumanMessage (`agents/nodes.py`).

## Limits

- CloudTrail is not tested live (account has a real trail). Covered only by canned cases in `judgment_eval.py`.
- Small samples: one planted vuln per service, 5 to 10 runs.
- The EC2 "closed" check accepts either stopped or IMDSv2 required.
- `fix_eval` leaves `AegisFlowLogRole` and `/aws/vpc/flowlogs/*` log groups behind (known Remedi limit). Delete them by hand after each run.
- Live evals cost real Gemini calls and AWS resources. Run `terraform destroy` after.

## How to run

```bash
cd terraform && terraform apply -var deploy_decoys=true
uv run python evals/detection_eval.py --runs 10
uv run python evals/fix_eval.py
uv run python evals/judgment_eval.py
uv run python evals/format_eval.py
cd terraform && terraform destroy -var deploy_decoys=true
```

`fix_eval` attaches policies outside terraform, so detach `ReadOnlyAccess` from `remedi-test-admin-user` before destroy or it fails with DeleteConflict.

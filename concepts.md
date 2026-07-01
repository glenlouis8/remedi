# Remedi — Concepts to Know

## Agent / AI
- LangGraph — nodes, edges, state, human-in-the-loop
- LangChain tool use — how LLM decides to call a tool
- Prompt engineering — structured output, regex-parseable format
- Agentic parallelism — ThreadPoolExecutor for sub-agents

## Infrastructure / Backend
- FastAPI — routes, `Depends()`, `StreamingResponse`
- Subprocess — spawn, stdin/stdout, streaming output to client
- Celery + Redis — task queue, worker, why it exists
- PostgreSQL — basic CRUD, Fernet encryption at rest

## AWS (the domain)
- IAM — users, roles, policies, least privilege
- S3 — bucket policies, public access blocks
- VPC — flow logs, security groups
- boto3 — how Python talks to AWS

## Frontend
- Next.js App Router — server vs client components, middleware
- Clerk — JWT, `useAuth`, protected routes
- Streaming reads — how browser reads `StreamingResponse` line-by-line
- State machine — `idle → scanning → awaiting_approval → remediating → complete`

## MCP
- What MCP is — protocol for LLM ↔ tool servers
- JSON-RPC over stdio — how messages flow
- Why single pipe = no concurrent calls

## Testing
- moto — mock AWS without real credentials
- pytest fixtures, `conftest.py` module-level mocking

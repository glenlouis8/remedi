# Bug verdicts — supervisor pass

67 agent-reported findings, checked against source by reading every file involved.
Verdict key:
- **CONFIRMED** — real, unambiguous in code (some reproduced)
- **CONFIRMED / NARROWER** — real bug, but impact was overstated
- **FALSE POSITIVE** — not a bug, or already handled
- **UNPROVEN** — depends on LLM output nobody has measured; real fragility, not a confirmed defect

---

## CRITICAL

### C1 — `active_scans` counter leak → permanent server-wide 503 · `server.py:383-390`
**CONFIRMED.** Line 383 `r.incr("active_scans")`. The 503 branch (385) decrements; the 429 daily-limit branch (390) raises **without decrementing**, and `run_scan_task.delay()` at 420 never runs, so the worker's `finally: r.decr` (`worker.py:31`) never fires. The `active_scans` key has no TTL (`incr`, never `set ... ex`) and nothing resets it on boot. 3 users hitting their daily cap 3× each → `active_scans` stuck ≥3 → every `/api/run-agent` returns 503 forever. Redeploy doesn't clear it (Upstash persists).

### C2 — `FINDING` regex drops all but the last finding · `nodes.py:103, 331`
**CONFIRMED / NARROWER.** Reproduced:
```
findall (no MULTILINE): 1 of 3   -> ['carol']
findall (re.MULTILINE): 3 of 3   -> ['alice','bob','carol']
```
Root cause: `...(?:\|\s*FIX:\s*(.+))?$` with no `re.MULTILINE`, so `$` only matches string end.

**Why it's not the catastrophe first reported:** the approval UI's finding list (`remediationPlan`, `dashboard/page.tsx:411`) is built by the frontend parsing the raw `🔴` report lines from the SSE stream directly — *not* from the lossy `[SCAN]` events. So "Approve all" still approves every resource, and the report generator (`nodes.py:447`) receives the full multi-line auditor text, so the remediator can still fix all of them.

**Residual real harm:**
1. `[SCAN]` events (`nodes.py:334, 347`) → only the last resource per service → the **service cards** under-count vulnerabilities and stay red after a fix for the unshown ones.
2. `_run_sub_agent` fallback (`nodes.py:177`): `accumulated_findings` also only ever gets the last finding per turn (same regex). If the specialist's final message ends with any non-FINDING prose, `finding_pattern.search(final_text)` fails and `text` is rebuilt from that single accumulated line → the report generator genuinely only sees one finding → only one fix. This is the real integrity bug; it needs the specialist to emit trailing prose (uncommon, not rare).

One-line fix (`re.MULTILINE` on both patterns) fixes all of it. Severity: **HIGH**, not CRITICAL, because of the accidental frontend safety net on the common path.

### C3 — `REMEDIATION_LINE_PATTERN` strict; lenient CIS-flip regex diverges · `patterns.py:9` + `nodes.py:459, 834`
**CONFIRMED (mechanism) / UNPROVEN (trigger rate).** Reproduced:
```
'-> ... I will call `x`'   strict=True   lenient=True
'→  ... I will call `x`'   strict=False  lenient=True    <-- divergence
'-> ... I will call **x**' strict=False  lenient=False
'-> ... I will run `x`'    strict=False  lenient=False
```
If Gemini emits a Unicode arrow (`→`), the remediator (`nodes.py:615`) parses **zero tasks** and applies zero fixes, but `findings_count` (`nodes.py:459`) and the post-verify CIS flip (`nodes.py:834`) use the lenient `I will call \`x\`` regex and still fire → scan shows findings + dashboard turns green with nothing fixed. Nothing asserts `parsed_tasks == findings_count`. Whether `gemini-3-flash-preview` at `temperature=0` actually deviates from the `->` in the prompt is unmeasured — the risk is real, the occurrence rate is unknown. Fix: loosen the strict pattern (accept `->`/`→`/`—`, optional `*`/`_`) **and** assert the two counts match.

---

## HIGH

### H1 — `active_scans` leak on any exception between incr and dispatch · `server.py:383-420`
**CONFIRMED.** No `try/finally` around 383-420. `count_scans_today` (388), `get_protected_users` (404), `r.set` (417), `run_scan_task.delay` (420) each raise on DB/Redis/broker trouble → slot leaked (same mechanism as C1). The STS block (395-402) *is* guarded; these are not.

### H2 — no startup reconciliation of `active_scans`; SIGKILL skips `finally` · `worker.py:31`, `server.py`
**CONFIRMED.** Nothing sets `active_scans` to 0 on boot. Render deploy/OOM → SIGKILL → the task's `finally` doesn't run → leaks accumulate for the life of the Redis instance. This is what turns C1/H1 from "annoying" into "permanent".

### H3 — `r.decr` has no floor → negative counter → unlimited concurrency · `worker.py:31`
**CONFIRMED.** If the key is evicted/reset while tasks are in flight, their `finally: r.decr` drives it negative; `server.py:384 if active > MAX_CONCURRENT_SCANS` then passes for many extra scans until it climbs back. Needs a triggering eviction/reset, but the fix (`max(0, ...)` via Lua, or set-based tracking) is cheap.

### H4 — worker read loop unguarded; exception orphans subprocess + hangs every SSE client · `worker.py:62-90`
**CONFIRMED.** No `try/except` around the loop. `r.xadd` (67) failing on a Redis blip, or `process.stdin.write` (85) raising `BrokenPipeError`, propagates out. `finally` releases the counter, but: the subprocess is never `wait()`ed/killed (orphan), `scan:{id}:status` stays `running`, `__DONE__` is never written. `server.py`'s `stream()` generator (426-450) then loops forever — `xread` times out every 5s, status ≠ done/aborted → `yield ": heartbeat\n"` → forever. Each connected browser holds a server thread + an `r_stream` connection indefinitely.

### H5 — worker `readline` blocks forever if the MCP subprocess is orphaned · `worker.py:62`
**CONFIRMED.** `mcp_client.py` runs the MCP session in a `daemon=True` thread (line 85). When `main.py`'s main thread exits (normally or via exception), the daemon thread is killed **without** running `stdio_client`'s async cleanup → the `mcp_server.main` subprocess is orphaned, and its stderr fd (merged into `main.py` stdout → the worker's pipe via `stderr=STDOUT`) stays open → the worker's `for line in iter(process.stdout.readline, "")` never sees EOF → blocks forever. With Celery `--concurrency=1` (`start.sh:5`) and no `soft_time_limit`, **every subsequent scan queues behind it indefinitely.**

### H6 — abort / decline / timeout paths don't fully kill the scan · `worker.py:75-84`
**CONFIRMED / NARROWER.** `process.terminate()` (SIGTERM) with **no `process.wait()`** (zombie until Celery reaps) and **no SIGKILL escalation**. `Popen` has no `start_new_session=True`, so `main.py`'s children aren't in a killable group. These early `return`s also never write `__DONE__` or set a TTL on `scan:{id}:stream` → stream key leaks (only the happy path, 99-100, cleans up).
*Overstated part:* at the approval gate `main.py` is blocked in `input()` and has **not** started remediation, so "AWS mutation continues after the user declined" is not accurate for the gate path. The zombie + stream-key-leak + SSE-hang parts are real.

### H7 — decrypted AWS secret keys transit the Celery broker in plaintext · `server.py:392,420` → `worker.py:26`
**CONFIRMED.** `env = dict(creds)` holds the decrypted `AWS_SECRET_ACCESS_KEY`; `run_scan_task.delay(scan_id, user_id, env)` serializes it (JSON) into the Upstash broker queue, where it sits until consumed and appears in any Celery task-failure traceback that logs `args`. The Fernet-at-rest design is bypassed while queued. TLS-in-transit and short lifetime are mitigations, not a fix. For a security-posture product this is worth fixing (pass a short-TTL Redis key, decrypt in the worker).

### H8 — `start.sh` has no supervision; SIGTERM not forwarded · `start.sh`
**CONFIRMED.** `set -e` can't catch a backgrounded celery crash → uvicorn keeps serving, Render health check stays green, scans queue forever, `active_scans` climbs → silent total outage. No `trap`/`exec` → Render's deploy SIGTERM hits bash (PID 1) and is not forwarded → uvicorn + celery are SIGKILLed after the grace period → in-flight scan interrupted mid-write + counter leak (H2).

### H9 — `enforce_imdsv2` blocks the single MCP pipe up to ~60s · `mcp_server/main.py:498-509` (+ `:339`)
**CONFIRMED.** `for attempt in range(30): ... time.sleep(2)` on `IncorrectInstanceState`. All MCP tool calls are serialized through one stdio pipe (`mcp_client.py:_call_lock`), so one instance stuck in this retry loop freezes every other concurrent audit/remediation call in the scan. `remediate_vpc_flow_logs:339` adds another `time.sleep(5)`.

### H10 — remediation tools write `check=SAFE` on partial / no-op paths · `mcp_server/main.py:412,426,430,503,522` etc.
**CONFIRMED / NARROWER.** `revoke_security_group_ingress` writes `check_ssh=SAFE` after fixing one group (others may still be open), and on its "already clean" / `NotFound` branches; `enforce_imdsv2`/`stop_instance` write `check_ec2=SAFE` though unencrypted volumes are never remediated. `/api/compliance` (60s cache) can show a control "passing" mid-remediation.
*Context that softens it:* the report generator already wrote that check's status **this scan** (`nodes.py:502`, all 8 checks), and the verifier re-confirms afterward. The premature-SAFE window is transient (bounded by the rest of the remediation + verify phase + 60s cache). Still wrong to write authoritative state from individual fix tools; severity **MEDIUM**.

### H11 — `mcp_client` timed-out tool call is never cancelled · `agents/mcp_client.py:42-49`
**CONFIRMED.** `future.result(timeout=60)` raises, the `with _call_lock` block exits and releases the lock, but the coroutine keeps running on `_loop`. The next tool call acquires the lock and starts its own coroutine on the same MCP session → two JSON-RPC exchanges interleaving on the one stdio pipe — exactly what `_call_lock` exists to prevent. A >60s AWS call is plausible with throttling or a large account. Fix: `future.cancel()` + treat a timeout as fatal (tear down and reconnect the session).

### H12 — verifier loop has no iteration cap · `agents/graph.py:66-71`
**CONFIRMED / latent.** `should_verify_continue` routes back to `verify_tools` while the LLM emits `tool_calls`, with no counter (unlike `_run_sub_agent`'s `MAX_TOOL_ITERATIONS=15`). `main.py:25` sets `recursion_limit: 25`. A tool-happy verifier re-auditing many resources hits `GraphRecursionError` **after** remediation already ran → account fixed, scan recorded FAILED/unverified. Usually converges in 1-3 turns, so latent.

### H13 — `interrupt_before=["remediator"]` fires even on a clean scan · `agents/graph.py:76`
**FALSE POSITIVE for the server path; real only for a hypothetical caller.** `safety_gate → remediator` is unconditional and the graph always interrupts, BUT:
- **CLI (`main.py`)**: after the stream, it calls `app.get_state`; on a clean scan `"SYSTEM SECURE"` is in `audit_summary` → it prints the conclusion and `return`s (`main.py:83-95`) — never resumes, no hang.
- **Server (`worker.py`)**: the worker only blocks on `blpop` when it sees `[ACTION_REQUIRED]` in the output (`worker.py:69`). On a clean scan the safety gate does **not** print that line (`nodes.py:528-531`), so the worker never blocks — it keeps reading stdout, `main.py` exits at the interrupt on its own, `readline` hits EOF, `process.wait()`, `__DONE__`. No hang.
The dead `remediation_tools` node/edge is real (see L-graph), but the "clean scan stalls to the 30-min timeout" claim does not hold for either real caller.

### H14 — no `reset_to_vulnerable` call anywhere · `mcp_server/database.py:270`, imported `server.py:15`
**CONFIRMED / NARROWER.** `reset_to_vulnerable` is imported and never called. So there's no "assume vulnerable until this scan re-proves safe" reset.
*Softening:* every scan, `report_generator_node` rewrites **all 8** checks (`nodes.py:483-502`) as VULNERABLE/SAFE — the loop's `continue` guard (`:485`) can't actually skip, because the orchestrator always emits all 8 `=== SVC ===` headers (`nodes.py:392-394`). So a check only goes stale if `report_generator_node` **throws before line 502** (e.g. the un-try/caught `llm.invoke` at 447 hits a rate limit). Then old values persist and the dashboard shows no "stale" indicator. Real gap, needs an LLM failure to bite; severity **MEDIUM**.

### H15 — frontend: no in-flight guard on `startScan` · `dashboard/page.tsx:309, 695`
**CONFIRMED / NARROWER.** `startScan` has no re-entrancy check; "I understand, run scan" (695) and "Scan again" (1209, not in this page slice) aren't `disabled` while a request is pending. A genuine double-click fires two `POST /api/run-agent` → two `r.incr` → two Celery scans → burns 2 of the 3 daily → two reader loops mutating state, `abortRef.current` clobbered so only one is abortable. The window is one handler tick (`setShowDisclaimer(false); startScan()` is synchronous, modal unmounts next render), so it needs a real double-click, not just a slow render. Severity **MEDIUM**.

---

## MEDIUM

### M1 — CIS `%` denominator is dynamic, not fixed at 8 · `remedi_platform/compliance.py:77-79`
**CONFIRMED / NARROWER.** `total = len(controls)` counts only rows that exist for the user. Agent scenario ("writes 3/8 → shows 100%") is **not reachable** in normal flow because `report_generator_node` writes all 8 every scan. It bites only: (a) brand-new user, 0 rows → `percentage = 0` (harmless, shows 0%); (b) `report_generator_node` throws before writing → stale/partial rows. Still a latent correctness bug — iterate `CIS_CONTROLS` (always 8), missing = failing.

### M2 — `has_issues` is a crude case-folded substring match · `nodes.py:350-360, 491-501`
**CONFIRMED.** Keywords `["CRITICAL","HIGH","FINDING:","VULNERABLE","EXPOSED","PUBLIC"]` matched as substrings against `section.upper()`. `"PUBLIC"` matches `"NO PUBLIC ACCESS"`, `"HIGH"` matches `"HIGHLY"` → false VULNERABLE (safe direction). A raw audit payload like `"Risk": "OPEN TO WORLD (0.0.0.0/0)"` contains none of the tokens → false SAFE if the specialist didn't emit a `FINDING:`/severity line (dangerous direction). Specialists are prompted to emit `FINDING: ... | SEVERITY: HIGH`, which contains two of the tokens, so it usually catches — fragile, not reliably broken.

### M3 — unauthenticated JWKS refetch amplification · `remedi_platform/auth.py:27-34`
**CONFIRMED.** `get_current_user` calls `jwt.get_unverified_header(token)` (attacker controls `kid`) before any signature check; an unknown `kid` triggers `_get_jwks(force=True)` — a blocking `httpx.get` to Clerk with no explicit timeout (httpx default 5s) and no rate limit / negative cache. A stream of random-`kid` tokens each holds a FastAPI threadpool worker up to 5s and can get your backend key rate-limited by Clerk. Fix: negative-cache misses, cap forced refetches, set a short timeout.

### M4 — `_jwks_cache` mutated from threadpool workers without a lock · `auth.py:16-24`
**CONFIRMED / low impact.** Concurrent requests after TTL expiry all fetch and all assign. CPython makes the assignment effectively atomic, so the practical effect is redundant network fetches, not corruption. Add a `threading.Lock`.

### M5 — `aud` never verified; `iss` verified only if undocumented `CLERK_ISSUER` is set · `auth.py:50-56`
**CONFIRMED / low.** `CLERK_ISSUER` is not in `render.yaml` or the documented env list → almost certainly unset in prod → `verify_iss=False`, `verify_aud=False`. Signature (RS256, pinned) + `exp` are still enforced, and `kid` is matched against this instance's JWKS, so cross-instance tokens don't pass. Missing `aud`/`azp` binding is a defense-in-depth gap, not an open door.

### M6 — Fernet decrypt failure is unhandled → opaque 500 · `remedi_platform/accounts.py:57-61`
**CONFIRMED.** `f.decrypt(...)` with no try/except; a rotated/invalid `ENCRYPTION_KEY` or a corrupt row turns every credentialed endpoint into a 500. Catch `InvalidToken`/`ValueError`, return a "reconnect your account" 4xx, consider `MultiFernet` for rotation.

### M7 — `count_scans_today` daily-limit check is TOCTOU · `server.py:388-390`
**CONFIRMED / low.** Two concurrent `/api/run-agent` both read `used=2`, both pass. Self-owned limit — impact is 4 scans that day, not a tenant breach.

### M8 — 3-account limit is TOCTOU · `server.py:121-126` + `accounts.py`
**CONFIRMED / low.** `count_aws_accounts` then `save_aws_credentials` are separate statements, no txn, no count constraint. Two concurrent distinct `account_name`s → 4+ rows. Self-owned; storage impact only.

### M9 — SSE `xread`-error branch has no backoff · `server.py:427-435`
**CONFIRMED.** `block=5000` only paces the success path. A persistently broken `r_stream` (Upstash down, DNS) makes `xread` raise immediately → tight loop hammering CPU and flooding the client with heartbeats. Add `time.sleep(1-2)` in the except branch and bail after N consecutive failures.

### M10 — decision list: disconnect pushes `abort`, LIFO pop beats a real `approve` · `server.py:453,477` + `worker.py:74`
**CONFIRMED.** `GeneratorExit` (tab close/refresh) does `r.lpush(scan:{id}:decision, "abort")` unconditionally, even past the gate. If a user clicks Approve then immediately closes the tab, the list becomes `["abort","approve"]` and the worker's single `blpop` pops `"abort"` (head) → scan aborted despite the approval. Also no TTL on the list → the leftover entry lingers. Gate the disconnect-abort on scan phase; give the list a TTL; drain it after the gate.

### M11 — queued scan has no `owner` → `/api/stop` 403s the owner · `worker.py:59` vs `server.py:483`
**CONFIRMED.** `scan:{id}:owner` is set only when `_run_scan_task` starts. While a scan is queued behind another (`--concurrency=1`), `/api/stop` and `/api/approve` do `r.get(...owner...) → None ≠ user["sub"]` → 403 "Not your scan". The user can't cancel their own queued scan and the message implies it's someone else's. Set `owner` + `queued` status in `/api/run-agent` before `.delay()`.

### M12 — worker spawn-failure message goes to a channel nobody reads · `worker.py:53-54`
**CONFIRMED.** `r.publish(scan:{id}:output, ...)` (pub/sub) but `server.py`'s stream reads `r_stream.xread(scan:{id}:stream)` (stream) — different key, different mechanism, leftover from an old design. On spawn failure the user's SSE never shows the `[ERROR]` line; the stream just closes ~5s later when the status poll sees `done`. Use `r.xadd(...:stream, {"line": ...})` + `__DONE__`.

### M13 — `init_db()` blocks import up to 60s and hard-raises · `server.py:65-76`
**CONFIRMED.** 30 × 2s at import time (also runs because `server` imports `worker`). Can exceed Render's port-bind deadline and fail the deploy; on final failure it `raise`s, killing uvicorn while the already-backgrounded celery keeps running (H8). Shorten the budget or make init lazy.

### M14 — `init_db` runs unguarded DDL on every MCP subprocess start · `mcp_server/database.py:61-181`
**CONFIRMED / low-probability.** No advisory lock around `CREATE TABLE IF NOT EXISTS` + `ALTER` + introspect-then-`DROP/ADD CONSTRAINT`. With `MAX_CONCURRENT_SCANS=3` three `main.py` → three MCP servers can run this simultaneously; Postgres can raise on concurrent `CREATE TABLE IF NOT EXISTS` (`duplicate key pg_type`) or a double `DROP CONSTRAINT`. Also `conn` leaks on any exception (no `try/finally` around the cursor work). Startup-only. Gate behind `pg_advisory_lock` or move migrations to deploy.

### M15 — `audit_security_groups` ignores IPv6 `::/0` · `mcp_server/main.py:375-386`
**CONFIRMED.** Only `perm.get("IpRanges", [])` is scanned for `0.0.0.0/0`; a rule open to `::/0` via `Ipv6Ranges` is never flagged and can still write `check_ssh=SAFE`. Add an `Ipv6Ranges` / `CidrIpv6 == "::/0"` check.

### M16 — `revoke_security_group_ingress` over-revokes peer-SG / prefix-list rules · `mcp_server/main.py:417-424`
**CONFIRMED.** When narrowing a risky permission it keeps every key except `IpRanges`, so `UserIdGroupPairs` and `PrefixListIds` on the *same* `IpPermission` are passed to `revoke_security_group_ingress` and deleted too. Port 443 allowed from both `0.0.0.0/0` and a peer app SG in one rule → remediation also strips the peer-SG access. Drop those sub-keys unless they're themselves world-open.

### M17 — `audit_lambda_permissions` swallows role-inspection errors as "clean" · `mcp_server/main.py:621-622`
**CONFIRMED.** `except Exception: pass` around the `list_attached_role_policies` / `get_role_policy` calls → a throttled or `AccessDenied` lookup on a role that actually holds `AdministratorAccess` yields `issues == []` → `_emit(..., "ok")` and, if it's the only function, `update_status("check_lambda","SAFE")`. Mark the function `unknown` on exception, skip the SAFE write.

### M18 — audit tools' error return shape collides with a clean result · `mcp_server/main.py:280,393,484,562,642,728`
**CONFIRMED.** Normal return is a list of dicts; on exception they return `[f"...Error: {e}"]` (list of one string). A consumer doing `for f in result: f["Key"]` raises `TypeError`, and short of that an AWS failure is indistinguishable from "no findings". Return `[{"error": str(e)}]` and check for it.

### M19 — `remediate_vpc_flow_logs` ignores `create_flow_logs` partial failure · `mcp_server/main.py:346-359`
**CONFIRMED.** `create_flow_logs` doesn't raise on partial failure — failures land in the `Unsuccessful` list (e.g. `DeliverLogsPermissionArn` not yet propagated after the fresh `create_role`). The code never reads the response and unconditionally returns SUCCESS + `update_status("check_vpc","SAFE")`. Inspect `resp["Unsuccessful"]`.

### M20 — `remediate_cloudtrail` region mismatch · `mcp_server/main.py:748-759`
**CONFIRMED.** `region = boto3.Session().region_name or "us-east-1"` is used for the bucket `LocationConstraint`, but `get_boto_client` pins the S3 client to `us-east-1`. When `AWS_DEFAULT_REGION != us-east-1`, `create_bucket` → `IllegalLocationConstraint` and CloudTrail remediation aborts. Use `TARGET_REGION` consistently.

### M21 — S3 `ClientError` from `get_public_access_block` all treated as "vulnerable" · `mcp_server/main.py:177-183, 215-217`
**CONFIRMED.** `AccessDenied` (missing `s3:GetBucketPublicAccessBlock`) is bucketed identically to `NoSuchPublicAccessBlockConfiguration` → false "public bucket" finding, and `remediate_s3` then also 403s. `check_s3_security`'s generic-exception branch (`:185`) returns a dict with no `is_public_risk` key → `KeyError` for a caller reading it. Branch on `e.response["Error"]["Code"]`.

### M22 — `report_generator` / `verifier` build Gemini turns with no `HumanMessage` · `nodes.py:447, 772`
**CONFIRMED / works today.** `nodes.py:447` invokes `[AIMessage, HumanMessage]`; `nodes.py:772` first verifier pass invokes `[SystemMessage, AIMessage]` — no user turn. CLAUDE.md explicitly warns Gemini rejects this shape. `langchain-google-genai` currently papers over it; a library or model update breaks both nodes on every scan. Insert a `HumanMessage`.

### M23 — sign-out proceeds even when credential deletion fails · `dashboard/page.tsx:813-818`, `onboarding`
**CONFIRMED.** `await fetch(DELETE /api/accounts).catch(console.error)` then unconditional `signOut()`. On failure the Fernet-encrypted keys stay until the 30-min inactivity purge, while the UI implies they were wiped on sign-out. Check `res.ok`; block or warn on failure.

### M24 — `NEXT_PUBLIC_API_URL` silently falls back to `http://localhost:8080` · `dashboard/page.tsx:15` (+ others)
**CONFIRMED.** `render.yaml:41` marks it `sync: false` (manual). If a Vercel/Render build runs without it, the production bundle points every call at `localhost:8080` (also mixed-content-blocked on HTTPS) with no build error. Assert it in `next.config.ts` or render a config-error state.

---

## LOW

### L1 — `restrict_iam_user` has no protected-user guard at the tool boundary · `mcp_server/main.py:91-137`
**CONFIRMED.** Protection lives only upstream (`nodes.py:623`, `PROTECTED_IAM_USERS` + STS caller identity). An upstream parse bug or LLM hallucination of the credential user's name would let the tool de-privilege the agent's own IAM user mid-scan. Re-check inside the tool.

### L2 — `update_scan` interpolates kwarg keys into SQL · `mcp_server/database.py:210-226`
**CONFIRMED / not currently exploitable.** `f"UPDATE scans SET {k} = %s"` with `k` from `**kwargs`. Values are parameterized and all call sites pass developer-literal keys today. Whitelist column names before someone forwards a client-derived field.

### L3 — `remediation_tools` node + loop is dead code · `agents/graph.py:16, 45, 58-63`
**CONFIRMED.** `remediator_agent` always returns a plain `AIMessage` (no `tool_calls`), so `should_remediate_continue` always routes to `verifier`; the `remediation_tools` `ToolNode` and its edge are unreachable. Remediation actually happens via direct `func.invoke()` in `_run_task`. The documented "remediator ⟷ remediation_tools" loop doesn't exist. Cosmetic / doc mismatch.

### L4 — `critical_findings` reducer key is never written · `agents/state.py:26`
**CONFIRMED.** `Annotated[List[str], operator.add]` with no node returning it. Harmless now; if a node ever returns `critical_findings: None`, `operator.add` raises `TypeError` and kills the graph. Wire it up or delete it.

### L5 — `enforce_imdsv2` + `stop_instance` for the same instance in one parallel batch · `nodes.py:682`
**CONFIRMED / self-mitigating.** Both tasks survive dedup (`(resource, tool)` keys differ) and run in the same pool. If `stop_instance` lands first, `enforce_imdsv2` hits `IncorrectInstanceState` and retries through the transition (H9's 60s loop) — usually succeeds on a stopped instance after blocking the pipe. Intermittent slowness, not a hard failure.

### L6 — `checkAccount` renders the full dashboard on a 401 · `dashboard/page.tsx:198-214`
**CONFIRMED.** Redirects to `/onboarding` only on `res.ok && !data.connected` or a thrown error. A 401 (not ok, doesn't throw) falls through to `setAccountChecked(true)` → the whole shell renders and every subsequent fetch 401s into `catch { /* ignore */ }`. Treat `!res.ok` like the catch branch.

### L7 — account-deletion fetches don't check `res.ok`; UI updates optimistically · `dashboard/page.tsx:508-522` (+ settings delete)
**CONFIRMED.** `handleDeleteAccount` never checks the response, then filters the account out of local state and may `router.replace('/onboarding')` using the stale `accounts` closure. A failed server-side delete leaves the account connected but invisible.

### L8 — `handleStop` shows `idle` while the backend keeps remediating · `dashboard/page.tsx:545-550`
**CONFIRMED / matches documented design.** `POST /api/stop` during remediation doesn't hard-kill (`worker.py` runs it to completion); the UI immediately sets `idle` with no "still finishing" indication.

### L9 — purge uses a `TIMESTAMP` (no tz) column with `NOW()` · `mcp_server/database.py:83, 188`
**CONFIRMED / latent.** `last_used_at` is `TIMESTAMP`; writes use `NOW()`, purge uses `NOW() - INTERVAL '30 minutes'`. Correct only while every pooled connection shares the same `TimeZone`. On a mixed-TZ pool, stored values and the cutoff diverge by the offset → credentials purged early or late. Use `timestamptz` or pin `SET TIME ZONE 'UTC'`.

### L10 — connection leak on exception in `create_postgres_db` / `init_db` · `database.py:38-59, 63-72`
**CONFIRMED / startup-only.** `conn` assigned, `conn.close()` only on the happy path; the `except` just prints. Wrap in `try/finally`.

### L11 — `/api/approve` doesn't check scan phase · `server.py:466-478`
**CONFIRMED.** Owner check only. An "approve" pushed before the gate is reached is popped the instant the gate opens → remediation auto-approved without the findings ever shown (double-submit / request replay). Add a status/nonce check.

### L12 — `approved_resources` written to subprocess stdin unsanitized · `server.py:473-474` → `worker.py:85`
**CONFIRMED / low.** `"approve:" + ",".join(body.approved_resources)`. A resource name containing `,` or `\n` corrupts the payload; `main.py:115` splits on `,` so bogus entries just mean some approved fixes get skipped. It's the authenticated user's own request, so it's fragility not attack surface. Validate each entry.

### L13 — `CORS` config · `server.py:30-36`
**CONFIRMED / low.** Single origin (`FRONTEND_URL` or `localhost:3000`) — not open CORS. `allow_methods=["*"] + allow_headers=["*"] + allow_credentials=True` is broader than needed; and if `FRONTEND_URL` is unset in prod the real frontend is blocked. Make the env var required, tighten methods/headers.

### L14 — `handle_sigterm` → `sys.exit(0)` from the signal handler · `server.py:92-95`
**CONFIRMED / low.** Exiting from the handler doesn't let uvicorn drain active SSE generators, so their `GeneratorExit` abort-push may not run on shutdown. Let uvicorn handle SIGTERM.

### L15 — `audit_ec2_vulnerabilities` false "unencrypted root volume" · `mcp_server/main.py:459-469`
**CONFIRMED.** If no `BlockDeviceMappings` entry matches `RootDeviceName` (mapping absent from the describe response, instance-store root), `encrypted` stays `False` and the instance is flagged. Track whether the root mapping was found; report `unknown` otherwise.

### L16 — `audit_cloudtrail_logging` NO_TRAILS case emits nothing · `mcp_server/main.py:702-703`
**CONFIRMED.** The worst case (no trail at all) early-returns a dict with no `_emit("cloudtrail", ...)` and no `update_status`, unlike every other branch → frontend shows no CloudTrail event and no compliance row for the most severe outcome.

---

## FALSE POSITIVES / cleared

- **`proxy.ts` public-route matcher** — `createRouteMatcher(["/", ...])` matches `/` exactly, not as a prefix; `/dashboard`, `/onboarding`, `/protected-users` are correctly protected. No accidentally-public route, no redirect loop. `tsc --noEmit` is clean.
- **XSS in the dashboard** — no `dangerouslySetInnerHTML`; all scan/SSE output is escaped JSX text.
- **`delete_aws_credentials(user_id, None)` nuking other users** — `WHERE user_id = %s` with a verified non-empty `user["sub"]`; `NULL`/`''` match zero/own rows only.
- **JWT `none`/HS256 downgrade** — `algorithms=["RS256"]` pinned, signature verified, `exp` enforced (the custom `options` dict doesn't disable `verify_exp`), all failure paths raise 401, no anonymous fallback.
- **SQL injection** — every query across `accounts.py`, `compliance.py`, `database.py` is parameterized; the one f-string DDL (`database.py:53`) is `isalnum`-validated and not user-reachable.
- **Celery double-spawn on retry** — defaults (`acks_late=False`, no `autoretry_for`) mean a worker crash doesn't redeliver.
- **IDOR on scan endpoints** — `get_scan_detail` is `WHERE id = %s AND user_id = %s`; `/api/approve` and `/api/stop` check `scan:{id}:owner`.
- **SSE JSON chunk-boundary split** — handled (`buffer` + `split('\n')` + `pop()`), and `JSON.parse` is wrapped in try/catch. Only the end-of-stream flush is missing, and the server always newline-terminates, so it's unreachable in practice (downgraded to LOW).
- **`interrupt_before` stalling a clean scan** — see H13; neither `main.py` nor `worker.py` waits on approval for a clean scan.
- **`rediss://` TLS URL munge** (`worker.py:16-17`) — correct `?`/`&` handling and `ssl_cert_reqs` guard.

---

## If you fix in one order

1. **C1 + H1 + H2 + H3** — replace the bare `active_scans` counter with a Redis set of in-flight scan-ids with TTLs; reset on boot. Kills the permanent-lockout class.
2. **C2** — add `re.MULTILINE` to both `finding_pattern` compiles (`nodes.py:103, 331`). One line, also fixes the `_run_sub_agent` fallback drop.
3. **H4 + H5 + H6** — wrap `_run_scan_task` in `try/except`; `Popen(..., start_new_session=True)`; on any exit path `terminate()` → `wait(timeout=10)` → `kill()` + `os.killpg`, always `xadd __DONE__` + `expire`; add Celery `soft_time_limit`.
4. **C3** — loosen `REMEDIATION_LINE_PATTERN` (accept `->`/`→`/`—`, optional `*`/`_`) and assert `len(tasks) == findings_count`, fail loud on mismatch.
5. **H7** — stop passing decrypted creds as a Celery arg; pass a short-TTL Redis key, decrypt in the worker.
6. **H8** — `start.sh`: `trap` SIGTERM → forward to both children, `exec`, exit the container if either dies.
7. **H14 + M1** — call `reset_to_vulnerable(user_id)` at scan start; make `get_cis_score` iterate the fixed 8-control set (missing = failing).

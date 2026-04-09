# Production Scale Ideas

Things to revisit when Remedi has real users.

---

## 1. Tiered Models
Use a cheap model (Gemini Flash) for sub-agents that just call tools and return raw data.
Only use a stronger/smarter model for the Report Generator which needs to actually reason over findings.
Sub-agents are dumb workers — they don't need to be smart, just accurate.

## 2. Scan Queuing
Don't let all users trigger scans simultaneously.
Queue scans and process N at a time (e.g. max 5 concurrent scans).
Prevents Gemini RPM/TPM rate limit explosions as user count grows.
Simple to implement with a Redis queue or even an in-memory queue at first.

## 3. Result Caching
Most AWS accounts don't change hour to hour.
If an account was scanned in the last X hours, return the cached report instead of re-running.
Massive cost and latency reduction for frequent users.
Cache key = user_id + hash of AWS account state.

## 4. Incremental Scanning
Instead of full scans every time, watch CloudTrail events to see what actually changed.
Only re-scan resources that were touched since the last scan.
Best long-term architecture — turns a 2-min full scan into a near-instant delta scan.
Requires CloudTrail to be enabled (ironic since Remedi flags it when it's off).

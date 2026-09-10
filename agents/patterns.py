import re

# Specialist sub-agents emit findings as:
#   FINDING: <resource> | SEVERITY: <CRITICAL|HIGH|MEDIUM> | REASON: <...> [| FIX: <...>]
# re.MULTILINE so every line in a multi-finding block matches — without it `$`
# only matches end-of-string and all but the last finding are silently dropped.
# Lives here (side-effect-free module) so both call sites in nodes.py and the
# tests import one copy instead of maintaining drift-prone duplicates.
FINDING_PATTERN = re.compile(
    r"FINDING:\s*(.+?)\s*\|\s*SEVERITY:\s*(CRITICAL|HIGH|MEDIUM)\s*\|\s*REASON:\s*(.+?)\s*(?:\|\s*FIX:\s*(.+?))?\s*$",
    re.IGNORECASE | re.MULTILINE,
)

# The report generator emits lines in exactly this format — the remediator
# regex-parses them with no LLM step. Changing this pattern requires updating
# the report generator prompt too (see agents/nodes.py). Kept in its own
# side-effect-free module so tests can import the real pattern instead of
# maintaining a duplicate copy that can silently drift from production.
REMEDIATION_LINE_PATTERN = re.compile(
    r"🔴 \[(?:CRITICAL|HIGH)\]\s*(.+?)\s+is vulnerable\s*"
    r"(?:-->|->|—>|–>|→|—|–)\s*"          # ascii or unicode arrow / dash
    r"ACTION:\s*I(?:'ll| will)\s+(?:call|run|invoke|use)\s+"
    r"[`'\"*_]*([A-Za-z_]\w*)[`'\"*_]*",  # tool name, tolerating **bold** / `code` / _italic_
    re.IGNORECASE,
)

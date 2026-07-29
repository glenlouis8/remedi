import re

# The report generator emits lines in exactly this format — the remediator
# regex-parses them with no LLM step. Changing this pattern requires updating
# the report generator prompt too (see agents/nodes.py). Kept in its own
# side-effect-free module so tests can import the real pattern instead of
# maintaining a duplicate copy that can silently drift from production.
REMEDIATION_LINE_PATTERN = re.compile(
    r'🔴 \[(?:CRITICAL|HIGH)\] (.+?) is vulnerable -> ACTION: I will call [`\'"]?(\w+)[`\'"]?'
)

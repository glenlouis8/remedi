import sys
from unittest.mock import MagicMock

# Mock the database module before any test imports anything that depends on it.
# mcp_server/main.py calls init_db() at module level — without this, every
# test that imports from mcp_server would attempt a real psycopg2 connection.
mock_db = MagicMock()
mock_db.init_db.return_value = None
mock_db.update_status.return_value = None
mock_db.get_connection.return_value = MagicMock()
mock_db.start_scan.return_value = None
mock_db.update_scan.return_value = None
mock_db.log_remediation.return_value = None

sys.modules["mcp_server.database"] = mock_db

"""Safe isolated secrets required while importing service modules in tests."""
import os


os.environ.setdefault("MCP_AUTH_TOKEN", "test-only-mcp-token-0000000000000000")
os.environ.setdefault(
    "ORCHESTRATOR_API_KEY",
    "test-only-orchestrator-key-000000000000",
)
os.environ.setdefault(
    "CHATUI_SESSION_SECRET",
    "test-only-session-secret-000000000000000",
)
os.environ.setdefault("CHATUI_USERNAME", "test-analyst")
os.environ.setdefault("CHATUI_PASSWORD", "test-only-password-0000")

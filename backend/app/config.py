"""
Runtime configuration, read from environment variables.

Secrets never live in the code or in Git: they are set in the hosting
platform (Render) or in the local terminal session.
"""
import os

# Shared secret the add-on must send in the X-API-Key header.
# Empty means "not configured": the API then refuses every analysis request.
API_KEY = os.environ.get("API_KEY", "")

# Interactive API docs (/docs) are useful locally but reveal the API's
# structure, so they are off unless explicitly enabled.
ENABLE_DOCS = os.environ.get("ENABLE_DOCS", "false").lower() == "true"

"""
Registry of all analyzers. To add a new one, write a module with an
analyze(email) -> list[Finding] function and add it to ANALYZERS.
"""
from app.analyzers import attachments, authentication, content, links, lookalike, sender

ANALYZERS = [
    authentication,
    sender,
    links,
    lookalike,
    attachments,
    content,
]

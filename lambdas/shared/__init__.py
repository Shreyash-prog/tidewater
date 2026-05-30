"""Code shared across Lambda deployment packages (models, helpers, base classes).

Packaged into each Lambda bundle at build time. Keep this dependency-light:
anything imported here is imported by every detector, the policy engine, the
remediator, and the API.
"""

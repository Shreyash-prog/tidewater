"""Pytest session setup.

Powertools' Tracer imports aws_xray_sdk at construction time. That package ships
in the Lambda Powertools layer at runtime but isn't a dev dependency, so we
disable tracing for tests (set before any handler/detector module is imported).
"""

import os

os.environ.setdefault("POWERTOOLS_TRACE_DISABLED", "true")
os.environ.setdefault("POWERTOOLS_METRICS_NAMESPACE", "TidewaterTest")
os.environ.setdefault("POWERTOOLS_SERVICE_NAME", "tidewater-test")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

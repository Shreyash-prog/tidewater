"""Reusable Python Lambda construct.

A lightweight stand-in for the experimental `aws_lambda_python_alpha.PythonFunction`
(which we avoid — it's slow and unstable). It applies the project-wide Lambda
conventions in one place (docs/architecture.md §13, CLAUDE.md):

  * Python 3.12 on ARM64 (cheaper)
  * AWS Lambda Powertools attached as a managed layer (not bundled)
  * X-Ray tracing ACTIVE
  * a dedicated CloudWatch log group with 1-day retention (Free Tier guardrail)
    and DESTROY removal policy

Packaging (no Docker): the asset is staged on the host into `.lambda-build/`.
Third-party deps in the Lambda's requirements.txt are pip-installed with
ARM64/Python-3.12 wheels (so a compiled dep like pydantic-core is correct
regardless of the build host), and `shared/` is copied in when `include_shared`
is set. Lambdas with no deps and no shared code are zipped directly.

Staging is skipped when the CDK context value `bundle_lambdas` is `false` (unit
tests set this — they only assert on template structure, not bundled code).
"""

import shutil
import subprocess
from pathlib import Path

from aws_cdk import Duration, RemovalPolicy
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_sqs as sqs
from aws_cdk import aws_ssm as ssm
from constructs import Construct

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_ROOT = REPO_ROOT / ".lambda-build"
SHARED_DIR = REPO_ROOT / "lambdas" / "shared"

# AWS publishes the latest Powertools (Python v3) layer ARN as a public SSM
# parameter. Reading it with value_from_lookup resolves the current version at
# synth time and caches it in cdk.context.json, so the resolved ARN is baked into
# the template (visible in `cdk diff`) rather than hardcoded. Refresh with
# `make refresh-powertools`.
POWERTOOLS_PARAM = "/aws/service/powertools/python/arm64/python3.12/latest"

# Lambda target platform — pip downloads matching wheels even on an x86/macOS host.
_PIP_PLATFORM = "manylinux2014_aarch64"
_PYTHON_VERSION = "3.12"


def _installable_requirements(requirements: Path) -> bool:
    """True if requirements.txt has at least one real (non-comment) dependency."""
    if not requirements.exists():
        return False
    return any(
        line.strip() and not line.strip().startswith("#")
        for line in requirements.read_text().splitlines()
    )


def _copy_tree(src: Path, dst: Path) -> None:
    shutil.copytree(
        src,
        dst,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "requirements.txt"),
    )


def _pip_install(requirements: Path, target: Path) -> None:
    subprocess.run(
        [
            "python",
            "-m",
            "pip",
            "install",
            "-r",
            str(requirements),
            "--target",
            str(target),
            "--platform",
            _PIP_PLATFORM,
            "--implementation",
            "cp",
            "--python-version",
            _PYTHON_VERSION,
            "--only-binary=:all:",
            "--upgrade",
            "--quiet",
        ],
        check=True,
    )


def _build_bundle(entry_path: Path, *, include_shared: bool, has_deps: bool) -> str:
    """Stage the Lambda asset on the host and return the staging directory.

    When `include_shared`, the bundle mirrors the repo's `lambdas/` tree (entry at
    its lambdas-relative path, plus a top-level `shared/`) so the handler's
    absolute imports (`detectors.iam...`, `shared...`) resolve identically in the
    repo (mypy/pytest) and in the Lambda runtime. The handler must be referenced
    by its full dotted path in that case.
    """
    slug = entry_path.relative_to(REPO_ROOT).as_posix().replace("/", "_")
    build_dir = BUILD_ROOT / slug
    if build_dir.exists():
        shutil.rmtree(build_dir)
    build_dir.mkdir(parents=True)

    if has_deps:
        _pip_install(entry_path / "requirements.txt", build_dir)

    if include_shared:
        entry_rel = entry_path.relative_to(REPO_ROOT / "lambdas")
        _copy_tree(entry_path, build_dir / entry_rel)
        _copy_tree(SHARED_DIR, build_dir / "shared")
    else:
        for item in entry_path.iterdir():
            if item.name in {"requirements.txt", "__pycache__"}:
                continue
            if item.is_dir():
                _copy_tree(item, build_dir / item.name)
            else:
                shutil.copy2(item, build_dir / item.name)

    return str(build_dir)


class PythonLambda(Construct):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        entry: str,
        handler: str = "handler.handler",
        environment: dict[str, str] | None = None,
        timeout: Duration | None = None,
        memory_size: int = 256,
        description: str | None = None,
        include_shared: bool = False,
        dead_letter_queue: sqs.IQueue | None = None,
    ) -> None:
        super().__init__(scope, construct_id)

        entry_path = REPO_ROOT / entry
        if not entry_path.is_dir():
            raise FileNotFoundError(f"Lambda entry directory not found: {entry_path}")

        code = self._resolve_code(entry_path, include_shared=include_shared)

        # Dedicated log group: 1-day retention, destroyed with the stack.
        log_group = logs.LogGroup(
            self,
            "LogGroup",
            retention=logs.RetentionDays.ONE_DAY,
            removal_policy=RemovalPolicy.DESTROY,
        )

        powertools_layer_arn = ssm.StringParameter.value_from_lookup(
            self, parameter_name=POWERTOOLS_PARAM
        )
        powertools_layer = lambda_.LayerVersion.from_layer_version_arn(
            self, "PowertoolsLayer", powertools_layer_arn
        )

        env = {
            "POWERTOOLS_SERVICE_NAME": construct_id,
            "POWERTOOLS_METRICS_NAMESPACE": "Tidewater",
            "POWERTOOLS_LOGGER_LOG_EVENT": "true",
            "LOG_LEVEL": "INFO",
            "POWERTOOLS_TRACE_DISABLED": "false",
            **(environment or {}),
        }

        self.function = lambda_.Function(
            self,
            "Function",
            runtime=lambda_.Runtime.PYTHON_3_12,
            architecture=lambda_.Architecture.ARM_64,
            handler=handler,
            code=code,
            environment=env,
            tracing=lambda_.Tracing.ACTIVE,
            layers=[powertools_layer],
            log_group=log_group,
            timeout=timeout or Duration.seconds(30),
            memory_size=memory_size,
            description=description,
            dead_letter_queue=dead_letter_queue,
        )

    def _resolve_code(self, entry_path: Path, *, include_shared: bool) -> lambda_.Code:
        # Unit tests set bundle_lambdas=false: skip staging, zip the source as-is.
        if self.node.try_get_context("bundle_lambdas") is False:
            return lambda_.Code.from_asset(str(entry_path))

        has_deps = _installable_requirements(entry_path / "requirements.txt")
        if not has_deps and not include_shared:
            return lambda_.Code.from_asset(str(entry_path))

        bundle_dir = _build_bundle(entry_path, include_shared=include_shared, has_deps=has_deps)
        return lambda_.Code.from_asset(bundle_dir)

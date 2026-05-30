"""Reusable Python Lambda construct.

A lightweight stand-in for the experimental `aws_lambda_python_alpha.PythonFunction`
(which we avoid — it's slow and unstable). It applies the project-wide Lambda
conventions in one place (docs/architecture.md §13, CLAUDE.md):

  * Python 3.12 on ARM64 (cheaper)
  * AWS Lambda Powertools attached as a managed layer (not bundled)
  * X-Ray tracing ACTIVE
  * a dedicated CloudWatch log group with 1-day retention (Free Tier guardrail)
    and DESTROY removal policy

Packaging: if the Lambda's requirements.txt lists real dependencies, they are
pip-installed into the asset (host-local bundler preferred, Docker as fallback);
otherwise the source directory is zipped as-is. Phase 2 Lambdas have no
third-party deps (Powertools = layer, boto3 = runtime), so synth needs no Docker.
"""

import shutil
import subprocess
from pathlib import Path
from typing import Any

import jsii
from aws_cdk import BundlingOptions, DockerImage, Duration, ILocalBundling, RemovalPolicy
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_ssm as ssm
from constructs import Construct

REPO_ROOT = Path(__file__).resolve().parents[2]

# AWS publishes the latest Powertools (Python v3) layer ARN as a public SSM
# parameter. Reading it with value_from_lookup resolves the current version at
# synth time and caches it in cdk.context.json, so the resolved ARN is baked into
# the template (visible in `cdk diff`) rather than hardcoded. Refresh with
# `make refresh-powertools`.
POWERTOOLS_PARAM = "/aws/service/powertools/python/arm64/python3.12/latest"

# Image used only when a Lambda actually has dependencies to pip-install.
_BUNDLING_IMAGE = "public.ecr.aws/sam/build-python3.12:latest-arm64"


def _installable_requirements(requirements: Path) -> bool:
    """True if requirements.txt has at least one real (non-comment) dependency."""
    if not requirements.exists():
        return False
    for raw in requirements.read_text().splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            return True
    return False


@jsii.implements(ILocalBundling)
class _LocalPipBundling:
    """Bundle on the host (no Docker) when pip is available."""

    def __init__(self, entry: Path) -> None:
        self._entry = entry

    def try_bundle(self, output_dir: str, *, image: DockerImage, **_: Any) -> bool:
        try:
            subprocess.run(
                [
                    "python",
                    "-m",
                    "pip",
                    "install",
                    "-r",
                    str(self._entry / "requirements.txt"),
                    "--target",
                    output_dir,
                    "--quiet",
                ],
                check=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False  # fall back to Docker bundling
        for item in self._entry.iterdir():
            if item.name in {"requirements.txt", "__pycache__"}:
                continue
            dest = Path(output_dir) / item.name
            if item.is_dir():
                shutil.copytree(item, dest, dirs_exist_ok=True)
            else:
                shutil.copy2(item, dest)
        return True


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
    ) -> None:
        super().__init__(scope, construct_id)

        entry_path = REPO_ROOT / entry
        if not entry_path.is_dir():
            raise FileNotFoundError(f"Lambda entry directory not found: {entry_path}")

        if _installable_requirements(entry_path / "requirements.txt"):
            code = lambda_.Code.from_asset(
                str(entry_path),
                bundling=BundlingOptions(
                    image=DockerImage.from_registry(_BUNDLING_IMAGE),
                    local=_LocalPipBundling(entry_path),
                    command=[
                        "bash",
                        "-c",
                        "pip install -r requirements.txt -t /asset-output && "
                        "cp -au . /asset-output",
                    ],
                ),
            )
        else:
            code = lambda_.Code.from_asset(str(entry_path))

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
        )

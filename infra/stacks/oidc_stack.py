"""OidcStack — GitHub Actions OIDC provider + deploy role.

Deployed ONCE from a developer laptop (chicken-and-egg: GitHub Actions cannot
assume a role that does not exist yet). After deploy, set the role ARN as the
`AWS_DEPLOY_ROLE_ARN` GitHub Actions repository variable so CI can deploy.

POC scope: the deploy role uses AdministratorAccess. Production MUST scope this
to least privilege (documented in the README).
"""

from typing import Any

from aws_cdk import CfnOutput, RemovalPolicy, Stack
from aws_cdk import aws_iam as iam
from constructs import Construct

# GitHub's OIDC issuer. Thumbprints are intentionally omitted: CDK's
# OpenIdConnectProvider fetches the current thumbprints via a custom resource at
# deploy time, which is more robust than hardcoding values that GitHub rotates.
# (AWS also no longer validates the thumbprint for this well-known IdP.)
GITHUB_OIDC_URL = "https://token.actions.githubusercontent.com"
GITHUB_AUDIENCE = "sts.amazonaws.com"
REPO = "Shreyash-prog/tidewater"


class OidcStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs: Any) -> None:
        super().__init__(scope, construct_id, **kwargs)

        provider = iam.OpenIdConnectProvider(
            self,
            "GitHubOidcProvider",
            url=GITHUB_OIDC_URL,
            client_ids=[GITHUB_AUDIENCE],
            removal_policy=RemovalPolicy.DESTROY,
        )

        # Trust: only the main branch and pull_request events of this repo.
        principal = iam.OpenIdConnectPrincipal(
            provider,
            conditions={
                "StringEquals": {
                    "token.actions.githubusercontent.com:aud": GITHUB_AUDIENCE,
                },
                "StringLike": {
                    "token.actions.githubusercontent.com:sub": [
                        f"repo:{REPO}:ref:refs/heads/main",
                        f"repo:{REPO}:pull_request",
                    ],
                },
            },
        )

        deploy_role = iam.Role(
            self,
            "GitHubDeployRole",
            role_name="tidewater-github-deploy",
            assumed_by=principal,
            # POC only — scope to least privilege for production.
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AdministratorAccess"),
            ],
        )

        CfnOutput(
            self,
            "DeployRoleArn",
            value=deploy_role.role_arn,
            description="Set this as the AWS_DEPLOY_ROLE_ARN GitHub Actions repo variable.",
        )
        CfnOutput(
            self,
            "OidcProviderArn",
            value=provider.open_id_connect_provider_arn,
            description="GitHub Actions OIDC provider ARN.",
        )

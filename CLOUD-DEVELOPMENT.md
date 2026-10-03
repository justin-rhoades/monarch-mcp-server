# Cloud development and deployment

The Codex cloud environment includes Git, GitHub CLI and Python 3.12. Run
`bash scripts/setup-cloud.sh` from the checkout to install locked development
dependencies and Google Cloud CLI. This script targets Linux x86_64 and the
checkout at `/workspace/monarch-mcp-server`. It does not authenticate or deploy.

Cloud tasks already run in isolated environments. Use the existing checkout;
create a Git worktree only when explicitly requested.

Run tests with `UV_CACHE_DIR=/workspace/.cache/uv uv run --no-sync pytest -q`.
Set your Git author name and email if they are not already configured. GitHub
push authorization is separate from commit identity; use the platform's existing
GitHub connection first.

For interactive Google authentication, run these commands in your terminal:

```bash
export PATH="/workspace/.tools/google-cloud-sdk/bin:$PATH"
export CLOUDSDK_CONFIG=/tmp/monarch-gcloud-auth
gcloud auth login --no-launch-browser
```

Complete the browser flow and enter the code in the terminal, never in chat.
Do not place credentials in this repository or publish them in an environment
snapshot. Temporary authentication must be repeated in new tasks. For automated
GitHub Actions deployments, use Workload Identity Federation with a scoped
deployment service account instead of a downloaded service-account key.

After committing and pushing tested changes, run:

```bash
bash scripts/deploy-cloud-run.sh
```

The defaults are project `monarch-mcp-509817`, region `us-central1`, service
`monarch-mcp`, and Artifact Registry repository `cloud-run-source-deploy`.
Override `GCP_PROJECT_ID`, `GCP_REGION` and `GCP_SERVICE` for another existing
deployment. Cloud Build builds the Dockerfile; a local Docker daemon is not
required. The deploying identity needs Cloud Build submission and Cloud Run
deployment permissions plus permission to use the runtime service account.
The build identity needs permission to publish images into Artifact Registry.

The script updates the service image while retaining its existing port,
environment, Secret Manager bindings and IAM policy. It expects the existing
service and image repository to be configured. Verify the resulting revision is
ready and perform authenticated MCP initialize and list_tools requests after
deployment. Do not call financial write tools as a deployment smoke test.

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if ! command -v gcloud >/dev/null; then
  export PATH="/workspace/.tools/google-cloud-sdk/bin:$PATH"
fi
project=${GCP_PROJECT_ID:-monarch-mcp-509817}
region=${GCP_REGION:-us-central1}
service=${GCP_SERVICE:-monarch-mcp}
commit=$(git rev-parse HEAD)
if [ -n "$(git status --porcelain)" ]; then
  echo 'Commit or stash local changes before deployment.' >&2
  exit 1
fi
image="${region}-docker.pkg.dev/${project}/cloud-run-source-deploy/${service}:${commit}"
gcloud builds submit --project "$project" --region "$region" --tag "$image" .
# Updating only the image preserves existing ports, secrets, environment and IAM.
gcloud run deploy "$service" --project "$project" --region "$region" --image "$image"

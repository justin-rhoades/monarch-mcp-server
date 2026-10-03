#!/usr/bin/env bash
set -euo pipefail
cd /workspace/monarch-mcp-server
export UV_CACHE_DIR=/workspace/.cache/uv
uv sync --locked --extra dev --python 3.12
command -v git >/dev/null
command -v gh >/dev/null
GCLOUD_VERSION=587.0.0
GCLOUD_ROOT=/workspace/.tools/google-cloud-sdk
if [ ! -x "$GCLOUD_ROOT/bin/gcloud" ]; then
  mkdir -p /workspace/.tools
  download_dir=$(mktemp -d)
  trap 'rm -rf "$download_dir"' EXIT
  curl --fail --show-error --location --proto '=https' --tlsv1.2 "https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-${GCLOUD_VERSION}-linux-x86_64.tar.gz" -o "$download_dir/gcloud.tar.gz"
  tar -xzf "$download_dir/gcloud.tar.gz" -C /workspace/.tools
  "$GCLOUD_ROOT/install.sh" --quiet --usage-reporting=false --path-update=false --command-completion=false
fi
"$GCLOUD_ROOT/bin/gcloud" --version

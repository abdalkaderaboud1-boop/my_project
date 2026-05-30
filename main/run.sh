#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE_NAME="main-orchestrator"


docker build -t "$IMAGE_NAME" "$SCRIPT_DIR"

docker run --rm \
  -p 8080:8080 \
  -e HOST_PROJECT_ROOT="$PROJECT_ROOT" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PROJECT_ROOT:$PROJECT_ROOT" \
  "$IMAGE_NAME"

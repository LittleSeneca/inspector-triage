#!/usr/bin/env bash
#
# Run the handler locally against your account without deploying, to see what it
# would decide. Writes nothing to Jira and nothing to the real state file.
#
# Usage:
#   ./scripts/dry-run.sh                    # assess up to 3 records and print the summary
#   BATCH_SIZE=1 ./scripts/dry-run.sh       # just one
#   AWS_PROFILE=my-readonly ./scripts/dry-run.sh
#
# Environment:
#   STATE_BUCKET   Required. Your stack's state bucket.
#   AWS_REGION     Default: us-east-1
#   BATCH_SIZE     Default: 3
#   REGIONS        Default: $AWS_REGION
#   REPOS, GITHUB_ORG, JIRA_* , INFERENCE_*   Override the stack defaults.
#
# Requires: python3 with boto3, AWS credentials that can read Inspector/ECR/ECS/EC2,
# read the credential parameters in SSM, and read/write the state bucket.
#
# What it does:
#   - forces DRY_RUN=true, so Jira is never called
#   - writes state under dry-run/ in the bucket, never to state.json
#   - prints the run summary as JSON, and logs one `decision` line per record

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1 (try --help)" >&2; exit 2 ;;
  esac
done

if ! python3 -c "import boto3" >/dev/null 2>&1; then
  echo "boto3 is not importable. Install it: pip3 install boto3" >&2
  exit 1
fi

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
export AWS_REGION="$REGION"
export AWS_DEFAULT_REGION="$REGION"

# Point these at your stack's values.
# This script runs the handler from src/. Do not leave .pyc files behind there:
# `sam build` copies src/ wholesale, so stray bytecode would ship in the package.
export PYTHONDONTWRITEBYTECODE=1
export DRY_RUN="true"
export BATCH_SIZE="${BATCH_SIZE:-3}"
export REGIONS="${REGIONS:-$REGION}"
export REPOS="${REPOS:-}"
export GITHUB_ORG="${GITHUB_ORG:-}"
export JIRA_BASE_URL="${JIRA_BASE_URL:-https://example.atlassian.net}"
export JIRA_EMAIL="${JIRA_EMAIL:-nobody@example.com}"
export JIRA_PROJECT_KEY="${JIRA_PROJECT_KEY:-SEC}"
export JIRA_API_KEY_SECRET="${JIRA_API_KEY_SECRET:-/inspector-triage/jira/api-key}"
export INFERENCE_API_KEY_SECRET="${INFERENCE_API_KEY_SECRET:-/inspector-triage/inference/api-key}"
export GITHUB_TOKEN_SECRET="${GITHUB_TOKEN_SECRET:-/inspector-triage/github/token}"
export INFERENCE_BASE_URL="${INFERENCE_BASE_URL:-https://api.groq.com/openai/v1}"
export INFERENCE_MODEL="${INFERENCE_MODEL:-openai/gpt-oss-120b}"

if [[ -z "${STATE_BUCKET:-}" ]]; then
  echo "STATE_BUCKET is not set. Point it at your stack's bucket, for example:" >&2
  echo "  STATE_BUCKET=\$(aws cloudformation describe-stacks --stack-name inspector-triage \\" >&2
  echo "    --query 'Stacks[0].Outputs[?OutputKey==\`StateBucketName\`].OutputValue' --output text) \\" >&2
  echo "  ./scripts/dry-run.sh" >&2
  exit 1
fi

echo "Region:       $REGION"
echo "State bucket: $STATE_BUCKET"
echo "Batch size:   $BATCH_SIZE"
echo "Dry run:      $DRY_RUN (Jira is never called)"
echo

cd "$REPO_ROOT/src"
python3 handler.py

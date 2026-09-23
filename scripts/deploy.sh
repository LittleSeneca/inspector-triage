#!/usr/bin/env bash
#
# Deploy inspector-triage with plain CloudFormation, no SAM CLI required.
#
# `aws cloudformation package` uploads src/ to S3 and rewrites the template's CodeUri
# into a Code block, then `aws cloudformation deploy` processes the SAM transform
# server-side. The result is an ordinary CloudFormation stack.
#
# If you do have the SAM CLI, `sam build && sam deploy --guided` is the shorter path.
# See README.md.
#
# Usage:
#   ./scripts/deploy.sh --jira-url https://acme.atlassian.net \
#                       --jira-email you@acme.com \
#                       --jira-project SEC
#
#   # Extra CloudFormation parameter overrides go after --
#   ./scripts/deploy.sh --jira-url ... --jira-email ... --jira-project SEC \
#                       -- --parameter-overrides Regions=us-east-1,us-west-2 DryRun=false
#
# Flags:
#   --stack-name NAME     Stack name (default: inspector-triage)
#   --region REGION       AWS region (default: $AWS_REGION or us-east-1)
#   --bucket BUCKET       S3 bucket for the packaged artifact. Created if it does
#                         not exist. Default: inspector-triage-artifacts-<account>-<region>
#   --jira-url URL        Required. Jira base URL, no trailing slash.
#   --jira-email EMAIL    Required. Jira account email.
#   --jira-project KEY    Required. Jira project key.
#   --no-deploy           Package only, then stop and print the packaged template path.
#   -h, --help            This text

set -euo pipefail

STACK_NAME="inspector-triage"
REGION="${AWS_REGION:-us-east-1}"
BUCKET=""
JIRA_URL=""
JIRA_EMAIL=""
JIRA_PROJECT=""
NO_DEPLOY="false"
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stack-name)   STACK_NAME="$2"; shift 2 ;;
    --region)       REGION="$2"; shift 2 ;;
    --bucket)       BUCKET="$2"; shift 2 ;;
    --jira-url)     JIRA_URL="$2"; shift 2 ;;
    --jira-email)   JIRA_EMAIL="$2"; shift 2 ;;
    --jira-project) JIRA_PROJECT="$2"; shift 2 ;;
    --no-deploy)    NO_DEPLOY="true"; shift ;;
    --)             shift; EXTRA_ARGS=("$@"); break ;;
    -h|--help)      sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

command -v aws >/dev/null 2>&1 || { echo "missing required command: aws" >&2; exit 1; }
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ACCOUNT="$(aws sts get-caller-identity --region "$REGION" --output text --query 'Account')" \
  || { echo "AWS credentials are not usable in $REGION" >&2; exit 1; }
[[ -n "$BUCKET" ]] || BUCKET="inspector-triage-artifacts-${ACCOUNT}-${REGION}"

echo "Account: $ACCOUNT"
echo "Region:  $REGION"
echo "Stack:   $STACK_NAME"
echo "Bucket:  $BUCKET"
echo

# The Lambda reads its credentials from SSM. Fail early rather than deploying a
# function that will error on every run.
check_param() {
  local name="$1" label="$2"
  if aws ssm get-parameter --name "$name" --region "$REGION" >/dev/null 2>&1; then
    echo "  ok      $label -> $name"
  else
    echo "  MISSING $label -> $name"
    return 1
  fi
}

echo "Checking credentials in SSM:"
missing=0
check_param "/inspector-triage/jira/api-key" "Jira API token" || missing=1
check_param "/inspector-triage/inference/api-key" "inference API key" || missing=1
if aws ssm get-parameter --name "/inspector-triage/github/token" --region "$REGION" >/dev/null 2>&1; then
  echo "  ok      GitHub token -> /inspector-triage/github/token"
else
  echo "  absent  GitHub token (optional; reachability evidence will be thin)"
fi
if [[ "$missing" -eq 1 ]]; then
  echo
  echo "Run ./scripts/set-secrets.sh first, or pass custom paths via"
  echo "--parameter-overrides JiraApiKeySecret=... InferenceApiKeySecret=..." >&2
  exit 1
fi
echo

if ! aws s3api head-bucket --bucket "$BUCKET" --region "$REGION" >/dev/null 2>&1; then
  echo "Creating artifact bucket $BUCKET"
  if [[ "$REGION" == "us-east-1" ]]; then
    aws s3api create-bucket --bucket "$BUCKET" --region "$REGION" >/dev/null
  else
    aws s3api create-bucket --bucket "$BUCKET" --region "$REGION" \
      --create-bucket-configuration "LocationConstraint=$REGION" >/dev/null
  fi
fi

PACKAGED="$(mktemp -t inspector-triage-packaged.XXXXXX.yaml)"
echo "Packaging template"
aws cloudformation package \
  --template-file "$REPO_ROOT/template.yaml" \
  --s3-bucket "$BUCKET" \
  --output-template-file "$PACKAGED" \
  --region "$REGION" \
  >/dev/null
echo "  packaged -> $PACKAGED"
echo

if [[ "$NO_DEPLOY" == "true" ]]; then
  echo "--no-deploy set. Deploy it yourself with:"
  echo "  aws cloudformation deploy --template-file $PACKAGED --stack-name $STACK_NAME \\"
  echo "    --capabilities CAPABILITY_IAM --region $REGION"
  exit 0
fi

REQUIRED=()
if [[ -n "$JIRA_URL" ]]; then
  REQUIRED+=("JiraBaseUrl=$JIRA_URL" "JiraEmail=$JIRA_EMAIL" "JiraProjectKey=$JIRA_PROJECT")
else
  echo "No --jira-url given. CloudFormation will prompt for anything without a default,"
  echo "or fail if a required parameter has none."
  echo
fi

echo "Deploying stack"
DEPLOY_ARGS=(
  --template-file "$PACKAGED"
  --stack-name "$STACK_NAME"
  --capabilities CAPABILITY_IAM
  --region "$REGION"
  --no-fail-on-empty-changeset
)
if [[ "${#REQUIRED[@]}" -gt 0 ]]; then
  DEPLOY_ARGS+=(--parameter-overrides "${REQUIRED[@]}")
fi
if [[ "${#EXTRA_ARGS[@]}" -gt 0 ]]; then
  DEPLOY_ARGS+=("${EXTRA_ARGS[@]}")
fi
aws cloudformation deploy "${DEPLOY_ARGS[@]}"

echo
echo "Stack outputs:"
aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --region "$REGION" \
  --query 'Stacks[0].Outputs[].[OutputKey,OutputValue]' \
  --output table

echo
echo "The stack ships with DryRun=true. Invoke once and read the decisions:"
echo "  aws lambda invoke --function-name $STACK_NAME-triage --region $REGION \\"
echo "    --payload '{}' --cli-binary-format raw-in-base64-out /dev/stdout"
echo
echo "Then switch to live writes:"
echo "  aws cloudformation deploy --template-file $PACKAGED --stack-name $STACK_NAME \\"
echo "    --capabilities CAPABILITY_IAM --region $REGION \\"
echo "    --parameter-overrides DryRun=false ${REQUIRED[*]:-}"

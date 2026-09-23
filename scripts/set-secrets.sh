#!/usr/bin/env bash
#
# Create or update the SSM SecureString parameters inspector-triage reads at runtime.
#
# CloudFormation cannot create SecureString parameters, so this is a separate step.
# Re-run it any time you rotate a credential; --overwrite makes it idempotent.
#
# Usage:
#   ./scripts/set-secrets.sh                                  # prompt for everything
#   ./scripts/set-secrets.sh --skip-github                     # Jira and inference only
#   JIRA_TOKEN=xxx INFERENCE_KEY=yyy ./scripts/set-secrets.sh   # non-interactive
#
# Flags:
#   --region REGION        AWS region (default: $AWS_REGION or us-east-1)
#   --jira-path PATH       SSM parameter name for the Jira token
#   --inference-path PATH  SSM parameter name for the inference API key
#   --github-path PATH     SSM parameter name for the GitHub token
#   --skip-github          Do not prompt for or write a GitHub token
#   --dry-run              Show what would be written, write nothing
#   -h, --help             This text

set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
JIRA_PATH="/inspector-triage/jira/api-key"
INFERENCE_PATH="/inspector-triage/inference/api-key"
GITHUB_PATH="/inspector-triage/github/token"
SKIP_GITHUB="false"
DRY_RUN="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --region)         REGION="$2"; shift 2 ;;
    --jira-path)      JIRA_PATH="$2"; shift 2 ;;
    --inference-path) INFERENCE_PATH="$2"; shift 2 ;;
    --github-path)    GITHUB_PATH="$2"; shift 2 ;;
    --skip-github)    SKIP_GITHUB="true"; shift ;;
    --dry-run)        DRY_RUN="true"; shift ;;
    -h|--help)        sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

command -v aws >/dev/null 2>&1 || { echo "missing required command: aws" >&2; exit 1; }

echo "Region: $REGION"
if [[ "$DRY_RUN" != "true" ]]; then
  aws sts get-caller-identity --region "$REGION" --output text --query 'Account' >/dev/null \
    || { echo "AWS credentials are not usable in $REGION" >&2; exit 1; }
  echo "Account: $(aws sts get-caller-identity --region "$REGION" --output text --query 'Account')"
fi
echo

prompt_secret() {
  local label="$1" value=""
  while [[ -z "$value" ]]; do
    read -r -s -p "$label: " value
    echo >&2
    [[ -n "$value" ]] || echo "  (a value is required)" >&2
  done
  printf '%s' "$value"
}

put() {
  local name="$1" value="$2"
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "  would set $name (${#value} chars)"
    return
  fi
  aws ssm put-parameter \
    --name "$name" \
    --type SecureString \
    --value "$value" \
    --overwrite \
    --region "$REGION" \
    --description "inspector-triage credential" \
    >/dev/null
  echo "  set $name"
}

# Jira API token. Create one at https://id.atlassian.com/manage-profile/security/api-tokens
JIRA_VALUE="${JIRA_TOKEN:-}"
if [[ -z "$JIRA_VALUE" ]]; then
  echo "Jira API token (input hidden). Create one at:"
  echo "  https://id.atlassian.com/manage-profile/security/api-tokens"
  JIRA_VALUE="$(prompt_secret "  token")"
fi
put "$JIRA_PATH" "$JIRA_VALUE"

# Inference provider API key.
INFERENCE_VALUE="${INFERENCE_KEY:-}"
if [[ -z "$INFERENCE_VALUE" ]]; then
  echo
  echo "Inference provider API key (input hidden)."
  echo "  Groq:       https://console.groq.com/keys"
  echo "  OpenAI:     https://platform.openai.com/api-keys"
  echo "  OpenRouter: https://openrouter.ai/keys"
  INFERENCE_VALUE="$(prompt_secret "  key")"
fi
put "$INFERENCE_PATH" "$INFERENCE_VALUE"

# Optional GitHub token. This is what produces the code-search evidence the
# assessment cites, so it is worth setting even though it is optional.
if [[ "$SKIP_GITHUB" != "true" ]]; then
  GITHUB_VALUE="${GITHUB_TOKEN:-}"
  if [[ -z "$GITHUB_VALUE" ]]; then
    echo
    echo "GitHub token (input hidden, optional). Needs read access to your"
    echo "repositories and the ability to search code. A fine-grained token with"
    echo "'Contents: Read' and 'Metadata: Read' on the repositories to search."
    echo "Press Enter to skip."
    read -r -s -p "  token: " GITHUB_VALUE
    echo >&2
  fi
  if [[ -n "$GITHUB_VALUE" ]]; then
    put "$GITHUB_PATH" "$GITHUB_VALUE"
  else
    echo "  skipped $GITHUB_PATH"
  fi
fi

echo
if [[ "$DRY_RUN" == "true" ]]; then
  echo "Dry run. Nothing was written."
  exit 0
fi
echo "Done. Pass these parameter names to the stack:"
echo "  JiraApiKeySecret=$JIRA_PATH"
echo "  InferenceApiKeySecret=$INFERENCE_PATH"
[[ "$SKIP_GITHUB" == "true" ]] || echo "  GitHubTokenSecret=$GITHUB_PATH"

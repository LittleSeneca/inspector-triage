# Configuration

Two places to configure: the **CloudFormation parameters** on the stack, and
**`src/config.json`** in the Lambda package. Simple scalars are stack parameters;
structural maps live in the JSON because they are nested and belong in version control.

Anything in `config.json` is deep-merged over the defaults in `src/handler.py`, so you
only state what differs from the shipped defaults.

---

## 1. CloudFormation parameters

### Credentials

These are references, not values. The secret itself lives in SSM Parameter Store or
Secrets Manager and is never part of the stack.

| Parameter | Default | Notes |
|---|---|---|
| `JiraApiKeySecret` | `/inspector-triage/jira/api-key` | SSM parameter name. Prefix with `sm:` to read a Secrets Manager secret instead. |
| `InferenceApiKeySecret` | `/inspector-triage/inference/api-key` | Same. |
| `GitHubTokenSecret` | *(empty)* | Optional. Same. Leave empty to run without code-search evidence. |

**CloudFormation cannot create SSM SecureString parameters.** That is an AWS limitation,
not a design choice, and it is why `scripts/set-secrets.sh` exists. Create the parameters
with the script or with the CLI directly:

```bash
aws ssm put-parameter --name /inspector-triage/jira/api-key \
  --type SecureString --value 'your-jira-token' --overwrite

aws ssm put-parameter --name /inspector-triage/inference/api-key \
  --type SecureString --value 'your-inference-key' --overwrite

aws ssm put-parameter --name /inspector-triage/github/token \
  --type SecureString --value 'github_pat_...' --overwrite
```

If you already store these in Secrets Manager, use the `sm:` prefix and leave the
parameters alone:

```
InferenceApiKeySecret=sm:inspector-triage/inference
JiraApiKeySecret=arn:aws:secretsmanager:us-east-1:123456789012:secret:inspector-triage/jira-AbCdEf
```

The IAM policy grants `secretsmanager:GetSecretValue` on
`secret:inspector-triage/*`. If you reference a secret outside that prefix, widen the
`ReadCredentialsFromSecretsManager` statement in `template.yaml`.

### Jira

| Parameter | Default | Notes |
|---|---|---|
| `JiraBaseUrl` | *(required)* | `https://acme.atlassian.net`, no trailing slash. |
| `JiraEmail` | *(required)* | The account email the token belongs to. |
| `JiraProjectKey` | *(required)* | For example `SEC`. |
| `JiraIssueType` | `Task` | Issue type for vulnerability cards. |
| `JiraClassIssueType` | `Epic` | Issue type for the standing exception-class issues. Set equal to `JiraIssueType` if your project has no hierarchy. |
| `JiraBoardId` | *(empty)* | Existing board id. Leave empty to have the Lambda create a filter and Kanban board on first run. |
| `BoardName` | `Vulnerability Triage` | Only used when creating a board. |
| `CreateBoard` | `true` | Set `false` to never create a filter or board. |
| `JiraAcceptedStatus` | `Accepted` | Falls back to a done status if absent. |
| `JiraBlockedStatus` | `Blocked` | Falls back to the accepted status if absent. |
| `JiraAcceptedResolution` | `Declined` | Used when the accepted status is unavailable. |
| `OpenStatuses` | `To Do,Open,Backlog` | Comma-separated, in order of preference. Case-sensitive. |
| `DoneStatuses` | `Done,Closed,Resolved,Won't Do,Cancelled` | Comma-separated. Used for closing and for detecting a human closing a card. |
| `Assignees` | `{}` | JSON map of remediation target prefix to Jira accountId, plus an optional `default`. |

See [JIRA-SETUP.md](JIRA-SETUP.md) for what the tool does with each of these.

### Inference

| Parameter | Default | Notes |
|---|---|---|
| `InferenceBaseUrl` | `https://api.groq.com/openai/v1` | Any OpenAI-compatible base URL. The tool appends `/chat/completions`. |
| `InferenceModel` | `openai/gpt-oss-120b` | Must support function calling. |
| `InferenceMaxTokens` | `4000` | 512 to 32000. |

Provider examples:

| Provider | Base URL | Model example |
|---|---|---|
| Groq | `https://api.groq.com/openai/v1` | `openai/gpt-oss-120b` |
| OpenAI | `https://api.openai.com/v1` | `gpt-4o-mini` |
| OpenRouter | `https://openrouter.ai/api/v1` | `openai/gpt-oss-120b` |
| Together | `https://api.together.xyz/v1` | `openai/gpt-oss-120b` |
| Fireworks | `https://api.fireworks.ai/inference/v1` | *(see their model list)* |
| Ollama (local) | `http://localhost:11434/v1` | `qwen2.5:14b` |
| vLLM (local) | `http://localhost:8000/v1` | *(your served model)* |

A local model is only reachable from the Lambda if the endpoint is reachable from your
VPC. For anything on a laptop, use `scripts/dry-run.sh` instead, which runs the handler
where you are.

### Reachability evidence

| Parameter | Default | Notes |
|---|---|---|
| `GitHubOrg` | *(empty)* | Scope code search to one organisation. |
| `GitHubRepos` | *(empty)* | Comma-separated `owner/repo` list. Used for the repo-scoped code search and to filter results. |

### Scanning and schedule

| Parameter | Default | Notes |
|---|---|---|
| `Regions` | *(empty)* | Comma-separated. Empty means the stack's own region. List every region where Inspector is enabled. |
| `BatchSize` | `15` | Maximum assessments per run. |
| `ScheduleExpression` | `rate(1 hour)` | EventBridge expression. |
| `DryRun` | `true` | Ships true on purpose. |
| `TriageLabel` | `inspector-triage` | Label prefix and idempotency key. |
| `StateKey` | `state.json` | Object name inside the state bucket. |

### Operations

| Parameter | Default | Notes |
|---|---|---|
| `LogRetentionDays` | `365` | |
| `EnableAlarm` | `true` | CloudWatch alarm on the function's `Errors` metric. |
| `AlertTopicArn` | *(empty)* | SNS topic for the alarm. Empty means an alarm with no actions. |

---

## 2. `src/config.json`

Deep-merged over the defaults in `handler.py`. Copy `src/config.example.json` for a
filled-in estate.

### Environments

| Key | Default | Notes |
|---|---|---|
| `environments` | `["production", "non-production"]` | Canonical names. Each gets its own risk score in the assessment, and the model must score every one. Add your own for a regulated region, a contract, or a staging tier you care about. |
| `fallback_environment` | `"production"` | Where anything unclassifiable lands. Conservative on purpose. |
| `non_production_environments` | `["non-production"]` | Which environments count as "not customer-facing" for the `non_production_only` exception class. |
| `environment_tag_map` | prod/staging/dev/... | Lowercased resource `Environment` tag value to canonical name. |
| `region_default_environment` | `{}` | Region to environment, used when a resource has no `Environment` tag. |

Environment resolution order, per resource: a mapped tag value wins; with no tag, the
region default; otherwise the fallback. Note that ECR images carry no environment tag of
their own, so an image's environment comes from its region.

### Where your code lives

| Key | Default | Notes |
|---|---|---|
| `source_map` | `{}` | The important one. Inspector remediation target to source location. |
| `ec2_compose_repos` | `[]` | ECR repositories whose images are pulled by EC2 hosts running compose. The newest pushed image in these repos is treated as deployed. |
| `lambda_source_repo` | `""` | Repository holding your Lambda source. |
| `lambda_manifest_path` | `functions/{function}/requirements.txt` | Path template for a given function's dependency manifest. |

`source_map` keys are Inspector remediation targets. The tool derives them itself:

- `ecr:<repository name>` for container images
- `ec2:<host class>` for EC2 instances, where the host class is read from the `Name` tag
  (`app2a (prod)` becomes `app`)
- `lambda:<function name>` for Lambda functions

Each `ecr:` entry takes:

```json
"ecr:web-api": {
  "repo": "acme/web-api",
  "dockerfile": "Dockerfile",
  "compose": "compose.yml",
  "manifests": ["requirements.txt", "pyproject.toml"]
}
```

`compose` and `manifests` are optional. A target with no entry produces a `missing` report
item, which is itself useful evidence: it tells the reader that the image is third-party
or built outside the repositories you gave the token access to.

### Host and image notes

| Key | Default | Notes |
|---|---|---|
| `host_class_notes` | `{}` | Host class to a one-line description of what configures it. Becomes a numbered report item the model can cite. |
| `compose_notes` | `{}` | Host class to a one-line description of the compose stacks it runs. |

These are free text and they matter more than they look. They are how the model learns
what actually executes on a host, which is the difference between "present" and
"reachable".

### Package aliases

| Key | Default | Notes |
|---|---|---|
| `package_aliases` | a generic table | Package name to the names it is invoked or imported by. |

This is the single highest-value small edit you can make. A zero-hit code search is only
evidence if the search would have found an invocation. `perl` maps to
`["perl", "/usr/bin/perl", ".pl"]`; add your own for packages whose import name differs
from the distribution name.

Aliases are merged over the defaults, so a config entry extends the table rather than
replacing it.

### Tiers, bands and classes

| Key | Default | Notes |
|---|---|---|
| `tiers` | P1/P2/P3 with SLA 7/30/90 | Order defines severity. Add a `P0` if you want one; the tier names flow into the assessment schema and Jira labels. |
| `risk_bands` | 81/51/21/1 | Highest environment risk score to Jira priority. First match wins. |
| `accepted_jira_priority` | `Lowest` | Priority for accepted vulnerabilities, whatever their score. |
| `exception_classes` | four classes | Must match the `### 5.N` headings in `prompts/standard.md`, because the class description is lifted from there into the standing Jira issue. |
| `epss_p1_threshold` | `0.10` | Exploit available at or above this EPSS score is P1 when reachable. |

### Everything else

| Key | Default | Notes |
|---|---|---|
| `excluded_path_pattern` | vendored, tests, docs, lockfiles | Regex over repository paths. Excluded paths do not count as invocations. |
| `kev_url` | the CISA feed | Change only if CISA moves it. |

---

## 3. Environment variables

Set by the template from the parameters above. Useful to know when running locally with
`scripts/dry-run.sh`.

`REGIONS`, `REPOS`, `GITHUB_ORG`, `BATCH_SIZE`, `STATE_BUCKET`, `STATE_KEY`,
`TRIAGE_LABEL`, `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_PROJECT_KEY`, `JIRA_ISSUE_TYPE`,
`JIRA_CLASS_ISSUE_TYPE`, `JIRA_BOARD_ID`, `BOARD_NAME`, `CREATE_BOARD`,
`ACCEPTED_STATUS`, `BLOCKED_STATUS`, `ACCEPTED_RESOLUTION`, `OPEN_STATUSES`,
`DONE_STATUSES`, `ASSIGNEES`, `INFERENCE_BASE_URL`, `INFERENCE_MODEL`,
`INFERENCE_MAX_TOKENS`, `JIRA_API_KEY_SECRET`, `INFERENCE_API_KEY_SECRET`,
`GITHUB_TOKEN_SECRET`, `DRY_RUN`

One more, not exposed as a stack parameter:

| Variable | Notes |
|---|---|
| `CONFIG_JSON` | A JSON object deep-merged over `config.json` at cold start. Useful for a one-off override without redeploying. |

---

## 4. Writing the environment statement

`src/prompts/environment.md` is the highest-leverage file in the repository. The sections
that earn their keep, in order of impact:

1. **Runtime profiles.** What actually executes in each image and on each host, and what
   is present only as base-layer baggage. This is what makes the perl case obvious.
2. **Network exposure.** What is reachable before authentication on each internet-facing
   surface. A login page is not a trust boundary.
3. **Data classes and where they sit.** Which store holds what, so environment risk
   scores are grounded.
4. **Patch and rebuild cadence.** So an SLA lands on a cadence that exists.
5. **Things that lower or raise risk here.** Where you correct the assessor's defaults.
6. **Controls, per surface.** Including the controls that are documented but not actually
   in place, which should be named as absent.

A statement of 2,000 to 3,000 words covering those six is worth more than 10,000 words of
architecture prose. Be specific and name things.

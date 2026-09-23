# inspector-triage

Turn an Amazon Inspector package-vulnerability backlog into a short, honest Jira queue.

Inspector gives you thousands of findings and no opinion about which ones matter. This
consolidates them into one record per CVE and package, works out whether the vulnerable
code is actually *reachable* in your environment, assesses the risk with an LLM against a
written statement of your own estate, and keeps a Jira board current. It runs on a
schedule, in your account, on your credentials.

```
Inspector findings ──┐
coverage status ─────┤
running ECS tasks ───┼──> consolidate ──> usage report ──> assess ──> Jira
your repos ──────────┘    (1 per CVE+pkg)  (cited evidence)  (LLM)     (board)
CISA KEV + EPSS ─────┘
```

It deploys as one CloudFormation stack: a single Python Lambda, an S3 bucket for state,
an EventBridge schedule, and an error alarm. No agents, no servers, no dashboard. Jira is
the interface.

---

## The idea in one paragraph

A CVSS score describes a vulnerability in the abstract. It does not know that the perl
CVE your scanner just flagged is sitting in a base image layer that nothing in your
application ever calls. So instead of sorting by severity, this tool asks a different
question: **can anyone outside this resource's trust boundary actually cause the
vulnerable code to run?** To answer it, the Lambda computes a numbered evidence report
from your own repositories and AWS account (the Dockerfile, the base image, dependency
manifests, code search for the package and its aliases, what runs on each host), hands
that to an LLM along with a statement of your environment, and requires the model to cite
the evidence items by number. Reachability plus exploitation evidence (CISA KEV, EPSS,
public exploits) drives the tier. Severity is context, and deliberately the weakest input.

The result is a queue of things worth a human's time, plus a set of documented risk
acceptances with the evidence attached, which is exactly what an auditor asks for.

---

## What you get

| | |
|---|---|
| **Consolidation** | Every Inspector finding for the same CVE and package collapses into one record across all regions and resources, marked deployed or undeployed. Undeployed image tags are never ticketed. |
| **Deployment resolution** | Walks ECS clusters, services and task definitions to find which image digests are actually running, handling the OCI image index versus child manifest trap. Falls back to newest-pushed for EC2 hosts running compose. |
| **Reachability evidence** | A numbered report per record: Dockerfile, `FROM` lines, compose service block, manifest hits, host OS and configuration-management notes, and code search for the package plus its invocation aliases. Zero hits is evidence, and the exact queries are always included. |
| **LLM assessment** | One forced tool call, temperature 0, schema-validated, one retry with the validation errors fed back. The model must cite real evidence item numbers; an unreachable verdict with no citation is rejected. |
| **Deterministic guards** | Code floors the model cannot lower. KEV-listed and reachable is at least P1. An acceptance needs an exception class whose conditions the evidence supports. A tier *demotion* with no change in facts is held for a human, which is what stops a model swap on the provider side quietly draining your queue. |
| **Jira lifecycle** | Idempotent cards keyed on a fingerprint label. Overdue nagging, manual-close detection, and closing only when the finding is gone *and* scan coverage is intact. |
| **Risk acceptance records** | Each exception class becomes one standing Jira issue. Accepted vulnerabilities become its children with their evidence, so the acceptance is auditable in one place. A quarterly review posts membership plus a random sample for human sign-off. |
| **State you can audit** | One versioned JSON object in S3 holding every record, assessment and prompt hash. 400 days of noncurrent versions retained. |

---

## Quick start

Four steps. About ten minutes.

### 0. Prerequisites

- Amazon Inspector enabled for EC2, ECR and Lambda in the regions you care about
- A Jira Cloud project to hold the cards, and a Jira API token
- An API key for any OpenAI-compatible inference provider
- The AWS CLI, configured for the account you want to scan
- Optional but recommended: the [SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)

### 1. Store your credentials

CloudFormation **cannot create SSM SecureString parameters**, so this step is separate.
The script creates or updates them and is safe to re-run when you rotate.

```bash
./scripts/set-secrets.sh
```

That writes three SSM SecureString parameters:

| Parameter | Contents |
|---|---|
| `/inspector-triage/jira/api-key` | Jira API token |
| `/inspector-triage/inference/api-key` | Inference provider API key |
| `/inspector-triage/github/token` | Optional read-only GitHub token |

Already keep these in Secrets Manager? Point the stack at them instead with the `sm:`
prefix, for example `InferenceApiKeySecret=sm:inspector-triage/inference`. See
[docs/CONFIGURATION.md](docs/CONFIGURATION.md).

### 2. Describe your environment

Edit `src/prompts/environment.md`. It ships as a template with `<ANGLE BRACKET>`
placeholders and `TODO` markers, filled in with a realistic default shape for a
small-to-medium AWS account. Replace it with facts about your estate: what is exposed to
the internet, what holds customer data, what runs inside each image and on each host, and
how fast you patch and rebuild.

**This is the highest-leverage file in the repository.** The quality of the triage is
bounded by the quality of this document. A vague statement produces vague risk scores.

### 3. Map your resources to your code

Edit `src/config.json` so the tool knows where the source for each Inspector target
lives. At minimum, fill in `source_map`:

```json
{
  "source_map": {
    "ecr:web-api": {
      "repo": "acme/web-api",
      "dockerfile": "Dockerfile",
      "compose": "compose.yml",
      "manifests": ["requirements.txt", "pyproject.toml"]
    }
  },
  "ec2_compose_repos": ["web-api"],
  "host_class_notes": { "app": "Amazon Linux 2023. Roles: base, docker, webapp." }
}
```

The keys are Inspector remediation targets: `ecr:<repository name>` for images,
`ec2:<host class>` for EC2 instances, `lambda:<function name>` for functions.
See `src/config.example.json` for a filled-in estate and
[docs/CONFIGURATION.md](docs/CONFIGURATION.md) for every key.

### 4. Deploy

**With the SAM CLI:**

```bash
sam build
sam deploy --guided
```

**With plain CloudFormation, no SAM CLI required:**

```bash
./scripts/deploy.sh \
  --jira-url https://acme.atlassian.net \
  --jira-email you@acme.com \
  --jira-project SEC
```

Either way you get an ordinary CloudFormation stack.

### 5. Watch it think, then let it write

The stack ships with `DryRun=true`. It assesses, logs a `decision` line per record, writes
state under `dry-run/` in the bucket, and never touches Jira. Invoke it once:

```bash
aws lambda invoke --function-name inspector-triage-triage \
  --payload '{}' --cli-binary-format raw-in-base64-out /dev/stdout
```

Read the decisions in CloudWatch Logs and check whether they read the way you would have
written them. If they do not, the fix is almost always `environment.md`, not the code.
Then flip it live:

```bash
sam deploy --parameter-overrides DryRun=false
```

---

## Requirements and honest caveats

### You need a GitHub token for the good version of this

The reachability evidence is what makes this better than a CVSS sorter, and most of that
evidence comes from searching your repositories. Without a GitHub token:

- the usage report degrades to `missing` items
- the prompt correctly returns `reachable = unknown`
- the standard treats unknown as reachable

You get a correct but noisy queue. Two keys get it running; three make it useful. A
fine-grained token with **Contents: Read** and **Metadata: Read** on the repositories you
want searched is enough.

### Your environment statement is the real work

Nobody has a 6,000-word description of their own estate lying around. The shipped starter
is deliberately short, which means thin risk scores until you expand it. Budget an
afternoon for a real one, and revisit it whenever your architecture changes.
[docs/CONFIGURATION.md](docs/CONFIGURATION.md) lists the sections that earn their keep.

### Jira needs some setup

The tool uses Jira statuses by name, and your instance's statuses are your own. Defaults
are `Accepted`, `Blocked` and `Declined`, and it falls back gracefully when a status or a
transition is missing. Board creation needs Jira Software; pass an existing `JiraBoardId`
to skip it. See [docs/JIRA-SETUP.md](docs/JIRA-SETUP.md).

### The model must support function calling

Tool use, not just chat. Most current hosted models do. Local runtimes that ignore
`tool_choice` are handled: if the model answers in prose with a JSON object, the tool
recovers it.

### What it deliberately does not do

- **No auto-remediation.** It files and maintains tickets. Humans rebuild images and patch hosts.
- **No free-form code browsing.** The model sees your environment statement and the evidence report, nothing else. Source code reaches the provider only as short excerpts in that report.
- **No network-reachability findings.** Package vulnerabilities only. Open-port observations belong to a different tool.
- **No Slack, no dashboard, no API.** Jira is the interface; the run summary is a log line.
- **No unauthenticated scanning.** It reads what Inspector already found and what your account already knows.

### It reads broadly across your account

The IAM policy grants read-only access to Inspector, ECR, ECS and EC2, and it grants
`secretsmanager:GetSecretValue` scoped to `inspector-triage/*` for the bring-your-own-secret
path. The read actions do not support resource-level scoping, so that statement is
necessarily on `*`. It grants no write access outside the state bucket. If you need to
narrow the credential reads, remove the Secrets Manager statement and use SSM only.

---

## Cost

Three components, and only one of them is real.

| Component | Cost |
|---|---|
| **Inference** | The only meaningful cost. Roughly one chat completion per new or changed record. Multiply your provider's input rate by the size of your environment statement (which dominates the prompt) plus about 1,000 tokens per assessment. On a small hosted model this is well under a cent per assessment. A few hundred findings to backfill is a few dollars, once. |
| **Lambda** | A handful of seconds of arm64 compute per hourly run. Cents per month. |
| **S3, SSM, CloudWatch** | One small versioned object, three standard parameters, a log group. Well under a dollar per month. |

Set `BatchSize` to cap how many records are assessed per hour. Each run stops early when
it is close to its time budget and defers the rest to the next hour, so a large backfill
spreads out on its own.

---

## How a run works

1. **Pull findings** from `inspector2:ListFindings` (`ACTIVE`, `PACKAGE_VULNERABILITY`) in every configured region.
2. **Pull coverage** from `inspector2:ListCoverage`, recording every resource that is not scanning successfully. A resource that silently stopped being scanned is a gap, and the tool will refuse to close a ticket over one.
3. **Resolve deployment**, walking ECS task definitions and expanding OCI image indexes to child manifests.
4. **Consolidate** by `sha256(cve|package)` into one record per vulnerability, enriched with the live CISA KEV catalogue, EPSS, exploit availability and fix versions.
5. **Diff against state**: new, changed (a fact moved), resources-changed (same facts, new digests, so the card updates without a re-assessment), unchanged, gone. KEV listings and fresh exploits jump the queue.
6. **Fetch KEV.** If it cannot be fetched, assessment is skipped for the run. A missing exploit catalogue is never treated as "not listed".
7. **Assess** up to `BatchSize` records: build the evidence report, call the model, validate, apply the code guards.
8. **Act in Jira**, then persist state after each record, so a timeout loses at most one action and the fingerprint label catches even that.
9. **Log a summary** with counts of everything that happened.

---

## Development

```bash
make verify        # lint + tests + packaging check. The one command that checks everything.
```

Individual targets:

```bash
make test          # 82 tests, no AWS and no network
make lint          # cfn-lint the template, shellcheck the scripts, compile the handler
make validate      # sam validate --lint
make build         # sam build
make package-check # assert the built artifact ships what the handler needs at cold start
make clean         # drop .aws-sam and bytecode
```

`make help` lists them. `cfn-lint`, `shellcheck` and the SAM CLI are the only tools
required, and each target tells you which one is missing rather than failing obscurely.

The handler has **zero third-party dependencies**: stdlib plus boto3, which the Lambda
runtime provides. That is why `sam build` needs no Docker and the deployment package is a
plain zip.

Layout:

```
Makefile                 make verify, make test, make lint, make build, make clean
template.yaml            CloudFormation stack (SAM transform)
src/handler.py           the Lambda, one file, read top to bottom
src/prompts/
  environment.md         your estate, described for the assessor
  standard.md            the prioritization standard the model applies
src/config.json          your estate's configuration
src/config.example.json  a filled-in example estate
tests/test_triage.py     70 unit + end-to-end tests over the pure logic
tests/test_template.py   12 tests asserting the template and the handler agree
scripts/set-secrets.sh   create the SSM SecureString parameters
scripts/deploy.sh        package and deploy without the SAM CLI
scripts/dry-run.sh       run locally against your account, no Jira writes
scripts/check_package.py assert the built artifact ships what the handler needs
docs/                    configuration, Jira setup, architecture
```

---

## Credits

The design comes from a production implementation at AvatarFleet, generalized and
stripped of everything estate-specific. The pipeline shape, the guards, the evidence-report
approach and the exception-class model are all lifted from that system.

## License

MIT. See [LICENSE](LICENSE).

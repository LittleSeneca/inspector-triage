# Jira setup

The tool uses the Jira Cloud REST API directly: v2 for writes with wiki-markup
descriptions, v3 for JQL search, and the Agile API for board creation. No plugin, no
marketplace app, no webhook.

---

## 1. What you need

### An API token

Create one at <https://id.atlassian.com/manage-profile/security/api-tokens>. It
authenticates as the account that owns it, so the account needs the permissions below in
the target project. A dedicated service account is better practice than a personal one:
the tool's comments and status changes then read as automation rather than as you.

### Permissions in the project

| Permission | Needed for |
|---|---|
| Browse Projects | Everything |
| Create Issues | Creating vulnerability cards and class issues |
| Edit Issues | Updating summaries, descriptions, priorities, labels, due dates, parent |
| Transition Issues | Moving cards between statuses |
| Add Comments | Comments on tier changes, resource-set changes, overdue notices, class membership |
| Assign Issues | Only if you use the `Assignees` map |
| Manage Sprint / Administer Projects | Only for board and filter creation, or to run `CreateBoard` at all |

### A project

Any project type works. A team-managed project is simpler; a company-managed project is
fine too. The tool only needs the project key.

---

## 2. Statuses

The tool cares about four states. Your workflow's status *names* are your own, and you
configure them.

| State | Default name | Parameter | What it means |
|---|---|---|---|
| **Open** | `To Do` | `OpenStatuses` | Actionable work with a fix available and an SLA due date. |
| **Blocked** | `Blocked` | `JiraBlockedStatus` | No patch exists. Nothing a human can do, so it does not read as open work and is excluded from overdue nagging. |
| **Accepted** | `Accepted` | `JiraAcceptedStatus` | A documented risk acceptance with a patch available. Also excluded from open work. |
| **Done** | `Done` | `DoneStatuses` | Closed, either because the finding is gone or because a human closed it. |

`OpenStatuses` and `DoneStatuses` are comma-separated lists, in order of preference. The
tool tries each in turn and takes the first transition that exists, so listing a few
aliases is a reasonable hedge.

Every status name is matched **case-sensitively** for transitions, because that is how the
Jira API works. If a transition silently does nothing, the name is wrong. The run log
records a failure when a transition cannot be found.

### If a status does not exist

The tool degrades rather than failing:

- `Blocked` missing, falls back to `Accepted`
- `Accepted` missing, falls back to a done status with the `JiraAcceptedResolution` resolution
- `Accepted` and the resolution both missing, the card stays where it is and the run logs a failure

So a project with nothing but `To Do`, `In Progress` and `Done` still works. You lose the
ability to distinguish "no patch exists" from "we accepted this", which is most of the
value of the blocked state.

### Recommended workflow

```
To Do  →  In Progress  →  Done
  ↓            ↓
Blocked     Accepted
```

`Accepted` should be in the **Done** status category, not the **To Do** category, or it
will keep showing up as open work on boards and in reports. Same for `Blocked`, if your
process treats "waiting on upstream" as not-open.

---

## 3. Issue types

| Use | Default | Parameter |
|---|---|---|
| Vulnerability cards | `Task` | `JiraIssueType` |
| Standing exception-class issues | `Epic` | `JiraClassIssueType` |

**Exception classes are Epics.** Each class becomes one Epic holding the class definition
lifted out of `prompts/standard.md`, and every accepted vulnerability becomes a child of
it. That means one Epic per class shows the complete set of acceptances with their
evidence, which is the artifact an auditor asks to see.

If your project has no issue hierarchy, set `JiraClassIssueType` equal to `JiraIssueType`.
Accepted vulnerabilities are then related to their class issue by an issue link instead of
a parent, which the tool handles automatically when setting a parent fails.

Parent and child issues must be in the same project.

---

## 4. Labels

Every issue the tool creates carries:

| Label | Example |
|---|---|
| `TriageLabel` | `inspector-triage` |
| `cve-<id>` | `cve-2026-12087` |
| `fp-<12 hex>` | `fp-3f9a1c2b8d4e` |
| `tier-<tier>` | `tier-p2` |
| `class-<name>` | `class-unreachable_component` (accepted cards only) |

**The `fp-` label is the idempotency key.** Before creating a card the tool searches for
it, so a lost state file does not produce duplicates. Do not rename or remove it by hand.

Labels must exist as labels in your Jira instance to be filterable, but the API creates
them on first use.

---

## 5. The board

Optional. Two paths:

**Use an existing board.** Find its id (it is in the board URL, `/boards/<id>`) and set
`JiraBoardId`. The tool then creates nothing and never touches your filter.

**Let the tool create one.** Leave `JiraBoardId` empty. On the first run it creates a
saved filter over `project = <key> AND labels = "inspector-triage"` ordered by priority
and due date, and a Kanban board on that filter. Requires Jira Software and the
Administer Projects permission. Set `CreateBoard=false` to disable this entirely.

The board is just a view. The tool never needs it to work, and deleting it changes
nothing.

---

## 6. Priorities

**Risk score drives priority, not tier.** The highest of the environment risk scores
becomes the Jira priority, and the tier only sets the due date. A P3 that touches only
non-production reads differently from a P3 in production, which is the point.

Default bands, configurable in `config.json` as `risk_bands`:

| Risk score | Jira priority |
|---|---|
| 81 to 100 | Highest |
| 51 to 80 | High |
| 21 to 50 | Medium |
| 1 to 20 | Low |
| accepted | Lowest |

**If your project uses a custom priority scheme**, change `risk_bands` and the `tiers`
block in `src/config.json` to match your priority names. The API rejects a priority name
that does not exist in the scheme, and the run will log a failure on every card.

The summary line carries both numbers, so cards read and sort visibly:

```
[Risk 72] [P2] CVE-2026-12087 perl in web-api, batch-worker (4 resources, production)
```

---

## 7. Assignees

Optional. `Assignees` is a JSON map of remediation target prefix to Jira accountId, with
an optional `default`:

```json
{
  "default": "5b10ac8d82e05b22cc7d4ef5",
  "ecr:web-api": "5b10ac8d82e05b22cc7d4ef5",
  "ec2:app": "712020:25f24a28-5bf7-44a7-b080-2f78f5810821"
}
```

Find account ids with:

```bash
curl -s -u "$JIRA_EMAIL:$JIRA_TOKEN" \
  "https://acme.atlassian.net/rest/api/3/user/search?query=someone@acme.com" \
  | python3 -m json.tool
```

Note the format: some accounts have a `712020:` prefix, some do not. Copy exactly what the
API returns. Leave the map empty to create unassigned cards.

Accepted vulnerabilities are never assigned, on purpose. They are not work.

---

## 8. What the tool creates, and what you create

| You create | The tool creates |
|---|---|
| The project | One card per consolidated vulnerability |
| The statuses (or accept the defaults) | One Epic per exception class, on first use |
| The priority scheme | A saved filter and Kanban board, if you let it |
| The API token | Comments on tier changes, resource changes, overdue cards, and class membership |
| | Issue links between promoted cards and the class they left |

---

## 9. What the lifecycle looks like

| Event | What happens |
|---|---|
| A new CVE appears in Inspector | One card, priority from the risk score, due date from the tier. |
| The same CVE appears on a new host or image | A comment listing what was added. No re-assessment, because the facts did not change. |
| A fix becomes available | The card moves out of `Blocked` into open work, with a comment naming the fixed version. |
| Facts change (KEV listing, EPSS moves, exploit appears, fix lands) | Re-assessed, priority and due date updated, comment if the tier moved. |
| A re-assessment proposes a *lower* tier with no change in facts | Held. The card gets a comment proposing the change and waits for a human. |
| The due date passes | One comment a week until it is resolved or blocked. |
| A human closes the card while Inspector still reports the finding | One comment noting the finding is still active, then the tool goes quiet on that card until the facts change. |
| Inspector stops reporting the finding | The card is closed, with a comment. **Unless** the affected resource has lost scan coverage, in which case the card stays open and the coverage gap is named. |
| The finding comes back | The same card is reopened, not duplicated. |

The last two rows are the ones that matter most in practice. A finding disappearing from
Inspector is not the same as a vulnerability being fixed, and the tool will not close a
card over a silent scanning failure.

---

## 10. Troubleshooting

| Symptom | Cause |
|---|---|
| `Jira POST /issue 400: {"errors":{"priority":"..."}}` | Priority name is not in your scheme. Fix `risk_bands` in `src/config.json`. |
| `Jira POST /issue 400` on `issuetype` | `JiraIssueType` or `JiraClassIssueType` does not exist in the project. |
| `Jira PUT /issue 400` on `parent` | Child and parent are in different projects, or the hierarchy is not enabled. The tool falls back to an issue link. |
| Transitions silently do nothing | Status name is wrong or unreachable from the current status. Check the workflow's allowed transitions, not just the status names. |
| `Jira GET /search/jql 404` | Very old Jira Server. This tool targets Jira Cloud. |
| Board creation fails with 403 | No Jira Software or no Administer Projects permission. Set `JiraBoardId` or `CreateBoard=false`. |
| Cards created but descriptions look like raw text | Expected. Descriptions use Jira wiki markup, not Atlassian Document Format. |
| Duplicate cards | Someone removed the `fp-` label, or the project key changed. |

The tool logs a `failure` entry in the run summary for anything it could not do, and the
CloudWatch alarm fires on unhandled errors. Check the log line before assuming a silent
success.

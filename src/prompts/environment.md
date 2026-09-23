# Environment Statement

**This is a template, and it is the single most important file in this tool.**
Replace every `<ANGLE BRACKET>` placeholder and every line marked `TODO` with
facts about your own estate. The quality of the triage is bounded by the quality
of this document.

Version 1.0. Owner: `<YOU>`. Review this whenever the architecture changes and
at every quarterly review. Its content hash is stamped on every assessment, so a
decision can always be traced to the exact text that produced it.

The rest of this file is written as a map of an estate, addressed to the
assessor. The body below is a realistic starting point for a small-to-medium AWS
account. Delete what does not apply and add what does. Be specific: name the
load balancer, the host classes, the base images, the patch cadence. Vague
statements here produce vague risk scores.

---

## 1. What this organisation does and what data it holds

`<ONE PARAGRAPH: what the business does, who the customers are, and what the
product is.>`

The data classes present, most sensitive first:

- **Restricted.** `<e.g. personal data subject to regulation, credentials,
  financial records, health information. Name the systems that hold it.>`
- **Confidential.** `<e.g. customer names and contact details, uploaded
  documents, request logs, internal incident records.>`
- **Internal.** `<e.g. infrastructure state, build logs, metrics.>`

Where the data sits:

| Store | Region | Holds | Reached by |
|---|---|---|---|
| `<database identifier>` | `<region>` | `<what>` | `<which compute>` |
| `<bucket name pattern>` | `<region>` | `<what>` | `<which role>` |
| `<other store>` | `<region>` | `<what>` | `<who>` |

State whether each store is encrypted at rest, whether backups are immutable,
and whether anything is subject to a data-residency obligation.

## 2. Environments and regions

| Environment | Region | Nature |
|---|---|---|
| **production** | `<region>` | Customer-facing. `<Availability commitment. What a compromise would mean.>` |
| **non-production** | `<region>` | `<Internal tooling, test, staging. State plainly whether it holds customer data and whether it is reachable from the internet.>` |

Add a row for every environment named in `environments` in `config.json`. If you
run a separate production estate for a regulated region or a contract, it
belongs here as its own environment with its own risk score.

Anything that cannot be classified from a resource tag is scored as
`production`. Say here whether that is correct for your estate, and if not,
change `fallback_environment` in `config.json`.

## 3. Network exposure, surface by surface

State the design rule first, then the exceptions. Example of the shape:

> The public subnets hold load balancers, NAT gateways, and the proxy hosts, and
> nothing else. Application servers, containers, databases, and file systems sit
> in private subnets with egress through a NAT gateway. Humans reach internal
> services over `<VPN or zero-trust overlay>`. There is no public SSH anywhere.

What faces the internet:

| Port | Where | What is behind it | Authentication |
|---|---|---|---|
| 443/tcp | `<load balancer>` | `<which applications>` | `<none / SSO / application login>` |
| `<port>` | `<host or balancer>` | `<what>` | `<what>` |

For each internet-facing surface, state what is reachable **before**
authentication. Login pages, password reset, applicant-facing forms, and file
upload endpoints are usually pre-authentication, and that changes the
reachability answer.

Private tier: what accepts traffic from what, and on which ports. Say whether
egress is restricted or open.

## 4. Compute inventory and what runs on each thing

### Hosts

| Host class | Instance type | Runs | Exposure |
|---|---|---|---|
| `<class>` | `<type>` | `<OS and version, the process, the containers>` | `<internet via load balancer / internal only>` |

State the OS and version for every host class. State whether hosts run
containers and, if so, what the containers carry. State whether the host OS
itself runs anything that handles outside input.

### Containers and serverless

| Service | Image or runtime | Runs | Exposure |
|---|---|---|---|
| `<service>` | `<image:tag, and the base image>` | `<the process, the user it runs as>` | `<public / internal / none>` |

State which images you build and can rebuild, and which you pull from a vendor
and cannot change. That distinction decides the
`third_party_image_awaiting_upstream` class, and it decides what remediation
text is even possible.

### Images you build

| Image | Built from | Base | Contents beyond the base |
|---|---|---|---|
| `<image>` | `<Dockerfile path>` | `<base image>` | `<your dependencies>` |

Also list the images that something pulls straight from a public registry and
never scans. Absence of findings on those is absence of scanning, not absence of
vulnerabilities. Say so explicitly so the assessor does not treat silence as
safety.

## 5. Runtime profiles that decide reachability

This is the section that makes the tool useful. For each image you build and
each host class, state what the process actually does at runtime, and then state
what is present only as base-image or OS baggage.

For each one, answer:

- What is the interpreter and framework, and what does it listen on?
- What does it parse that comes from outside the trust boundary?
- What does it link against at runtime (TLS libraries, compression, XML)?
- What is present in the image but never invoked by your code (shells, perl,
  language runtimes you do not use, unrelated OS packages)?
- What does the entrypoint actually run?

Worked example of the shape, for a Python web application on a Debian slim base:

> The process is `<gunicorn>` serving `<framework>`, with workers alongside
> consuming `<queue>`. It handles HTTP from the internet through the load
> balancer, parses uploaded documents, renders PDFs by calling `<renderer>` over
> HTTP, and talks to `<database>`, `<cache>`, `<queue>`, and object storage. Its
> reachable surface is Python, the packages in its dependency manifest, the C
> libraries those link against (OpenSSL, zlib, libpq), and the web server.
> Shell tools, perl, and unrelated OS packages are present because the base
> image ships them and the application never calls them. The interpreter is the
> entrypoint; no script in the image shells out to perl.

The distinction between "present" and "reachable" is the whole point of this
document. The usage report is how the assessor confirms which one applies to the
case in front of it.

## 6. Detection and compensating controls, per surface

| Control | Where it applies | What it does |
|---|---|---|
| `<WAF>` | `<every HTTP request>` | `<which rules, and whether rate rules block or only count>` |
| `<SSO proxy>` | `<which services>` | `<what identity is required before the application sees a request>` |
| `<VPN / overlay>` | `<which services>` | `<identity-bound access>` |
| `<network isolation>` | `<which tiers>` | `<ingress rules, and whether egress is open>` |
| `<GuardDuty or equivalent>` | `<regions>` | `<what it alerts on, and whether anything automated acts on it>` |
| `<Inspector>` | `<resource types and regions>` | `<scan cadence, and any suppression rules>` |
| `<patch management>` | `<hosts>` | `<see section 7>` |
| `<image rebuild pipeline>` | `<which images>` | `<see section 7>` |

Name the controls that are documented but **not** actually in place. A control
that exists in a repository and is applied to nothing is not a compensating
control, and the assessor should not be told otherwise.

Also state your Inspector suppression rules and why each exists. Suppressed
findings never reach this tool, so if a class of resource is suppressed, say so
and say what it is.

## 7. Patch and rebuild cadence

For each class of asset, state how a fix reaches production and how long that
takes. This is what makes an SLA land on a cadence that exists.

- **Hosts.** `<Patch mechanism, approval windows by severity, install windows,
  whether reboots are automatic. State the practical consequence: a userland fix
  lands within N days; a kernel fix may wait for a reboot.>`
- **Images you build.** `<Rebuild trigger and cadence. State whether an OS
  package fix arrives automatically on the next rebuild, or whether it needs a
  Dockerfile change and a pull request.>`
- **Third-party images.** `<Whether there is any pipeline at all. Floating tags
  update on task restart; pinned tags update when someone changes them.>`
- **Serverless.** `<When the package is rebuilt. Vendored dependencies update
  only when someone rebuilds.>`

## 8. Things that categorically lower or raise risk here

This section is where you correct the assessor's defaults. Examples of the
shape:

- `<A non-production environment that sits in the production network is as
  exposed as production for reachability, and holds no customer data.>`
- `<A cold standby region holds production data at rest and runs nothing. Score
  it for the confidentiality of the data and for no attack surface.>`
- `<A build runner holds credentials with wide blast radius regardless of its
  criticality tag.>`
- `<A service that intentionally ships security tooling or vulnerable packages
  by design is suppressed in Inspector and should not reach this assessment.>`
- `<Unrestricted egress everywhere means a foothold can reach the internet. The
  compensating control is detection and quarantine, not the network.>`
- `<An account or estate outside the scanner's reach that cannot be scored.>`

## 9. How to read the usage report

The usage report is a numbered list of items the Lambda gathered from your
repositories and from AWS for the specific vulnerability in front of you. Cite
items by number. Every item is one of these kinds:

| Kind | What it contains |
|---|---|
| `dockerfile` | The full Dockerfile for an affected image you build, with its path in the repository. Read the `FROM`, `RUN`, `USER`, and `CMD` or `ENTRYPOINT` lines. |
| `compose_service` | The compose service block for an affected image, showing ports, command, and volumes. |
| `manifest_hits` | Lines in dependency manifests (`requirements.txt`, `pyproject.toml`, `package.json`, `package-lock.json`, `go.mod`) that mention the package. An empty result lists the manifests that were checked. |
| `base_image` | The `FROM` line, so base-layer baggage can be told from something you installed. |
| `host_os` | For an affected host class, the OS from the live account or from the host class notes. |
| `compose_on_host` | The compose stacks a host class runs, so image findings and host findings join up. |
| `config_hits` | Search results for the package name across the configuration-management tree. |
| `code_search` | Code search results for the package name and its alias names across your repositories, excluding vendored, test, and documentation paths. Capped at twenty hits. |
| `search_queries` | The exact queries that were run and the paths that were excluded. Always present. |
| `missing` | Items that could not be gathered, with the reason. If this item is present, reachability should be `unknown` unless the remaining items settle it on their own. |

A `code_search` with zero hits means the package name and its aliases appear
nowhere in the searched repositories outside the excluded paths. That is strong
evidence for an OS-level package like perl. It is weaker for a library that a
runtime loads by a different name (for example a Python package whose import
name differs from its distribution name, or a shared library linked by the
interpreter). The alias table in `config.json` covers the common cases and
`search_queries` shows you exactly what was tried, so judge the strength of the
zero yourself.

If you want strong evidence for a package, add it to `package_aliases` in
`config.json` with the names your code would actually use. That single line is
often the difference between a confident `unreachable_component` acceptance and
an `unknown` that has to be treated as reachable.

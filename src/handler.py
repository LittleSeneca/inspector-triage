"""inspector-triage: turn an Amazon Inspector package-vulnerability backlog into
a short, honest Jira queue.

Consolidates Inspector findings into one record per CVE and package, assesses
each record with an LLM against a written environment statement and a
prioritization standard, and keeps Jira current.

Runs on stdlib plus boto3 (supplied by the Lambda runtime). No vendored
dependencies, so the deployment package is a plain zip and `sam build` needs no
Docker.

Pipeline, in order:

    pull findings -> pull coverage -> resolve deployment -> consolidate ->
    diff against state -> fetch KEV -> build usage report -> assess ->
    act in Jira -> persist state

Read top to bottom: configuration, helpers, AWS pulls, consolidation, usage
report, assessment, Jira, state, handler.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import logging
import os
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request

import boto3

log = logging.getLogger()
log.setLevel(logging.INFO)

HERE = os.path.dirname(os.path.abspath(__file__))


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

DEFAULT_CONFIG: dict = {
    # Canonical environment names. Every one of these appears in the assessment
    # schema and gets its own risk score. Add to this list for your own estate.
    "environments": ["production", "non-production"],
    # Anything that cannot be classified is treated as production. Conservative
    # on purpose: an untagged resource is more likely to matter than not.
    "fallback_environment": "production",
    # Environments that count as "not customer-facing" for the
    # non_production_only exception class.
    "non_production_environments": ["non-production"],
    # Resource tag value (lowercased) -> canonical environment.
    "environment_tag_map": {
        "prod": "production",
        "production": "production",
        "prd": "production",
        "stage": "non-production",
        "staging": "non-production",
        "qa": "non-production",
        "uat": "non-production",
        "dev": "non-production",
        "development": "non-production",
        "test": "non-production",
        "sandbox": "non-production",
        "non-production": "non-production",
    },
    # Region -> environment, used when a resource carries no Environment tag.
    "region_default_environment": {},
    # Inspector remediation target ("ecr:<repo>" or "ec2:<host class>") -> where
    # its source lives. This is what turns a finding into cited evidence.
    "source_map": {},
    # ECR repositories whose images are pulled by EC2 hosts running compose, so
    # the newest pushed tag is what is actually deployed.
    "ec2_compose_repos": [],
    # Host class -> one-line description of what configures it. Free text; it
    # becomes a numbered report item the model may cite.
    "host_class_notes": {},
    # Host class -> one-line description of the compose stacks it runs.
    "compose_notes": {},
    # Repository holding your Lambda source, and the path template to a given
    # function's dependency manifest. Used to build evidence for Lambda findings.
    "lambda_source_repo": "",
    "lambda_manifest_path": "functions/{function}/requirements.txt",
    # Package name -> names it is invoked or imported by. This is what makes a
    # zero-hit code search meaningful evidence rather than an absence of data.
    "package_aliases": {
        "perl": ["perl", "/usr/bin/perl", ".pl"],
        "perl-base": ["perl", "/usr/bin/perl", ".pl"],
        "libssh2": ["libssh2", "ssh2"],
        "curl": ["curl", "libcurl"],
        "libcurl": ["curl", "libcurl"],
        "openssl": ["openssl", "libssl"],
        "libssl3": ["openssl", "libssl"],
        "zlib": ["zlib", "gzip"],
        "libxml2": ["libxml2", "lxml"],
        "libxslt": ["libxslt", "lxml"],
        "sqlite3": ["sqlite3", "sqlite"],
        "libsqlite3": ["sqlite3", "sqlite"],
        "expat": ["expat", "pyexpat"],
        "libexpat1": ["expat", "pyexpat"],
        "python3": ["python3", "python"],
        "glibc": ["glibc"],
        "libc6": ["glibc"],
        "kernel": ["kernel"],
        "systemd": ["systemd"],
        "gnutls28": ["gnutls"],
        "krb5": ["krb5", "kerberos"],
        "pip": ["pip"],
        "setuptools": ["setuptools"],
        "starlette": ["starlette", "fastapi"],
        "fastapi": ["fastapi"],
    },
    # Tier -> SLA in days and the Jira priority that tier maps to when the risk
    # score is not the driver. Order here defines severity order.
    "tiers": {
        "P1": {"sla_days": 7, "jira_priority": "Highest"},
        "P2": {"sla_days": 30, "jira_priority": "High"},
        "P3": {"sla_days": 90, "jira_priority": "Medium"},
    },
    # Highest environment risk score -> Jira priority. First match wins.
    "risk_bands": [[81, "Highest"], [51, "High"], [21, "Medium"], [1, "Low"], [0, "Lowest"]],
    "accepted_jira_priority": "Lowest",
    # Exception classes. The headings in prompts/standard.md must match these
    # names for the class description to be lifted into the standing issue.
    "exception_classes": [
        "no_fix_available",
        "unreachable_component",
        "non_production_only",
        "third_party_image_awaiting_upstream",
    ],
    # Exploit available at or above this EPSS score is P1 when reachable.
    "epss_p1_threshold": 0.10,
    # Paths excluded from code search, so vendored and test code does not count
    # as an invocation.
    "excluded_path_pattern": (
        r"(^|/)(vendor|vendored|node_modules|tests?|test_[^/]*|docs?|__pycache__|"
        r"\.venv|dist|build)(/|$)|\.md$|\.lock$"
    ),
    "kev_url": (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    ),
}


def _deep_merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for key, value in (over or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config() -> dict:
    """config.json beside this file, then CONFIG_JSON over the top."""
    cfg = dict(DEFAULT_CONFIG)
    path = os.path.join(HERE, "config.json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            cfg = _deep_merge(cfg, json.load(fh))
    if os.environ.get("CONFIG_JSON"):
        cfg = _deep_merge(cfg, json.loads(os.environ["CONFIG_JSON"]))
    return cfg


CONFIG = load_config()

ENVIRONMENTS = list(CONFIG["environments"])
CLASSES = list(CONFIG["exception_classes"])
RISK_BANDS = [tuple(b) for b in CONFIG["risk_bands"]]
EPSS_P1 = float(CONFIG["epss_p1_threshold"])
EXCLUDED_PATH = re.compile(CONFIG["excluded_path_pattern"], re.I)
SOURCE_MAP = CONFIG["source_map"]
ALIASES = CONFIG["package_aliases"]
NON_PROD = list(CONFIG["non_production_environments"])

# Tier order: shortest SLA is the most severe.
TIER_ORDER = [
    t for t, _ in sorted(CONFIG["tiers"].items(), key=lambda kv: kv[1]["sla_days"])
]
TIER_RANK = {t: len(TIER_ORDER) - i for i, t in enumerate(TIER_ORDER)}
TIER_RANK["accepted"] = 0
SLA_DAYS = {t: int(v["sla_days"]) for t, v in CONFIG["tiers"].items()}

REGIONS = [r for r in os.environ.get("REGIONS", "us-east-1").split(",") if r]
REPOS = [r for r in os.environ.get("REPOS", "").split(",") if r]
GITHUB_ORG = os.environ.get("GITHUB_ORG", "")
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "15"))
STATE_BUCKET = os.environ.get("STATE_BUCKET", "")
STATE_KEY = os.environ.get("STATE_KEY", "state.json")

LABEL = os.environ.get("TRIAGE_LABEL", "inspector-triage")
JIRA_BASE_URL = os.environ.get("JIRA_BASE_URL", "").rstrip("/")
JIRA_EMAIL = os.environ.get("JIRA_EMAIL", "")
JIRA_PROJECT_KEY = os.environ.get("JIRA_PROJECT_KEY", "")
JIRA_BOARD_ID = os.environ.get("JIRA_BOARD_ID", "")
JIRA_ISSUE_TYPE = os.environ.get("JIRA_ISSUE_TYPE", "Task")
JIRA_CLASS_ISSUE_TYPE = os.environ.get("JIRA_CLASS_ISSUE_TYPE", "Epic")
ACCEPTED_STATUS = os.environ.get("ACCEPTED_STATUS", "Accepted")
BLOCKED_STATUS = os.environ.get("BLOCKED_STATUS", "Blocked")
ACCEPTED_RESOLUTION = os.environ.get("ACCEPTED_RESOLUTION", "Declined")
BOARD_NAME = os.environ.get("BOARD_NAME", "Vulnerability Triage")
CREATE_BOARD = os.environ.get("CREATE_BOARD", "true").lower() == "true"


def _status_list(env_name: str, default: list) -> list:
    raw = os.environ.get(env_name, "")
    if not raw:
        return list(default)
    return [s.strip() for s in raw.split(",") if s.strip()]


# Statuses the Lambda will move a card *into*. Jira matches these names
# case-sensitively, so they are kept exactly as they appear in your workflow.
OPEN_STATUSES = tuple(_status_list("OPEN_STATUSES", ["To Do", "Open", "Backlog"]))
DONE_STATUSES = tuple(
    _status_list("DONE_STATUSES", ["Done", "Closed", "Resolved", "Won't Do", "Cancelled"])
)
# Lowercased copies, for reading a status back and comparing.
DONE_STATUSES_LOWER = tuple(s.lower() for s in DONE_STATUSES)

INFERENCE_BASE_URL = os.environ.get(
    "INFERENCE_BASE_URL", "https://api.groq.com/openai/v1"
).rstrip("/")
INFERENCE_MODEL = os.environ.get("INFERENCE_MODEL", "openai/gpt-oss-120b")
INFERENCE_MAX_TOKENS = int(os.environ.get("INFERENCE_MAX_TOKENS", "4000"))

INFERENCE_API_KEY_SECRET = os.environ.get("INFERENCE_API_KEY_SECRET", "")
JIRA_API_KEY_SECRET = os.environ.get("JIRA_API_KEY_SECRET", "")
GITHUB_TOKEN_SECRET = os.environ.get("GITHUB_TOKEN_SECRET", "")

ASSIGNEES = json.loads(os.environ.get("ASSIGNEES", "{}"))
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"
AWS_REGION = (
    os.environ.get("AWS_REGION")
    or os.environ.get("AWS_DEFAULT_REGION")
    or (REGIONS[0] if REGIONS else "us-east-1")
)


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

_ssm = None
_params: dict = {}


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(d: dt.datetime | None = None) -> str:
    return (d or now()).replace(microsecond=0).isoformat()


def get_param(path: str) -> str:
    """Read an SSM parameter (SecureString included) and cache it for the invocation."""
    if not path:
        raise RuntimeError("no SSM parameter path configured")
    global _ssm
    if path not in _params:
        _ssm = _ssm or boto3.client("ssm", region_name=AWS_REGION)
        _params[path] = _ssm.get_parameter(Name=path, WithDecryption=True)["Parameter"][
            "Value"
        ].strip()
    return _params[path]


def get_credential(ref: str) -> str:
    """Read a credential from SSM Parameter Store or from Secrets Manager.

    CloudFormation cannot create SecureString parameters, so SSM is populated by
    scripts/set-secrets.sh rather than by the stack. A ref starting with
    'arn:aws:secretsmanager:' or 'sm:' is read from Secrets Manager instead, which
    lets you point at a secret you already manage.
    """
    if not ref:
        raise RuntimeError("no credential reference configured")
    if ref in _params:
        return _params[ref]
    if ref.startswith("arn:aws:secretsmanager:") or ref.startswith("sm:"):
        secret_id = ref[3:] if ref.startswith("sm:") else ref
        client = boto3.client("secretsmanager", region_name=AWS_REGION)
        resp = client.get_secret_value(SecretId=secret_id)
        raw = resp.get("SecretString")
        if raw is None:
            raw = base64.b64decode(resp["SecretBinary"]).decode("utf-8")
        _params[ref] = raw.strip()
    else:
        _params[ref] = get_param(ref)
    return _params[ref]


def http(url, method="GET", headers=None, body=None, timeout=60):
    req = urllib.request.Request(url, method=method, headers=headers or {}, data=body)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read()


def load_prompt_files() -> tuple:
    with open(os.path.join(HERE, "prompts", "environment.md"), encoding="utf-8") as fh:
        env = fh.read()
    with open(os.path.join(HERE, "prompts", "standard.md"), encoding="utf-8") as fh:
        std = fh.read()
    sha = hashlib.sha256((env + std).encode()).hexdigest()[:12]
    return env + "\n\n---\n\n" + std, sha


def fingerprint(cve: str, package: str) -> str:
    return hashlib.sha256(f"{cve}|{package}".lower().encode()).hexdigest()


def environment_for_region(region: str) -> str:
    return CONFIG["region_default_environment"].get(region, CONFIG["fallback_environment"])


def normalise_environment(tags: dict, region: str) -> str:
    raw = str((tags or {}).get("Environment", "")).strip().lower()
    mapping = {k.lower(): v for k, v in CONFIG["environment_tag_map"].items()}
    if raw and raw in mapping:
        return mapping[raw]
    if not raw:
        return environment_for_region(region)
    return CONFIG["fallback_environment"]


def host_class(name: str) -> str:
    """'app2a (prod)' -> 'app'. 'github-actions-runner' -> 'github-actions-runner'."""
    m = re.match(r"^([a-z][a-z-]*?)(?:\d+[a-z]?)?(?=$|\s|\()", (name or "").strip().lower())
    return m.group(1) if m else (name or "unknown").lower()


def epss_band(score) -> int:
    return int((score or 0) * 10)


def quarter(d: dt.datetime) -> str:
    return f"{d.year}Q{(d.month - 1) // 3 + 1}"


def aliases_for(pkg: str) -> list:
    if pkg in ALIASES:
        return list(ALIASES[pkg])
    out = [pkg]
    stripped = re.sub(r"^(lib|python3?-|py|node-|ruby-|golang-)", "", pkg)
    stripped = re.sub(r"\d+(\.\d+)*$", "", stripped)
    if stripped and stripped != pkg and len(stripped) > 2:
        out.append(stripped)
    return out[:3]


# --------------------------------------------------------------------------- #
# AWS pulls
# --------------------------------------------------------------------------- #


def pull_findings(regions) -> list:
    out = []
    crit = {
        "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
        "findingType": [{"comparison": "EQUALS", "value": "PACKAGE_VULNERABILITY"}],
    }
    for region in regions:
        insp = boto3.client("inspector2", region_name=region)
        try:
            pages = insp.get_paginator("list_findings").paginate(
                filterCriteria=crit, PaginationConfig={"PageSize": 100}
            )
        except Exception as e:  # noqa: BLE001
            log.warning("inspector2 not usable in %s: %s", region, e)
            continue
        for page in pages:
            for f in page.get("findings", []):
                f["_region"] = region
                out.append(f)
    log.info("pulled %d active package findings", len(out))
    return out


def pull_coverage(regions) -> tuple:
    """Return (gaps, index). Image indexes and expired images are structural."""
    gaps, index = [], {}
    for region in regions:
        insp = boto3.client("inspector2", region_name=region)
        try:
            pages = insp.get_paginator("list_coverage").paginate()
        except Exception as e:  # noqa: BLE001
            log.warning("inspector2 coverage not usable in %s: %s", region, e)
            continue
        for page in pages:
            for c in page.get("coveredResources", []):
                st = c.get("scanStatus", {})
                index[c["resourceId"]] = st
                ok = st.get("statusCode") == "ACTIVE" and st.get("reason") == "SUCCESSFUL"
                if ok or c["resourceType"] == "AWS_ECR_CONTAINER_IMAGE":
                    continue
                gaps.append(
                    {
                        "region": region,
                        "type": c["resourceType"],
                        "id": c["resourceId"],
                        "status": st.get("statusCode"),
                        "reason": st.get("reason"),
                    }
                )
    return gaps, index


def _ecr_ref(image: str):
    m = re.match(
        r"^\d+\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com/([^:@]+)(?::([^@]+))?"
        r"(?:@(sha256:[0-9a-f]+))?$",
        image,
    )
    return (m.group(1), m.group(2), m.group(3), m.group(4)) if m else None


def _expand_digest(ecr, repo: str, image_id: dict) -> set:
    """The digest itself, plus every child manifest digest for an OCI index.

    Inspector scans the platform child manifest under a different digest, so a
    plain tag comparison misses deployed images on multi-arch builds.
    """
    out = set()
    try:
        resp = ecr.batch_get_image(
            repositoryName=repo,
            imageIds=[image_id],
            acceptedMediaTypes=[
                "application/vnd.oci.image.index.v1+json",
                "application/vnd.docker.distribution.manifest.list.v2+json",
                "application/vnd.oci.image.manifest.v1+json",
                "application/vnd.docker.distribution.manifest.v2+json",
            ],
        )
        for img in resp.get("images", []):
            out.add(img["imageId"]["imageDigest"])
            manifest = json.loads(img["imageManifest"])
            for child in manifest.get("manifests", []) or []:
                out.add(child["digest"])
    except Exception as e:  # noqa: BLE001
        log.warning("batch_get_image %s %s: %s", repo, image_id, e)
    return out


def resolve_deployed(regions) -> dict:
    """{repo: {"digests": set, "tags": set}} for images something actually runs."""
    deployed: dict = {}

    def add(region, repo, tag, digest):
        d = deployed.setdefault(repo, {"digests": set(), "tags": set()})
        ecr = boto3.client("ecr", region_name=region)
        if tag:
            d["tags"].add(tag)
            d["digests"] |= _expand_digest(ecr, repo, {"imageTag": tag})
        if digest:
            d["digests"] |= _expand_digest(ecr, repo, {"imageDigest": digest})

    for region in regions:
        ecs = boto3.client("ecs", region_name=region)
        try:
            clusters = ecs.list_clusters().get("clusterArns", [])
        except Exception as e:  # noqa: BLE001
            log.warning("ecs list_clusters %s: %s", region, e)
            continue
        for cluster in clusters:
            arns = []
            try:
                for page in ecs.get_paginator("list_services").paginate(cluster=cluster):
                    arns += page.get("serviceArns", [])
            except Exception as e:  # noqa: BLE001
                log.warning("ecs list_services %s: %s", cluster, e)
                continue
            for i in range(0, len(arns), 10):
                try:
                    svcs = ecs.describe_services(cluster=cluster, services=arns[i : i + 10]).get(
                        "services", []
                    )
                except Exception as e:  # noqa: BLE001
                    log.warning("ecs describe_services %s: %s", cluster, e)
                    continue
                for svc in svcs:
                    if svc.get("desiredCount", 0) == 0:
                        continue
                    try:
                        td = ecs.describe_task_definition(taskDefinition=svc["taskDefinition"])[
                            "taskDefinition"
                        ]
                    except Exception as e:  # noqa: BLE001
                        log.warning("describe_task_definition %s: %s", svc.get("taskDefinition"), e)
                        continue
                    for c in td.get("containerDefinitions", []):
                        ref = _ecr_ref(c.get("image", ""))
                        if ref:
                            add(ref[0], ref[1], ref[2], ref[3])
    # Compose stacks on EC2: the newest pushed image in these repos is what the
    # hosts pull, because a compose file references a tag, not a digest.
    compose_region = REGIONS[0] if REGIONS else AWS_REGION
    ecr = boto3.client("ecr", region_name=compose_region)
    for repo in CONFIG["ec2_compose_repos"]:
        try:
            imgs = []
            for page in ecr.get_paginator("describe_images").paginate(
                repositoryName=repo, filter={"tagStatus": "TAGGED"}
            ):
                imgs += page.get("imageDetails", [])
            if imgs:
                newest = max(imgs, key=lambda i: i["imagePushedAt"])
                for tag in newest.get("imageTags", []):
                    add(compose_region, repo, tag, None)
                add(compose_region, repo, None, newest["imageDigest"])
        except Exception as e:  # noqa: BLE001
            log.warning("describe_images %s: %s", repo, e)
    return deployed


def fetch_kev() -> dict | None:
    """The CISA known-exploited catalogue, or None when it cannot be read.

    A missing KEV list is never treated as "not listed": assessment is skipped
    for the run instead.
    """
    try:
        status, _, body = http(CONFIG["kev_url"], timeout=60)
        if status != 200:
            raise RuntimeError(f"KEV HTTP {status}")
        return {v["cveID"]: v for v in json.loads(body)["vulnerabilities"]}
    except Exception as e:  # noqa: BLE001
        log.error("KEV fetch failed, assessments skipped this run: %s", e)
        return None


# --------------------------------------------------------------------------- #
# Consolidation
# --------------------------------------------------------------------------- #


def resource_entry(f: dict, deployed: dict) -> dict:
    r = f["resources"][0]
    region = str(r.get("region") or f.get("_region") or AWS_REGION)
    tags = r.get("tags") or {}
    d = r.get("details", {})
    e = {
        "type": r["type"],
        "id": r["id"],
        "region": region,
        "finding_arn": f["findingArn"],
        "deployed": True,
        "environment": normalise_environment(tags, region),
        "name": tags.get("Name", ""),
    }
    if r["type"] == "AWS_ECR_CONTAINER_IMAGE":
        img = d.get("awsEcrContainerImage", {})
        repo = img.get("repositoryName", "")
        tags_ = img.get("imageTags", []) or []
        e.update(
            name=repo,
            image_tags=tags_,
            image_digest=img.get("imageHash"),
            target=f"ecr:{repo}",
        )
        dep = deployed.get(repo, {"digests": set(), "tags": set()})
        e["deployed"] = img.get("imageHash") in dep["digests"] or any(
            t in dep["tags"] for t in tags_
        )
        # ECR images carry no environment tag of their own; the region is the
        # only signal available at this point.
        e["environment"] = environment_for_region(region)
    elif r["type"] == "AWS_EC2_INSTANCE":
        e["target"] = f"ec2:{host_class(tags.get('Name', ''))}"
    elif r["type"] == "AWS_LAMBDA_FUNCTION":
        fn = d.get("awsLambdaFunction", {}).get("functionName", r["id"].split(":")[-1])
        e.update(name=fn, target=f"lambda:{fn}")
    else:
        e["target"] = f"{r['type'].lower()}:{r['id']}"
    return e


SEV_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFORMATIONAL": 0,
    "UNTRIAGED": 0,
}


def consolidate(findings: list, deployed: dict, kev: dict | None) -> dict:
    records: dict = {}
    for f in findings:
        pvd = f.get("packageVulnerabilityDetails", {})
        cve = pvd.get("vulnerabilityId") or f.get("title", "unknown")
        pkgs = pvd.get("vulnerablePackages") or [{}]
        pkg = pkgs[0].get("name") or "unknown"
        fp = fingerprint(cve, pkg)
        rec = records.setdefault(
            fp,
            {
                "fingerprint": fp,
                "cve_id": cve,
                "package_name": pkg,
                "installed_versions": [],
                "fixed_version": None,
                "severity": "UNTRIAGED",
                "cvss_score": f.get("inspectorScore"),
                "epss_score": None,
                "exploit_available": False,
                "fix_available": "NO",
                "description": (f.get("description") or "")[:1500],
                "references": (pvd.get("referenceUrls") or [])[:5],
                "resources": [],
                "_ids": set(),
            },
        )
        for p in pkgs:
            v = p.get("version")
            if v and v not in rec["installed_versions"]:
                rec["installed_versions"].append(v)
            if p.get("fixedInVersion") and not rec["fixed_version"]:
                rec["fixed_version"] = p["fixedInVersion"]
        if SEV_ORDER.get(f.get("severity", ""), 0) > SEV_ORDER.get(rec["severity"], 0):
            rec["severity"] = f["severity"]
        rec["cvss_score"] = max(rec["cvss_score"] or 0, f.get("inspectorScore") or 0) or None
        rec["epss_score"] = max(rec["epss_score"] or 0, (f.get("epss") or {}).get("score") or 0) or None
        rec["exploit_available"] = rec["exploit_available"] or f.get("exploitAvailable") == "YES"
        if f.get("fixAvailable") == "YES" or (
            f.get("fixAvailable") == "PARTIAL" and rec["fix_available"] == "NO"
        ):
            rec["fix_available"] = f["fixAvailable"]
        e = resource_entry(f, deployed)
        if e["id"] not in rec["_ids"]:
            rec["_ids"].add(e["id"])
            rec["resources"].append(e)

    for rec in records.values():
        del rec["_ids"]
        dep = [r for r in rec["resources"] if r["deployed"]]
        rec["resource_count"] = len(rec["resources"])
        rec["deployed_count"] = len(dep)
        rec["remediation_targets"] = sorted({r["target"] for r in dep})
        rec["environments"] = sorted({r["environment"] for r in dep})
        k = (kev or {}).get(rec["cve_id"])
        rec["kev_listed"] = bool(k)
        rec["kev_date_added"] = k.get("dateAdded") if k else None
        rec["kev_ransomware"] = (k or {}).get("knownRansomwareCampaignUse") == "Known"
    return records


def facts_of(rec: dict) -> dict:
    """The facts that make a record worth re-assessing. Everything else is
    bookkeeping."""
    return {
        "fix_available": rec["fix_available"],
        "kev_listed": rec["kev_listed"],
        "epss_band": epss_band(rec["epss_score"]),
        "environments": rec["environments"],
        "deployed": rec["deployed_count"] > 0,
        "targets": rec["remediation_targets"],
        "exploit_available": rec["exploit_available"],
    }


def classify(current: dict, state: dict) -> dict:
    prior = state["records"]
    out = {"new": [], "changed": [], "resources_changed": [], "unchanged": [], "gone": []}
    for fp, rec in current.items():
        old = prior.get(fp)
        if not old:
            out["new"].append(fp)
        elif facts_of(rec) != old.get("facts"):
            out["changed"].append(fp)
        elif {r["id"] for r in rec["resources"]} != {r["id"] for r in old["resources"]}:
            # Same facts, different digests or hosts: update the card, no
            # re-assessment. This is the weekly-rebuild case.
            out["resources_changed"].append(fp)
        else:
            out["unchanged"].append(fp)
    # KEV listings and fresh exploits jump the queue.
    out["changed"].sort(
        key=lambda fp: (not current[fp]["kev_listed"], not current[fp]["exploit_available"])
    )
    out["gone"] = [
        fp
        for fp in prior
        if fp not in current and prior[fp].get("jira_status_observed") != "gone"
    ]
    return out


# --------------------------------------------------------------------------- #
# Usage report: the computed evidence handed to the model
# --------------------------------------------------------------------------- #


class GitHub:
    """Thin REST client. Read-only token; code search is what matters here."""

    def __init__(self, token: str):
        self.h = {
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "inspector-triage",
        }

    def _get(self, url, accept):
        for attempt in range(3):
            status, headers, body = http(url, headers={**self.h, "Accept": accept})
            if status in (403, 429) and headers.get("X-RateLimit-Remaining") == "0":
                wait = min(70, max(1, int(headers.get("X-RateLimit-Reset", "0")) - int(time.time())))
                log.info("GitHub rate limited, sleeping %ss", wait)
                time.sleep(wait)
                continue
            if status == 404:
                return None
            if status >= 400:
                raise RuntimeError(f"GitHub {status} {url}: {body[:200]!r}")
            return body
        raise RuntimeError(f"GitHub rate limit persisted for {url}")

    def file(self, repo: str, path: str) -> str | None:
        body = self._get(
            f"https://api.github.com/repos/{repo}/contents/{urllib.parse.quote(path)}",
            "application/vnd.github.raw+json",
        )
        return body.decode("utf-8", "replace") if body is not None else None

    def code_search(self, query: str) -> list:
        scope = f" org:{GITHUB_ORG}" if GITHUB_ORG else ""
        q = urllib.parse.quote(f'"{query}"{scope}')
        body = self._get(
            f"https://api.github.com/search/code?q={q}&per_page=50",
            "application/vnd.github.text-match+json",
        )
        hits = []
        for item in (json.loads(body) if body else {}).get("items", []):
            frag = " | ".join(
                m.get("fragment", "").strip().replace("\n", " ")[:160]
                for m in item.get("text_matches", [])[:2]
            )
            hits.append({"repo": item["repository"]["full_name"], "path": item["path"], "fragment": frag})
        return hits


_search_cache: dict = {}


def _search_all(gh: GitHub, aliases: list) -> list:
    hits = []
    for a in aliases:
        if a not in _search_cache:
            try:
                _search_cache[a] = gh.code_search(a)
            except Exception as e:  # noqa: BLE001
                log.warning("code search %r: %s", a, e)
                _search_cache[a] = []
        hits += _search_cache[a]
    seen, out = set(), []
    for h in hits:
        k = (h["repo"], h["path"])
        if k not in seen:
            seen.add(k)
            out.append(h)
    return out


def build_usage_report(rec: dict, gh: GitHub | None) -> list:
    """Numbered evidence items. gh may be None when GitHub is unavailable.

    Every item is something the model can cite by number, so a reachability
    claim is checkable by construction.
    """
    items: list = []
    missing: list = []

    def add(kind, target, title, body):
        items.append(
            {
                "n": len(items) + 1,
                "kind": kind,
                "target": target,
                "title": title,
                "body": (body or "").strip()[:6000],
            }
        )

    pkg = rec["package_name"]
    aliases = aliases_for(pkg)
    for target in rec["remediation_targets"]:
        if target.startswith("ecr:"):
            src = SOURCE_MAP.get(target)
            if not src:
                add(
                    "missing",
                    target,
                    f"No source map entry for {target}",
                    "Add this target to source_map in config.json to get build evidence for it. "
                    "Without it the image may be third-party (built outside your repositories).",
                )
                continue
            if gh is None:
                missing.append(f"{target}: GitHub unavailable")
                continue
            df = gh.file(src["repo"], src["dockerfile"])
            if df is None:
                missing.append(f"{target}: {src['repo']}/{src['dockerfile']} absent")
            else:
                add("dockerfile", target, f"{src['repo']}/{src['dockerfile']}", df)
                froms = [l for l in df.splitlines() if l.strip().upper().startswith("FROM")]
                add("base_image", target, f"FROM lines in {src['dockerfile']}", "\n".join(froms))
            if src.get("compose"):
                comp = gh.file(src["repo"], src["compose"])
                if comp:
                    add("compose_service", target, f"{src['repo']}/{src['compose']}", comp[:4000])
            checked, hits = [], []
            for m in src.get("manifests", []):
                text = gh.file(src["repo"], m)
                if text is None:
                    continue
                checked.append(m)
                hits += [
                    f"{m}: {l.strip()}"
                    for l in text.splitlines()
                    if any(a.lower() in l.lower() for a in aliases)
                ]
            add(
                "manifest_hits",
                target,
                f"Dependency manifest lines mentioning {pkg}",
                "\n".join(hits)
                if hits
                else f"No mention of {pkg} or aliases {aliases} in: "
                f"{', '.join(checked) or 'no manifests found'}",
            )
        elif target.startswith("ec2:"):
            cls = target.split(":", 1)[1]
            add(
                "host_os",
                target,
                f"Host class {cls} operating system",
                CONFIG["host_class_notes"].get(cls, "No host class notes configured."),
            )
            if cls in CONFIG["compose_notes"]:
                add("compose_on_host", target, f"Compose stacks on {cls}", CONFIG["compose_notes"][cls])
            if gh is not None:
                hits = [
                    h
                    for h in _search_all(gh, aliases)
                    if h["path"].startswith("ansible/") or h["path"].startswith("config/")
                ]
                add(
                    "config_hits",
                    target,
                    f"Configuration-management mentions of {pkg}",
                    "\n".join(f"{h['path']}: {h['fragment']}" for h in hits[:20])
                    or f"No mention of {aliases} under ansible/ or config/.",
                )
        elif target.startswith("lambda:"):
            fn = target.split(":", 1)[1]
            add(
                "host_os",
                target,
                f"Lambda {fn}",
                "Managed runtime zip deployment, event-driven, no inbound listener.",
            )
            if gh is not None and CONFIG["lambda_source_repo"]:
                path = CONFIG["lambda_manifest_path"].format(function=fn)
                req = gh.file(CONFIG["lambda_source_repo"], path)
                add(
                    "manifest_hits",
                    target,
                    f"Dependency manifest for {fn}",
                    req or f"{path} absent; runtime-provided libraries and stdlib only.",
                )
    if gh is not None and REPOS:
        hits = [
            h
            for h in _search_all(gh, aliases)
            if not EXCLUDED_PATH.search(h["path"]) and h["repo"] in REPOS
        ]
        add(
            "code_search",
            "all",
            f"Code search for {aliases} across {', '.join(REPOS)}",
            "\n".join(f"{h['repo']}/{h['path']}: {h['fragment']}" for h in hits[:20])
            or "Zero hits outside excluded paths.",
        )
    else:
        missing.append("code_search: GitHub unavailable")
    add(
        "search_queries",
        "all",
        "Queries run",
        f"aliases={aliases}; GitHub code search"
        + (f" scoped to org {GITHUB_ORG}" if GITHUB_ORG else "")
        + f"; results filtered to {REPOS or 'no repos configured'}; "
        f"excluded paths matching {EXCLUDED_PATH.pattern}",
    )
    if missing:
        add(
            "missing",
            "all",
            "Items that could not be gathered",
            "\n".join(missing)
            + "\nReachability should be unknown unless the remaining items settle it.",
        )
    return items


def render_report(items: list) -> str:
    return "\n\n".join(
        f"[{i['n']}] ({i['kind']}) {i['target']}: {i['title']}\n{i['body']}" for i in items
    )


def render_record(rec: dict) -> str:
    slim = {
        k: v
        for k, v in rec.items()
        if k
        not in (
            "assessment",
            "usage_report",
            "facts",
            "jira_key",
            "jira_status_observed",
            "manually_closed",
            "proposed_assessment",
            "first_seen",
            "last_seen",
        )
    }
    slim["resources"] = [
        {k: r.get(k) for k in ("type", "name", "region", "environment", "deployed", "target", "image_tags")}
        for r in rec["resources"]
    ][:60]
    return json.dumps(slim, indent=1, default=str)


# --------------------------------------------------------------------------- #
# Assessment
# --------------------------------------------------------------------------- #


def assessment_tool() -> dict:
    return {
        "type": "function",
        "function": {
            "name": "record_assessment",
            "description": "Record the risk assessment for this vulnerability record.",
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "reachable",
                    "reachability_evidence",
                    "tier",
                    "exception_class",
                    "environment_risk",
                    "remediation",
                    "rationale",
                    "confidence",
                ],
                "properties": {
                    "reachable": {"type": "string", "enum": ["yes", "no", "unknown"]},
                    "reachability_evidence": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["report_item", "note"],
                            "properties": {
                                "report_item": {"type": "integer"},
                                "note": {"type": "string"},
                            },
                        },
                    },
                    "tier": {"type": "string", "enum": TIER_ORDER + ["accepted"]},
                    "exception_class": {"type": ["string", "null"], "enum": CLASSES + [None]},
                    "environment_risk": {
                        "type": "object",
                        "required": ENVIRONMENTS,
                        "properties": {
                            e: {
                                "type": "object",
                                "required": ["score", "rationale"],
                                "properties": {
                                    "score": {"type": "integer", "minimum": 0, "maximum": 100},
                                    "rationale": {"type": "string"},
                                },
                            }
                            for e in ENVIRONMENTS
                        },
                    },
                    "remediation": {"type": "string"},
                    "rationale": {"type": "string"},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                },
            },
        },
    }


def validate_assessment(a: dict, items: list) -> list:
    errs = []
    for k in assessment_tool()["function"]["parameters"]["required"]:
        if k not in a:
            errs.append(f"missing field {k}")
    if errs:
        return errs
    if a["reachable"] not in ("yes", "no", "unknown"):
        errs.append("reachable must be yes, no, or unknown")
    if a["tier"] not in TIER_RANK:
        errs.append(f"tier must be one of {TIER_ORDER + ['accepted']}")
    if a["exception_class"] not in CLASSES + [None]:
        errs.append(f"exception_class must be one of {CLASSES} or null")
    if a["confidence"] not in ("high", "medium", "low"):
        errs.append("confidence must be high, medium, or low")
    valid = {i["n"] for i in items}
    ev = a.get("reachability_evidence") or []
    if not isinstance(ev, list):
        errs.append("reachability_evidence must be a list")
        ev = []
    bad = [
        e.get("report_item")
        for e in ev
        if not isinstance(e, dict) or e.get("report_item") not in valid
    ]
    if bad:
        errs.append(f"reachability_evidence cites report items that do not exist: {bad}")
    if a["reachable"] == "no" and not [
        e for e in ev if isinstance(e, dict) and e.get("report_item") in valid
    ]:
        errs.append("reachable=no requires at least one valid report_item citation")
    er = a.get("environment_risk") or {}
    for env in ENVIRONMENTS:
        s = (er.get(env) or {}).get("score")
        if not isinstance(s, int) or not 0 <= s <= 100:
            errs.append(f"environment_risk.{env}.score must be an integer 0-100")
    return errs


def apply_guards(a: dict, rec: dict) -> list:
    """Floors the model cannot lower. Mutates a; returns the overrides applied."""
    notes = []
    reachable = a["reachable"] != "no"
    if rec["kev_listed"] and reachable and TIER_RANK[a["tier"]] < TIER_RANK["P1"]:
        notes.append(f"KEV-listed and reachable/unknown: tier raised from {a['tier']} to P1")
        a["tier"], a["exception_class"] = "P1", None
    if a["tier"] == "accepted":
        cls = a["exception_class"]
        prod_envs = [e for e in rec["environments"] if e not in NON_PROD]
        third_party = all(
            t.startswith("ecr:") and t not in SOURCE_MAP for t in rec["remediation_targets"]
        )
        why = None
        if not cls:
            why = "accepted without an exception class"
        elif cls == "unreachable_component" and a["reachable"] != "no":
            why = "unreachable_component requires reachable=no"
        elif cls == "non_production_only" and prod_envs:
            why = f"non_production_only but deployed in {prod_envs}"
        elif cls == "third_party_image_awaiting_upstream" and not third_party:
            why = "third_party_image_awaiting_upstream but a target is an image we build or a host"
        elif cls == "no_fix_available" and rec["fix_available"] == "YES":
            why = "no_fix_available but Inspector reports a fix"
        if why:
            fallback = (
                "P1"
                if (rec["kev_listed"] or (rec["exploit_available"] and (rec["epss_score"] or 0) >= EPSS_P1))
                else "P2"
                if rec["severity"] in ("CRITICAL", "HIGH")
                else "P3"
            )
            notes.append(f"{why}: tier raised from accepted to {fallback}")
            a["tier"], a["exception_class"] = fallback, None
    if a["tier"] != "accepted":
        a["exception_class"] = None
    return notes


class InferenceError(RuntimeError):
    def __init__(self, message: str, status_code=None):
        super().__init__(message)
        self.status_code = status_code


def provider_down(e: Exception) -> bool:
    """True for provider errors that will fail every call this run."""
    status = getattr(e, "status_code", None)
    text = str(e).lower()
    return (
        status in (401, 402, 403)
        or "organization_delinquent" in text
        or "invalid_api_key" in text
        or "insufficient_quota" in text
        or "no such model" in text
    )


class Inference:
    """Any OpenAI-compatible /chat/completions endpoint.

    Works against Groq, OpenAI, Together, Fireworks, OpenRouter, vLLM, Ollama,
    LM Studio and anything else that speaks the same shape. No SDK, so the
    deployment package stays a plain zip.
    """

    def __init__(self, base_url: str, api_key: str, model: str):
        self.url = f"{base_url.rstrip('/')}/chat/completions"
        self.model = model
        self.h = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    def _post(self, payload: dict) -> dict:
        body = json.dumps(payload).encode()
        last = None
        for attempt in range(4):
            status, _, data = http(self.url, "POST", self.h, body, timeout=180)
            if status in (429, 500, 502, 503, 504):
                last = f"HTTP {status}"
                time.sleep(2**attempt + random.random())
                continue
            if status >= 400:
                raise InferenceError(
                    f"inference {status} from {self.url}: {data[:400]!r}", status_code=status
                )
            return json.loads(data)
        raise InferenceError(f"inference retries exhausted ({last})")

    def assess(self, system_prompt: str, user_message: str, tool: dict) -> tuple:
        """Return (arguments dict, usage dict). Raises InferenceError."""
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]
        last_err = None
        for attempt in range(2):
            resp = self._post(
                {
                    "model": self.model,
                    "messages": messages,
                    "tools": [tool],
                    "tool_choice": {"type": "function", "function": {"name": tool["function"]["name"]}},
                    "temperature": 0,
                    "max_tokens": INFERENCE_MAX_TOKENS,
                }
            )
            usage = resp.get("usage") or {}
            choice = (resp.get("choices") or [{}])[0]
            msg = choice.get("message") or {}
            calls = msg.get("tool_calls") or []
            raw, last_err = None, None
            if calls:
                raw = (calls[0].get("function") or {}).get("arguments")
            elif isinstance(msg.get("content"), str) and "{" in msg["content"]:
                # Some local runtimes ignore tool_choice and answer in prose.
                raw = msg["content"][msg["content"].find("{"):]
                if raw.rstrip().endswith("```"):
                    raw = raw[: raw.rfind("```")]
            if raw is None:
                last_err = "no tool call returned"
            else:
                try:
                    return json.loads(raw), usage
                except json.JSONDecodeError as e:
                    last_err = f"arguments were not valid JSON: {e}"
            messages.append({"role": "assistant", "content": msg.get("content") or ""})
            messages.append(
                {
                    "role": "user",
                    "content": f"Your previous answer was rejected: {last_err}. "
                    f"Call {tool['function']['name']} again with a valid answer.",
                }
            )
        raise InferenceError(f"assessment failed after retry: {last_err}")


def assess(rec: dict, items: list, system_prompt: str, client: Inference) -> dict:
    tool = assessment_tool()
    user = (
        "Vulnerability record:\n"
        + render_record(rec)
        + "\n\nUsage report:\n"
        + render_report(items)
        + f"\n\nCall {tool['function']['name']} now."
    )
    errs: list = []
    for attempt in range(2):
        a, usage = client.assess(system_prompt, user, tool)
        errs = validate_assessment(a, items)
        if not errs:
            a["model"] = INFERENCE_MODEL
            a["usage"] = {
                "prompt_tokens": usage.get("prompt_tokens"),
                "completion_tokens": usage.get("completion_tokens"),
            }
            return a
        user = (
            "Vulnerability record:\n"
            + render_record(rec)
            + "\n\nUsage report:\n"
            + render_report(items)
            + f"\n\nYour previous answer was rejected: {'; '.join(errs)}. "
            f"Call {tool['function']['name']} again with a valid answer."
        )
    raise InferenceError(f"assessment failed validation after retry: {errs}")


# --------------------------------------------------------------------------- #
# Jira (REST v2 for writes with wiki markup, v3 for search, agile for boards)
# --------------------------------------------------------------------------- #


class Jira:
    def __init__(self):
        if not JIRA_BASE_URL:
            raise RuntimeError("JIRA_BASE_URL is not set")
        self.base = f"{JIRA_BASE_URL}/rest/api/2"
        self.browse = f"{JIRA_BASE_URL}/browse"
        tok = base64.b64encode(
            f"{JIRA_EMAIL}:{get_credential(JIRA_API_KEY_SECRET)}".encode()
        ).decode()
        self.h = {
            "Authorization": f"Basic {tok}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _call(self, method, path, body=None):
        for attempt in range(4):
            status, _, data = http(
                self.base + path,
                method,
                self.h,
                json.dumps(body).encode() if body is not None else None,
            )
            if status in (429, 500, 502, 503, 504):
                time.sleep(2**attempt + random.random())
                continue
            if status >= 400:
                raise RuntimeError(f"Jira {method} {path} {status}: {data[:300]!r}")
            return json.loads(data) if data else {}
        raise RuntimeError(f"Jira {method} {path}: retries exhausted")

    def find_by_label(self, label: str) -> str | None:
        # /rest/api/2/search was removed by Atlassian (410, CHANGE-2046); the
        # replacement lives only under v3.
        jql = urllib.parse.quote(
            f'project = {JIRA_PROJECT_KEY} AND labels = "{label}" ORDER BY created ASC'
        )
        status, _, data = http(
            f"{self.base.replace('/rest/api/2', '/rest/api/3')}/search/jql"
            f"?jql={jql}&fields=key&maxResults=1",
            headers=self.h,
        )
        if status >= 400:
            raise RuntimeError(f"Jira GET /search/jql {status}: {data[:300]!r}")
        issues = json.loads(data).get("issues", [])
        return issues[0]["key"] if issues else None

    def create(
        self,
        summary,
        description,
        priority,
        labels,
        duedate=None,
        assignee=None,
        issuetype=None,
        parent=None,
    ) -> str:
        fields = {
            "project": {"key": JIRA_PROJECT_KEY},
            "issuetype": {"name": issuetype or JIRA_ISSUE_TYPE},
            "summary": summary[:250],
            "description": description[:30000],
            "priority": {"name": priority},
            "labels": labels,
        }
        if duedate:
            fields["duedate"] = duedate
        if assignee:
            fields["assignee"] = {"accountId": assignee}
        if parent:
            fields["parent"] = {"key": parent}
        return self._call("POST", "/issue", {"fields": fields})["key"]

    def set_parent(self, key, parent):
        try:
            self.update(key, {"parent": {"key": parent}})
        except RuntimeError as e:
            log.warning("set parent %s -> %s: %s", key, parent, e)
            self.link(key, parent)

    def comment(self, key, text):
        self._call("POST", f"/issue/{key}/comment", {"body": text[:30000]})

    def update(self, key, fields):
        self._call("PUT", f"/issue/{key}", {"fields": fields})

    def status(self, key) -> str:
        return self._call("GET", f"/issue/{key}?fields=status")["fields"]["status"]["name"]

    def transition(self, key, target_names=(), resolution=None) -> bool:
        for t in self._call("GET", f"/issue/{key}/transitions").get("transitions", []):
            if t["name"] in target_names or t.get("to", {}).get("name") in target_names:
                body = {"transition": {"id": t["id"]}}
                if resolution:
                    body["fields"] = {"resolution": {"name": resolution}}
                try:
                    self._call("POST", f"/issue/{key}/transitions", body)
                except RuntimeError:
                    if not resolution:
                        raise
                    # The transition screen has no resolution field.
                    self._call("POST", f"/issue/{key}/transitions", {"transition": {"id": t["id"]}})
                return True
        return False

    def link(self, inward_key, outward_key, link_type="Related"):
        try:
            self._call(
                "POST",
                "/issueLink",
                {
                    "type": {"name": link_type},
                    "inwardIssue": {"key": inward_key},
                    "outwardIssue": {"key": outward_key},
                },
            )
        except RuntimeError as e:
            log.warning("issue link %s -> %s: %s", inward_key, outward_key, e)

    def ensure_board(self, state: dict):
        """A saved filter over the triage label and a Kanban board on it, created
        once. Skipped when JIRA_BOARD_ID names a board that already exists, or
        when CREATE_BOARD is false."""
        if JIRA_BOARD_ID:
            state["board_id"] = JIRA_BOARD_ID
        if state.get("board_id") or not CREATE_BOARD:
            return
        agile = self.base.replace("/rest/api/2", "/rest/agile/1.0")
        status, _, data = http(
            f"{agile}/board?name={urllib.parse.quote(BOARD_NAME)}"
            f"&projectKeyOrId={JIRA_PROJECT_KEY}",
            headers=self.h,
        )
        existing = [
            b for b in (json.loads(data).get("values", []) if status == 200 else [])
            if b["name"] == BOARD_NAME
        ]
        if existing:
            state["board_id"] = existing[0]["id"]
            return
        project_id = self._call("GET", f"/project/{JIRA_PROJECT_KEY}")["id"]
        jql = (
            f'project = {JIRA_PROJECT_KEY} AND labels = "{LABEL}" '
            f"ORDER BY priority DESC, duedate ASC, created ASC"
        )
        flt = self._call(
            "POST",
            "/filter",
            {
                "name": BOARD_NAME,
                "jql": jql,
                "description": "Every consolidated vulnerability from inspector-triage, "
                "ordered by risk-derived priority",
                "sharePermissions": [{"type": "project", "project": {"id": project_id}}],
            },
        )
        status, _, data = http(
            f"{agile}/board",
            "POST",
            self.h,
            json.dumps({"name": BOARD_NAME, "type": "kanban", "filterId": flt["id"]}).encode(),
        )
        if status >= 400:
            raise RuntimeError(f"board create {status}: {data[:200]!r}")
        state["filter_id"], state["board_id"] = flt["id"], json.loads(data)["id"]
        log.info("created Jira board %r id %s", BOARD_NAME, state["board_id"])


def inspector_link(rec: dict, r: dict) -> str:
    return (
        f"https://{r['region']}.console.aws.amazon.com/inspector/v2/home"
        f"?region={r['region']}#/findings/vulnerability/{urllib.parse.quote(rec['cve_id'])}"
    )


def risk_score(a: dict) -> int:
    """Highest environment score. This is what sets Jira priority."""
    er = a.get("environment_risk") or {}
    return max((int((er.get(e) or {}).get("score") or 0) for e in ENVIRONMENTS), default=0)


def priority_from_risk(a: dict) -> str:
    if a.get("tier") == "accepted":
        return CONFIG["accepted_jira_priority"]
    score = risk_score(a)
    for floor, name in RISK_BANDS:
        if score >= floor:
            return name
    return CONFIG["accepted_jira_priority"]


def summary_line(rec: dict, a: dict | None = None) -> str:
    targets = ", ".join(t.split(":", 1)[1] for t in rec["remediation_targets"][:3]) or "undeployed"
    a = a or rec.get("assessment") or {}
    prefix = f"[Risk {risk_score(a)}] [{a['tier']}] " if a.get("tier") else ""
    return (
        f"{prefix}{rec['cve_id']} {rec['package_name']} in {targets} "
        f"({rec['deployed_count']} resources, {', '.join(rec['environments']) or 'none'})"
    )


def describe(rec: dict, a: dict, notes: list, prompt_sha: str) -> str:
    due = (
        (now() + dt.timedelta(days=SLA_DAYS[a["tier"]])).date().isoformat()
        if a["tier"] in SLA_DAYS
        else "quarterly review"
    )
    lines = [
        f"h2. {rec['cve_id']} in {rec['package_name']}",
        "",
        f"*Risk score:* {risk_score(a)} (Jira priority {priority_from_risk(a)})  "
        f"*Tier:* {a['tier']}  *Exception class:* {a['exception_class'] or 'none'}  "
        f"*Due:* {due}  *Confidence:* {a['confidence']}",
        "",
        "h3. Facts",
        f"* Severity {rec['severity']}, CVSS {rec['cvss_score']}, EPSS {rec['epss_score']}, "
        f"exploit available: {rec['exploit_available']}, "
        f"KEV: {rec['kev_listed']}{' (ransomware)' if rec['kev_ransomware'] else ''}, "
        f"fix available: {rec['fix_available']} {rec['fixed_version'] or ''}",
        f"* Installed: {', '.join(rec['installed_versions'][:6])}",
        f"* Refs: {' '.join(rec['references'][:3])}",
        "",
        "h3. Environment risk",
    ]
    for env in ENVIRONMENTS:
        er = a["environment_risk"].get(env, {})
        lines.append(f"* {env}: {er.get('score')} - {er.get('rationale')}")
    lines += ["", f"h3. Reachability: {a['reachable']}"]
    lines += [f"* [{e['report_item']}] {e['note']}" for e in a["reachability_evidence"]]
    lines += ["", "h3. Rationale", a["rationale"], "", "h3. Remediation", a["remediation"], ""]
    if notes:
        lines += ["h3. Guard overrides applied by the Lambda"] + [f"* {n}" for n in notes] + [""]
    lines += ["h3. Resources", "||Target||Environment||Deployed||Resource||Region||Link||"]
    for r in sorted(rec["resources"], key=lambda r: (r["target"], r["environment"]))[:80]:
        rid = r.get("name") or r["id"]
        if r.get("image_tags"):
            rid += f" tags={','.join(r['image_tags'][:3])}"
        lines.append(
            f"|{r['target']}|{r['environment']}|{r['deployed']}|{rid}|{r['region']}|"
            f"[Inspector|{inspector_link(rec, r)}]|"
        )
    lines += [
        "",
        "h3. Usage report (evidence the model saw)",
        "{noformat}",
        render_report(rec.get("usage_report", []))[:12000],
        "{noformat}",
        "",
        f"_Model {a['model']}, prompt {prompt_sha}, assessed {iso()}. "
        f"Fingerprint {rec['fingerprint']}._",
    ]
    return "\n".join(lines)


def class_description(cls: str, standard: str) -> str:
    m = re.search(rf"### 5\.\d `{re.escape(cls)}`\n(.*?)(?=\n### 5\.|\n## 6)", standard, re.S)
    body = m.group(1).strip() if m else cls
    return (
        f"h2. Exception class: {cls}\n\nStanding risk acceptance record. Membership comments "
        f"are posted by inspector-triage.\n\n{body}"
    )


def assignee_for(rec: dict) -> str | None:
    for t in rec["remediation_targets"]:
        for prefix, acct in ASSIGNEES.items():
            if prefix != "default" and t.startswith(prefix):
                return acct
    return ASSIGNEES.get("default")


# --------------------------------------------------------------------------- #
# State
# --------------------------------------------------------------------------- #


def load_state() -> dict:
    s3 = boto3.client("s3", region_name=AWS_REGION)
    try:
        state = json.loads(s3.get_object(Bucket=STATE_BUCKET, Key=STATE_KEY)["Body"].read())
    except Exception as e:  # noqa: BLE001
        log.info("no readable state yet (%s); starting fresh", e)
        state = {}
    state.setdefault("records", {})
    state.setdefault("class_issues", {})
    state.setdefault("coverage_gaps", [])
    state.setdefault("last_review_quarter", None)
    return state


def save_state(state: dict):
    state["generated_at"] = iso()
    # Dry runs never touch the real state file.
    key = f"dry-run/{STATE_KEY}" if DRY_RUN else STATE_KEY
    boto3.client("s3", region_name=AWS_REGION).put_object(
        Bucket=STATE_BUCKET,
        Key=key,
        Body=json.dumps(state, default=str).encode(),
        ContentType="application/json",
    )


# --------------------------------------------------------------------------- #
# Handler
# --------------------------------------------------------------------------- #


def lambda_handler(event, context):
    t0 = time.time()
    system_prompt, prompt_sha = load_prompt_files()
    standard = system_prompt.split("\n\n---\n\n", 1)[1]
    state = load_state()
    summary: dict = {
        k: 0
        for k in (
            "new",
            "changed",
            "resources_changed",
            "unchanged",
            "gone",
            "undeployed_only",
            "assessed",
            "ticketed",
            "accepted",
            "overdue",
            "coverage_gaps",
            "failed",
            "held",
            "unassessed",
        )
    }
    p1_created, failures = [], []

    findings = pull_findings(REGIONS)
    gaps, coverage = pull_coverage(REGIONS)
    state["coverage_gaps"] = gaps
    summary["coverage_gaps"] = len(gaps)
    deployed = resolve_deployed(REGIONS)
    kev = fetch_kev()
    carried_kev = {
        r["cve_id"]: {"dateAdded": r.get("kev_date_added")}
        for r in state["records"].values()
        if r.get("kev_listed")
    }
    current = consolidate(findings, deployed, kev if kev is not None else carried_kev)
    buckets = classify(current, state)
    summary.update(
        new=len(buckets["new"]),
        changed=len(buckets["changed"]),
        resources_changed=len(buckets["resources_changed"]),
        unchanged=len(buckets["unchanged"]),
        gone=len(buckets["gone"]),
    )
    summary["undeployed_only"] = sum(1 for r in current.values() if r["deployed_count"] == 0)

    jira = None if DRY_RUN else Jira()
    if jira:
        try:
            jira.ensure_board(state)
        except Exception as e:  # noqa: BLE001
            failures.append(f"Jira board bootstrap: {e}")

    client = None
    try:
        client = Inference(
            INFERENCE_BASE_URL, get_credential(INFERENCE_API_KEY_SECRET), INFERENCE_MODEL
        )
    except Exception as e:  # noqa: BLE001
        failures.append(f"inference client: {e}")

    gh = None
    if GITHUB_TOKEN_SECRET:
        try:
            gh = GitHub(get_credential(GITHUB_TOKEN_SECRET))
        except Exception as e:  # noqa: BLE001
            log.warning("GitHub token unavailable: %s", e)
    else:
        log.warning("no GitHub token configured; reachability evidence will be thin")

    # Quarterly review: queue accepted records older than 80 days for re-assessment.
    q = quarter(now())
    review_due = state["last_review_quarter"] != q
    if review_due:
        for fp, old in state["records"].items():
            a = old.get("assessment") or {}
            if (
                fp in current
                and a.get("tier") == "accepted"
                and (now() - dt.datetime.fromisoformat(a.get("assessed_at", "2000-01-01T00:00:00+00:00"))).days > 80
                and fp not in buckets["changed"]
                and fp not in buckets["new"]
            ):
                buckets["changed"].append(fp)

    # Carry forward prior bookkeeping onto current records.
    for fp, rec in current.items():
        old = state["records"].get(fp, {})
        rec["first_seen"] = old.get("first_seen", iso())
        rec["last_seen"] = iso()
        rec["facts"] = facts_of(rec)
        for k in (
            "assessment",
            "usage_report",
            "jira_key",
            "jira_status_observed",
            "manually_closed",
            "proposed_assessment",
        ):
            if k in old:
                rec[k] = old[k]

    def remaining() -> float:
        return (context.get_remaining_time_in_millis() / 1000) if context else 900 - (time.time() - t0)

    # Assess changed facts first, then anything never assessed. A record can sit
    # in state without an assessment when an earlier run failed after saving it,
    # so "not yet assessed" is the queue condition, not membership in "new".
    unassessed = [
        fp
        for fp in current
        if fp not in buckets["changed"]
        and not current[fp].get("assessment")
        and not current[fp].get("proposed_assessment")
    ]
    queue = [fp for fp in buckets["changed"] + unassessed if current[fp]["deployed_count"] > 0]
    summary["unassessed"] = len([fp for fp in unassessed if current[fp]["deployed_count"] > 0])

    for fp in queue[:BATCH_SIZE]:
        if remaining() < 120:
            log.info("time budget reached; deferring the rest to the next run")
            break
        rec = current[fp]
        if kev is None or client is None:
            break
        try:
            items = build_usage_report(rec, gh)
            a = assess(rec, items, system_prompt, client)
            notes = apply_guards(a, rec)
            a["guard_notes"], a["assessed_at"], a["prompt_sha"] = notes, iso(), prompt_sha
            log.info(
                "decision %s",
                json.dumps(
                    {
                        "cve": rec["cve_id"],
                        "package": rec["package_name"],
                        "targets": rec["remediation_targets"],
                        "severity": rec["severity"],
                        "epss": rec["epss_score"],
                        "kev": rec["kev_listed"],
                        "fix": rec["fix_available"],
                        "reachable": a["reachable"],
                        "tier": a["tier"],
                        "class": a["exception_class"],
                        "risk": risk_score(a),
                        "priority": priority_from_risk(a),
                        "confidence": a["confidence"],
                        "guards": notes,
                        "evidence": a["reachability_evidence"],
                        "rationale": a["rationale"],
                        "remediation": a["remediation"],
                        "tokens": a.get("usage"),
                    },
                    default=str,
                ),
            )
            old_a = rec.get("assessment")
            facts_changed = state["records"].get(fp, {}).get("facts") != rec["facts"]
            if old_a and TIER_RANK[a["tier"]] < TIER_RANK[old_a["tier"]] and not facts_changed:
                # A demotion with no factual change is held for a human. This is
                # what stops a model swap on the provider side quietly draining
                # the queue.
                rec["proposed_assessment"] = a
                summary["held"] += 1
                if jira and rec.get("jira_key"):
                    jira.comment(
                        rec["jira_key"],
                        f"Re-assessment proposes lowering the tier from {old_a['tier']} to "
                        f"{a['tier']} with no change in facts. Held for human confirmation. "
                        f"Rationale: {a['rationale']}",
                    )
            else:
                rec["assessment"], rec["usage_report"] = a, items
                rec.pop("proposed_assessment", None)
                summary["assessed"] += 1
                act_jira(rec, old_a, jira, state, standard, prompt_sha, summary, p1_created)
        except Exception as e:  # noqa: BLE001
            log.exception("assessment failed for %s", rec["cve_id"])
            failures.append(f"{rec['cve_id']} {rec['package_name']}: {e}")
            summary["failed"] += 1
            if provider_down(e):
                failures.append(
                    "the inference provider rejected the request for account reasons; "
                    "assessment batch aborted for this run"
                )
                log.error("inference unavailable (%s); aborting the batch", e)
                break
        state["records"][fp] = rec
        save_state(state)

    # Everything else: resource-set comments, overdue checks, carry-over.
    for fp, rec in current.items():
        old = state["records"].get(fp)
        if (
            jira
            and rec.get("assessment")
            and not rec.get("jira_key")
            and rec["deployed_count"] > 0
            and remaining() > 60
        ):
            try:
                # Assessed earlier but Jira failed afterwards: file the card
                # without spending another assessment.
                act_jira(rec, None, jira, state, standard, prompt_sha, summary, p1_created)
                summary["ticketed_retry"] = summary.get("ticketed_retry", 0) + 1
            except Exception as e:  # noqa: BLE001
                log.exception("ticketing retry failed for %s", rec["cve_id"])
                failures.append(f"ticketing {rec['cve_id']}: {e}")
            state["records"][fp] = rec
            save_state(state)
            continue
        if (
            old
            and rec.get("jira_key")
            and jira
            and rec.get("assessment")
            and (
                fp in buckets["resources_changed"]
                or (fp in buckets["changed"] and fp not in queue[:BATCH_SIZE])
            )
        ):
            added = {r["id"] for r in rec["resources"]} - {r["id"] for r in old["resources"]}
            removed = {r["id"] for r in old["resources"]} - {r["id"] for r in rec["resources"]}
            if added or removed:
                jira.comment(
                    rec["jira_key"],
                    f"Resource set changed. Added: {sorted(added) or 'none'}. "
                    f"Removed: {sorted(removed) or 'none'}. "
                    f"Now {rec['deployed_count']} deployed of {rec['resource_count']}.",
                )
        if rec.get("jira_key") and rec.get("assessment", {}).get("tier") in SLA_DAYS and jira:
            check_overdue(rec, jira, summary)
        state["records"][fp] = rec

    # Gone: close only when every resource is absent from the account or still
    # covered by a working scan.
    for fp in buckets["gone"]:
        old = state["records"][fp]
        uncovered = [
            r
            for r in old["resources"]
            if r["id"] in coverage
            and not (coverage[r["id"]].get("statusCode") == "ACTIVE" and coverage[r["id"]].get("reason") == "SUCCESSFUL")
            and r["type"] != "AWS_ECR_CONTAINER_IMAGE"
        ]
        key = old.get("jira_key")
        if uncovered:
            if jira and key and not old.get("coverage_comment"):
                jira.comment(
                    key,
                    f"Finding disappeared from Inspector but these resources have lost scan "
                    f"coverage: {[r['id'] for r in uncovered]}. Leaving open.",
                )
                old["coverage_comment"] = True
        else:
            if jira and key and old.get("jira_status_observed") != "gone":
                jira.comment(
                    key,
                    f"No active Inspector findings for this vulnerability as of {iso()}. "
                    f"Last seen with {old.get('resource_count')} resources. Closing.",
                )
                jira.transition(key, DONE_STATUSES)
            if old.get("assessment", {}).get("tier") == "accepted" and jira:
                ck = state["class_issues"].get(old["assessment"].get("exception_class"))
                if ck:
                    jira.comment(
                        ck,
                        f"{old['cve_id']} {old['package_name']} left this class: no longer "
                        f"reported by Inspector as of {iso()}.",
                    )
            old["jira_status_observed"] = "gone"
            old["gone_at"] = iso()
        state["records"][fp] = old
    save_state(state)

    if review_due and jira and state["class_issues"]:
        post_quarterly_review(state, jira, q)
        state["last_review_quarter"] = q
        save_state(state)
    elif review_due and DRY_RUN:
        state["last_review_quarter"] = q

    summary["p1_created"], summary["failures"] = p1_created, failures[:5]
    summary["elapsed_s"] = int(time.time() - t0)
    log.info("summary %s", json.dumps(summary))
    return summary


def act_jira(rec, old_a, jira, state, standard, prompt_sha, summary, p1_created):
    """One card per vulnerability. Priority comes from the risk score, due date
    from the tier. Accepted vulnerabilities are created too, moved to the
    accepted status, and parented to their class issue."""
    a = rec["assessment"]
    tier, cls = a["tier"], a["exception_class"]
    if tier == "accepted":
        summary["accepted"] += 1
    if jira is None:
        summary["ticketed"] += 1
        return
    class_key = None
    if tier == "accepted":
        class_key = state["class_issues"].get(cls)
        if not class_key:
            class_key = jira.find_by_label(f"{LABEL}-class-{cls}") or jira.create(
                f"Vulnerability exception class: {cls}",
                class_description(cls, standard),
                CONFIG["accepted_jira_priority"],
                [LABEL, f"{LABEL}-class-{cls}"],
                assignee=ASSIGNEES.get("default"),
                issuetype=JIRA_CLASS_ISSUE_TYPE,
            )
            state["class_issues"][cls] = class_key
    desc = describe(rec, a, a.get("guard_notes", []), prompt_sha)
    priority = priority_from_risk(a)
    due = (
        (now() + dt.timedelta(days=SLA_DAYS[tier])).date().isoformat() if tier in SLA_DAYS else None
    )
    labels = [LABEL, f"cve-{rec['cve_id'].lower()}", f"fp-{rec['fingerprint'][:12]}", f"tier-{tier.lower()}"] + (
        [f"class-{cls}"] if cls else []
    )
    old_tier = (old_a or {}).get("tier")
    key = rec.get("jira_key") or jira.find_by_label(f"fp-{rec['fingerprint'][:12]}")
    created = False
    if not key:
        key = jira.create(
            summary_line(rec, a),
            desc,
            priority,
            labels,
            due,
            assignee_for(rec) if tier != "accepted" else None,
            parent=class_key if tier == "accepted" else None,
        )
        created = True
        summary["ticketed"] += 1
        if tier == TIER_ORDER[0]:
            p1_created.append(key)
    else:
        fields = {
            "summary": summary_line(rec, a)[:250],
            "description": desc,
            "priority": {"name": priority},
            "labels": labels,
        }
        if due:
            fields["duedate"] = due
        jira.update(key, fields)
    rec["jira_key"], rec["sla_due"] = key, due

    observed = rec.get("jira_status_observed")
    if tier == "accepted":
        if not created:
            jira.set_parent(key, class_key)
        if created or observed not in ("accepted", "blocked"):
            jira.comment(
                class_key,
                f"*Accepted:* {summary_line(rec, a)} ({jira.browse}/{key})\n"
                f"CVSS {rec['cvss_score']}, EPSS {rec['epss_score']}, KEV {rec['kev_listed']}, "
                f"fix {rec['fix_available']}. Reachable: {a['reachable']}.\n"
                f"{a['rationale']}\nEvidence: "
                + "; ".join(f"[{e['report_item']}] {e['note']}" for e in a["reachability_evidence"])
                + f"\n_Model {a['model']}, prompt {prompt_sha}, fingerprint {rec['fingerprint']}._",
            )
            if old_tier and old_tier != "accepted":
                jira.comment(
                    key,
                    f"Re-assessed as accepted under class {cls}. "
                    f"Acceptance record: {jira.browse}/{class_key}.",
                )
    elif not created and observed in ("accepted", "gone"):
        was_accepted = observed == "accepted"
        reason = (
            f"Promoted out of class {(old_a or {}).get('exception_class')}"
            if was_accepted
            else "Finding returned in Inspector"
        )
        jira.comment(key, f"{reason} as of {iso()}: now {tier}, priority {priority}. {a['rationale']}")
        if was_accepted:
            try:
                jira.update(key, {"parent": None})
            except RuntimeError as e:
                log.warning("clear parent %s: %s", key, e)
            old_ck = state["class_issues"].get((old_a or {}).get("exception_class"))
            if old_ck:
                jira.comment(
                    old_ck,
                    f"{rec['cve_id']} {rec['package_name']} promoted out of this class to "
                    f"{tier}: {jira.browse}/{key}.",
                )
    elif not created and old_tier and old_tier != tier:
        jira.comment(key, f"Tier changed {old_tier} to {tier}, priority now {priority}. {a['rationale']}")

    # Park or open the card. No patch available parks in the blocked status
    # whatever the tier; accepted with a patch parks in accepted; everything
    # else is open work.
    want = "blocked" if rec["fix_available"] == "NO" else ("accepted" if tier == "accepted" else "open")
    if created and want == "open":
        rec["jira_status_observed"] = "open"
        return
    if created or observed != want:
        if want == "blocked":
            jira.transition(key, (BLOCKED_STATUS,)) or jira.transition(key, (ACCEPTED_STATUS,))
        elif want == "accepted":
            jira.transition(key, (ACCEPTED_STATUS,)) or jira.transition(
                key, DONE_STATUSES, resolution=ACCEPTED_RESOLUTION
            )
        else:
            jira.transition(key, OPEN_STATUSES + DONE_STATUSES)
            if observed == "blocked":
                jira.comment(
                    key,
                    f"A fix is now available ({rec['fixed_version'] or 'see Inspector'}). "
                    f"Moving out of {BLOCKED_STATUS} into open work, priority {priority}, due {due}.",
                )
        rec["jira_status_observed"] = want


def check_overdue(rec: dict, jira, summary: dict):
    due = rec.get("sla_due")
    if not due or rec.get("manually_closed") or rec.get("jira_status_observed") == "blocked":
        return  # nothing to be overdue against while no patch exists
    if now().date() <= dt.date.fromisoformat(due):
        return
    status = jira.status(rec["jira_key"])
    if status.lower() == BLOCKED_STATUS.lower():
        return  # a human parked it; no overdue nagging
    if status.lower() in DONE_STATUSES_LOWER:
        if not rec.get("manually_closed"):
            jira.comment(
                rec["jira_key"],
                "Issue is closed in Jira while Inspector still reports the finding active. "
                "Marking manually closed; the Lambda will stay quiet until the facts change.",
            )
            rec["manually_closed"] = True
        return
    summary["overdue"] += 1
    last = rec.get("overdue_comment_at")
    if not last or (now() - dt.datetime.fromisoformat(last)).days >= 7:
        jira.comment(
            rec["jira_key"],
            f"Overdue: tier {rec['assessment']['tier']} was due {due}. Still active in "
            f"Inspector on {rec['deployed_count']} deployed resources.",
        )
        rec["overdue_comment_at"] = iso()


def post_quarterly_review(state: dict, jira, q: str):
    accepted = [
        r
        for r in state["records"].values()
        if r.get("assessment", {}).get("tier") == "accepted" and r.get("jira_status_observed") != "gone"
    ]
    held = [r for r in state["records"].values() if r.get("proposed_assessment")]
    rng = random.Random(q)
    sample = rng.sample(accepted, min(10, len(accepted)))
    for cls, key in state["class_issues"].items():
        members = [r for r in accepted if r["assessment"].get("exception_class") == cls]
        lines = [f"h3. Quarterly review {q}", f"Members: {len(members)}", ""] + [
            f"* {summary_line(r)} (assessed {r['assessment'].get('assessed_at', '')[:10]}, "
            f"confidence {r['assessment'].get('confidence')})"
            for r in members[:200]
        ]
        s = [r for r in sample if r["assessment"].get("exception_class") == cls]
        if s:
            lines += ["", "Review sample (record agree or disagree for each):"] + [
                f"* {summary_line(r)}" for r in s
            ]
        h = [r for r in held if r.get("assessment", {}).get("exception_class") == cls]
        if h:
            lines += ["", "Held demotions awaiting confirmation:"] + [
                f"* {summary_line(r)} -> {r['proposed_assessment']['tier']}" for r in h
            ]
        jira.comment(key, "\n".join(lines))


if __name__ == "__main__":  # local dry run
    # DRY_RUN=true AWS_REGION=us-east-1 STATE_BUCKET=... python3 src/handler.py
    logging.basicConfig(level=logging.INFO)
    print(json.dumps(lambda_handler({}, None), indent=1))

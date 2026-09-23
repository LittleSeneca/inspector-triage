"""Unit tests for the pure logic in handler.py.

Run: python3 -m unittest discover -s tests -v

No AWS calls and no network. Everything here is deterministic.
"""

import json
import logging
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import handler as lf  # noqa: E402

# The handler logs at INFO. Keep the test output readable.
logging.disable(logging.CRITICAL)


def finding(
    cve="CVE-2026-12087",
    pkg="perl",
    rtype="AWS_ECR_CONTAINER_IMAGE",
    rid="img-1",
    repo="web-api",
    tags=None,
    region="us-east-1",
    severity="CRITICAL",
    fix="NO",
    epss=0.02,
    exploit="NO",
    digest="sha256:aaa",
    image_tags=("latest",),
):
    details = {}
    if rtype == "AWS_ECR_CONTAINER_IMAGE":
        details = {
            "awsEcrContainerImage": {
                "repositoryName": repo,
                "imageHash": digest,
                "imageTags": list(image_tags),
            }
        }
    elif rtype == "AWS_LAMBDA_FUNCTION":
        details = {"awsLambdaFunction": {"functionName": rid}}
    return {
        "findingArn": f"arn:{rid}",
        "_region": region,
        "severity": severity,
        "inspectorScore": 9.1,
        "fixAvailable": fix,
        "exploitAvailable": exploit,
        "epss": {"score": epss},
        "description": "d",
        "packageVulnerabilityDetails": {
            "vulnerabilityId": cve,
            "vulnerablePackages": [{"name": pkg, "version": "5.36.0-7+deb12u3"}],
            "referenceUrls": [],
        },
        "resources": [
            {"type": rtype, "id": rid, "region": region, "tags": tags or {}, "details": details}
        ],
    }


DEPLOYED = {"web-api": {"digests": {"sha256:aaa"}, "tags": {"latest"}}}


def standard_md():
    path = os.path.join(os.path.dirname(lf.__file__), "prompts", "standard.md")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class FakeGitHub:
    """Stands in for the REST client. Files come from a dict; search is canned."""

    def __init__(self, files=None, hits=None):
        self.files = files or {}
        self.hits = hits or []

    def file(self, repo, path):
        return self.files.get(f"{repo}/{path}")

    def code_search(self, query):
        return [h for h in self.hits if query in h.get("fragment", "")]


class Config(unittest.TestCase):
    def test_tier_order_and_slas(self):
        self.assertEqual(lf.TIER_ORDER, ["P1", "P2", "P3"])
        self.assertEqual(lf.SLA_DAYS, {"P1": 7, "P2": 30, "P3": 90})
        self.assertEqual(lf.TIER_RANK["P1"], 3)
        self.assertEqual(lf.TIER_RANK["accepted"], 0)

    def test_environments_and_classes_are_configured(self):
        self.assertIn("production", lf.ENVIRONMENTS)
        self.assertIn("unreachable_component", lf.CLASSES)

    def test_status_lists_keep_case_for_transitions_and_lower_case_for_comparison(self):
        # Jira matches transition target names case-sensitively, so the tuple used
        # for transitions must preserve case while the comparison tuple must not.
        self.assertIn("Done", lf.DONE_STATUSES)
        self.assertIn("done", lf.DONE_STATUSES_LOWER)
        self.assertNotIn("done", lf.DONE_STATUSES)
        self.assertIn("To Do", lf.OPEN_STATUSES)

    def test_status_lists_can_be_overridden_by_a_comma_separated_env_var(self):
        with mock.patch.dict(os.environ, {"DONE_STATUSES": "Closed, Resolved , Done"}):
            self.assertEqual(
                lf._status_list("DONE_STATUSES", ["ignored"]), ["Closed", "Resolved", "Done"]
            )
        self.assertEqual(lf._status_list("NOT_SET_ANYWHERE", ["fallback"]), ["fallback"])

    def test_prompt_files_load_and_are_joined(self):
        prompt, sha = lf.load_prompt_files()
        self.assertIn("\n\n---\n\n", prompt)
        self.assertEqual(len(sha), 12)
        int(sha, 16)  # hex

    def test_standard_has_the_section_headings_class_description_needs(self):
        std = standard_md()
        for cls in lf.CLASSES:
            self.assertIn(f"`{cls}`", std)
        self.assertIn("\n## 6", std)


class Helpers(unittest.TestCase):
    def test_fingerprint_is_case_insensitive_and_stable(self):
        self.assertEqual(lf.fingerprint("CVE-1", "Perl"), lf.fingerprint("cve-1", "perl"))
        self.assertNotEqual(lf.fingerprint("CVE-1", "perl"), lf.fingerprint("CVE-2", "perl"))

    def test_environment_normalisation(self):
        self.assertEqual(lf.normalise_environment({"Environment": "prod"}, "us-east-1"), "production")
        self.assertEqual(lf.normalise_environment({"Environment": "PROD"}, "us-east-1"), "production")
        self.assertEqual(
            lf.normalise_environment({"Environment": "staging"}, "us-east-1"), "non-production"
        )
        # No tag and no region default: falls back, which is conservative on purpose.
        self.assertEqual(lf.normalise_environment({}, "eu-west-1"), lf.CONFIG["fallback_environment"])
        # An unrecognised tag also falls back rather than inventing an environment.
        self.assertEqual(
            lf.normalise_environment({"Environment": "wat"}, "us-east-1"),
            lf.CONFIG["fallback_environment"],
        )

    def test_host_class(self):
        cases = [
            ("app2a (tenant)", "app"),
            ("app0 (canary)", "app"),
            ("worker2 (batch runner)", "worker"),
            ("github-actions-runner", "github-actions-runner"),
            ("proxy (edge)", "proxy"),
            ("reports (dashboards)", "reports"),
            ("batch1", "batch"),
            ("", "unknown"),
        ]
        for name, expected in cases:
            self.assertEqual(lf.host_class(name), expected, name)

    def test_aliases_for_uses_the_table_then_falls_back_to_stripping(self):
        self.assertEqual(lf.aliases_for("perl"), ["perl", "/usr/bin/perl", ".pl"])
        self.assertIn("openssl", lf.aliases_for("libssl3"))
        # Unknown package: the name itself plus a de-prefixed, de-versioned form.
        self.assertEqual(lf.aliases_for("libfoo1.2.3"), ["libfoo1.2.3", "foo"])

    def test_epss_band_and_quarter(self):
        self.assertEqual(lf.epss_band(0.42), 4)
        self.assertEqual(lf.epss_band(None), 0)
        self.assertEqual(lf.quarter(lf.dt.datetime(2026, 5, 4)), "2026Q2")


class Consolidation(unittest.TestCase):
    def test_four_findings_become_one_record_with_deployment_flags(self):
        fs = [
            finding(rid="img-1"),
            finding(rid="img-2", digest="sha256:old", image_tags=("abc123",)),
            finding(
                rid="i-1",
                rtype="AWS_EC2_INSTANCE",
                tags={"Name": "app4 (prod)", "Environment": "prod"},
            ),
            finding(
                rid="i-2",
                rtype="AWS_EC2_INSTANCE",
                tags={"Name": "app2b (stage)", "Environment": "staging"},
                region="us-west-2",
            ),
        ]
        recs = lf.consolidate(
            fs, DEPLOYED, {"CVE-2026-12087": {"dateAdded": "2026-09-01", "knownRansomwareCampaignUse": "Unknown"}}
        )
        self.assertEqual(len(recs), 1)
        rec = next(iter(recs.values()))
        self.assertEqual(rec["resource_count"], 4)
        self.assertEqual(rec["deployed_count"], 3)  # the old image tag is undeployed
        self.assertEqual(rec["remediation_targets"], ["ec2:app", "ecr:web-api"])
        self.assertEqual(rec["environments"], ["non-production", "production"])
        self.assertTrue(rec["kev_listed"])
        self.assertEqual(rec["severity"], "CRITICAL")
        self.assertEqual(rec["fix_available"], "NO")

    def test_undeployed_only_record_has_no_targets(self):
        fs = [finding(rid="img-9", digest="sha256:dead", image_tags=("old",))]
        rec = next(iter(lf.consolidate(fs, DEPLOYED, {}).values()))
        self.assertEqual(rec["deployed_count"], 0)
        self.assertEqual(rec["remediation_targets"], [])

    def test_fix_available_partial_does_not_overwrite_yes(self):
        fs = [finding(fix="YES"), finding(rid="img-2", fix="PARTIAL", digest="sha256:zzz")]
        rec = next(iter(lf.consolidate(fs, DEPLOYED, {}).values()))
        self.assertEqual(rec["fix_available"], "YES")

    def test_severity_takes_the_worst_and_epss_the_highest(self):
        fs = [
            finding(severity="LOW", epss=0.01),
            finding(rid="img-2", severity="HIGH", epss=0.55, digest="sha256:bbb"),
        ]
        rec = next(iter(lf.consolidate(fs, DEPLOYED, {}).values()))
        self.assertEqual(rec["severity"], "HIGH")
        self.assertEqual(rec["epss_score"], 0.55)

    def test_classify_new_changed_unchanged_gone(self):
        recs = lf.consolidate([finding()], DEPLOYED, {})
        fp = next(iter(recs))
        rec = recs[fp]
        rec["facts"] = lf.facts_of(rec)
        state = {
            "records": {
                fp: dict(rec),
                "zzz": {"resources": [], "facts": {}, "jira_status_observed": "open"},
            }
        }
        b = lf.classify(recs, state)
        self.assertEqual(b["unchanged"], [fp])
        self.assertEqual(b["gone"], ["zzz"])

        recs2 = lf.consolidate([finding(fix="YES")], DEPLOYED, {})
        self.assertEqual(lf.classify(recs2, state)["changed"], [fp])
        self.assertEqual(lf.classify(recs2, {"records": {}})["new"], [fp])

        # A new image digest with the same facts updates the card without a
        # re-assessment. This is the weekly-rebuild case.
        recs3 = lf.consolidate([finding(rid="img-9", digest="sha256:aaa")], DEPLOYED, {})
        b3 = lf.classify(recs3, state)
        self.assertEqual(b3["resources_changed"], [fp])
        self.assertEqual(b3["changed"], [])

    def test_kev_listings_sort_to_the_front_of_changed(self):
        base = lf.consolidate([finding()], DEPLOYED, {})
        fp = next(iter(base))
        state = {"records": {fp: {"resources": base[fp]["resources"], "facts": {"stale": True}}}}
        plain = lf.consolidate([finding()], DEPLOYED, {})
        kev = lf.consolidate([finding()], DEPLOYED, {"CVE-2026-12087": {"dateAdded": "2026-01-01"}})
        other = lf.consolidate([finding(cve="CVE-2026-99999")], DEPLOYED, {})
        other_fp = next(iter(other))
        state["records"][other_fp] = {"resources": other[other_fp]["resources"], "facts": {"stale": True}}
        merged = {**plain, **other}
        merged[fp]["kev_listed"] = True
        merged[other_fp]["kev_listed"] = False
        self.assertEqual(lf.classify(merged, state)["changed"][0], fp)
        self.assertTrue(kev[fp]["kev_listed"])

    def test_gone_record_already_marked_gone_is_not_reprocessed(self):
        state = {
            "records": {
                "abc": {"resources": [], "facts": {}, "jira_status_observed": "gone"},
            }
        }
        self.assertEqual(lf.classify({}, state)["gone"], [])


class UsageReport(unittest.TestCase):
    def setUp(self):
        lf._search_cache.clear()

    def rec(self, targets):
        return {"package_name": "perl", "remediation_targets": targets}

    def test_no_source_map_entry_is_itself_evidence_of_a_gap(self):
        items = lf.build_usage_report(self.rec(["ecr:unknown-image"]), None)
        kinds = [i["kind"] for i in items]
        self.assertIn("missing", kinds)
        body = " ".join(i["body"] for i in items)
        self.assertIn("source_map", body)
        # search_queries is always present so the reader can judge the search.
        self.assertIn("search_queries", kinds)

    def test_github_unavailable_degrades_to_missing(self):
        with mock.patch.dict(lf.SOURCE_MAP, {"ecr:web": {"repo": "acme/web", "dockerfile": "Dockerfile"}}):
            items = lf.build_usage_report(self.rec(["ecr:web"]), None)
        missing = [i for i in items if i["kind"] == "missing"]
        self.assertTrue(missing)
        self.assertIn("GitHub unavailable", missing[0]["body"])

    def test_full_report_from_a_github_client(self):
        files = {
            "acme/web/Dockerfile": "FROM python:3.12-slim-bookworm\nRUN pip install x\nUSER app\n",
            "acme/web/compose.yml": "services:\n  web:\n    image: web\n    ports: ['80:80']\n",
            "acme/web/requirements.txt": "flask==3.0\nrequests==2.31\n",
        }
        gh = FakeGitHub(
            files=files,
            hits=[{"repo": "acme/web", "path": "app/main.py", "fragment": "import perl"}],
        )
        with mock.patch.dict(
            lf.SOURCE_MAP,
            {
                "ecr:web": {
                    "repo": "acme/web",
                    "dockerfile": "Dockerfile",
                    "compose": "compose.yml",
                    "manifests": ["requirements.txt"],
                }
            },
        ), mock.patch.object(lf, "REPOS", ["acme/web"]):
            items = lf.build_usage_report(self.rec(["ecr:web"]), gh)
        kinds = [i["kind"] for i in items]
        for expected in ("dockerfile", "base_image", "compose_service", "manifest_hits", "code_search", "search_queries"):
            self.assertIn(expected, kinds)
        # Numbers are contiguous from 1, because the model cites them.
        self.assertEqual([i["n"] for i in items], list(range(1, len(items) + 1)))
        base = next(i for i in items if i["kind"] == "base_image")
        self.assertIn("FROM python:3.12-slim-bookworm", base["body"])
        manifest = next(i for i in items if i["kind"] == "manifest_hits")
        self.assertIn("No mention of perl", manifest["body"])

    def test_manifest_hits_are_reported_when_present(self):
        files = {
            "acme/web/Dockerfile": "FROM alpine\n",
            "acme/web/requirements.txt": "perl-bindings==1.0\nflask==3.0\n",
        }
        gh = FakeGitHub(files=files)
        with mock.patch.dict(
            lf.SOURCE_MAP,
            {"ecr:web": {"repo": "acme/web", "dockerfile": "Dockerfile", "manifests": ["requirements.txt"]}},
        ), mock.patch.object(lf, "REPOS", ["acme/web"]):
            items = lf.build_usage_report(self.rec(["ecr:web"]), gh)
        manifest = next(i for i in items if i["kind"] == "manifest_hits")
        self.assertIn("perl-bindings==1.0", manifest["body"])

    def test_ec2_and_lambda_targets_produce_host_items(self):
        gh = FakeGitHub(
            files={"acme/infrastructure/functions/my-fn/requirements.txt": "requests==2.31"}
        )
        cfg = dict(lf.CONFIG)
        cfg["host_class_notes"] = {"app": "Amazon Linux 2023"}
        cfg["compose_notes"] = {"app": "web stack: web-api on :80, postgres, redis"}
        cfg["lambda_source_repo"] = "acme/infrastructure"
        with mock.patch.object(lf, "REPOS", []), mock.patch.object(lf, "CONFIG", cfg):
            items = lf.build_usage_report(self.rec(["ec2:app", "lambda:my-fn"]), gh)
        kinds = [i["kind"] for i in items]
        self.assertIn("host_os", kinds)
        self.assertIn("compose_on_host", kinds)
        self.assertIn("config_hits", kinds)
        lambda_manifest = [
            i for i in items if i["kind"] == "manifest_hits" and i["target"] == "lambda:my-fn"
        ]
        self.assertTrue(lambda_manifest)
        self.assertIn("requests==2.31", lambda_manifest[0]["body"])

    def test_host_class_without_notes_still_produces_an_item(self):
        with mock.patch.object(lf, "REPOS", []):
            items = lf.build_usage_report(self.rec(["ec2:unknown-class"]), None)
        host = next(i for i in items if i["kind"] == "host_os")
        self.assertIn("No host class notes configured", host["body"])

    def test_render_report_numbers_every_item(self):
        items = [
            {"n": 1, "kind": "dockerfile", "target": "ecr:x", "title": "t", "body": "b"},
            {"n": 2, "kind": "code_search", "target": "all", "title": "t", "body": "zero"},
        ]
        text = lf.render_report(items)
        self.assertIn("[1] (dockerfile) ecr:x: t", text)
        self.assertIn("[2] (code_search) all: t", text)


class AssessmentValidation(unittest.TestCase):
    items = [
        {"n": 1, "kind": "dockerfile", "target": "ecr:x", "title": "t", "body": "b"},
        {"n": 2, "kind": "code_search", "target": "all", "title": "t", "body": "Zero hits"},
    ]

    def good(self, **over):
        a = {
            "reachable": "no",
            "reachability_evidence": [{"report_item": 2, "note": "zero hits"}],
            "tier": "accepted",
            "exception_class": "unreachable_component",
            "environment_risk": {e: {"score": 5, "rationale": "r"} for e in lf.ENVIRONMENTS},
            "remediation": "none",
            "rationale": "r",
            "confidence": "high",
        }
        a.update(over)
        return a

    def test_good_assessment_validates(self):
        self.assertEqual(lf.validate_assessment(self.good(), self.items), [])

    def test_missing_required_field_is_rejected(self):
        a = self.good()
        del a["rationale"]
        self.assertTrue(any("missing field rationale" in e for e in lf.validate_assessment(a, self.items)))

    def test_citation_to_a_nonexistent_item_is_rejected(self):
        a = self.good(reachability_evidence=[{"report_item": 99, "note": "n"}])
        errs = lf.validate_assessment(a, self.items)
        self.assertTrue(any("do not exist" in e for e in errs))

    def test_unreachable_with_no_citation_is_rejected(self):
        a = self.good(reachability_evidence=[])
        errs = lf.validate_assessment(a, self.items)
        self.assertTrue(any("requires at least one valid report_item" in e for e in errs))

    def test_reachable_yes_needs_no_citation(self):
        a = self.good(reachable="yes", tier="P2", exception_class=None, reachability_evidence=[])
        self.assertEqual(lf.validate_assessment(a, self.items), [])

    def test_bad_tier_class_and_confidence_are_rejected(self):
        self.assertTrue(lf.validate_assessment(self.good(tier="P9"), self.items))
        self.assertTrue(lf.validate_assessment(self.good(exception_class="made_up"), self.items))
        self.assertTrue(lf.validate_assessment(self.good(confidence="certain"), self.items))

    def test_environment_risk_must_cover_every_environment_in_range(self):
        a = self.good(environment_risk={"production": {"score": 5, "rationale": "r"}})
        errs = lf.validate_assessment(a, self.items)
        self.assertTrue(any("non-production" in e for e in errs))
        a = self.good(
            environment_risk={e: {"score": 500, "rationale": "r"} for e in lf.ENVIRONMENTS}
        )
        self.assertTrue(any("0-100" in e for e in lf.validate_assessment(a, self.items)))

    def test_the_tool_schema_requires_every_environment(self):
        schema = lf.assessment_tool()["function"]["parameters"]
        self.assertEqual(schema["properties"]["environment_risk"]["required"], lf.ENVIRONMENTS)
        self.assertEqual(schema["properties"]["tier"]["enum"], lf.TIER_ORDER + ["accepted"])
        self.assertEqual(schema["properties"]["exception_class"]["enum"], lf.CLASSES + [None])


class Guards(unittest.TestCase):
    def rec(self, **over):
        r = {
            "kev_listed": False,
            "exploit_available": False,
            "epss_score": 0.0,
            "fix_available": "NO",
            "severity": "CRITICAL",
            "environments": ["production"],
            "remediation_targets": ["ecr:web"],
        }
        r.update(over)
        return r

    def a(self, **over):
        base = {
            "reachable": "yes",
            "tier": "P3",
            "exception_class": None,
            "environment_risk": {},
        }
        base.update(over)
        return base

    def test_kev_listed_and_reachable_is_floored_at_p1(self):
        a = self.a(tier="P3")
        notes = lf.apply_guards(a, self.rec(kev_listed=True))
        self.assertEqual(a["tier"], "P1")
        self.assertTrue(any("KEV-listed" in n for n in notes))

    def test_kev_listed_but_unreachable_is_not_floored(self):
        a = self.a(tier="P3", reachable="no")
        lf.apply_guards(a, self.rec(kev_listed=True))
        self.assertEqual(a["tier"], "P3")

    def test_accepted_without_a_class_is_raised(self):
        a = self.a(tier="accepted", exception_class=None)
        notes = lf.apply_guards(a, self.rec())
        self.assertEqual(a["tier"], "P2")  # critical severity, no KEV, no exploit
        self.assertIsNone(a["exception_class"])
        self.assertTrue(any("without an exception class" in n for n in notes))

    def test_unreachable_component_requires_reachable_no(self):
        a = self.a(tier="accepted", exception_class="unreachable_component", reachable="yes")
        notes = lf.apply_guards(a, self.rec())
        self.assertEqual(a["tier"], "P2")
        self.assertTrue(any("requires reachable=no" in n for n in notes))

    def test_non_production_only_fails_when_a_production_resource_exists(self):
        a = self.a(tier="accepted", exception_class="non_production_only", reachable="no")
        notes = lf.apply_guards(a, self.rec(environments=["production", "non-production"]))
        self.assertEqual(a["tier"], "P2")
        self.assertTrue(any("non_production_only" in n for n in notes))

    def test_non_production_only_passes_when_only_non_production(self):
        a = self.a(tier="accepted", exception_class="non_production_only", reachable="no")
        notes = lf.apply_guards(a, self.rec(environments=["non-production"]))
        self.assertEqual(a["tier"], "accepted")
        self.assertEqual(notes, [])

    def test_no_fix_available_fails_when_a_fix_exists(self):
        a = self.a(tier="accepted", exception_class="no_fix_available", reachable="no")
        notes = lf.apply_guards(a, self.rec(fix_available="YES"))
        self.assertEqual(a["tier"], "P2")
        self.assertTrue(any("no_fix_available" in n for n in notes))

    def test_third_party_class_fails_when_a_target_is_an_image_we_build(self):
        a = self.a(tier="accepted", exception_class="third_party_image_awaiting_upstream", reachable="no")
        with mock.patch.dict(lf.SOURCE_MAP, {"ecr:web": {"repo": "acme/web", "dockerfile": "Dockerfile"}}):
            notes = lf.apply_guards(a, self.rec(remediation_targets=["ecr:web"]))
        self.assertEqual(a["tier"], "P2")
        self.assertTrue(any("third_party_image_awaiting_upstream" in n for n in notes))

    def test_third_party_class_passes_for_an_unmapped_image(self):
        a = self.a(tier="accepted", exception_class="third_party_image_awaiting_upstream", reachable="no")
        notes = lf.apply_guards(a, self.rec(remediation_targets=["ecr:vendor-thing"]))
        self.assertEqual(a["tier"], "accepted")
        self.assertEqual(notes, [])

    def test_a_valid_unreachable_acceptance_survives_untouched(self):
        a = self.a(tier="accepted", exception_class="unreachable_component", reachable="no")
        notes = lf.apply_guards(a, self.rec(environments=["production"]))
        self.assertEqual(a["tier"], "accepted")
        self.assertEqual(a["exception_class"], "unreachable_component")
        self.assertEqual(notes, [])

    def test_a_non_accepted_tier_never_carries_a_class(self):
        a = self.a(tier="P1", exception_class="no_fix_available")
        lf.apply_guards(a, self.rec())
        self.assertIsNone(a["exception_class"])

    def test_exploit_with_high_epss_and_kev_absent_still_floors_at_p1(self):
        # Not a guard, but the tier rules should have produced P1; the guard must
        # not touch it.
        a = self.a(tier="P1")
        notes = lf.apply_guards(a, self.rec(exploit_available=True, epss_score=0.5))
        self.assertEqual(a["tier"], "P1")
        self.assertEqual(notes, [])


class RiskAndPriority(unittest.TestCase):
    def test_risk_score_is_the_highest_environment(self):
        a = {
            "tier": "P2",
            "environment_risk": {
                "production": {"score": 72, "rationale": ""},
                "non-production": {"score": 5, "rationale": ""},
            },
        }
        self.assertEqual(lf.risk_score(a), 72)
        self.assertEqual(lf.priority_from_risk(a), "High")

    def test_bands(self):
        for score, expected in ((95, "Highest"), (81, "Highest"), (80, "High"), (51, "High"),
                                (50, "Medium"), (21, "Medium"), (20, "Low"), (1, "Low"), (0, "Lowest")):
            a = {"tier": "P2", "environment_risk": {"production": {"score": score, "rationale": ""}}}
            self.assertEqual(lf.priority_from_risk(a), expected, score)

    def test_accepted_is_always_lowest(self):
        a = {
            "tier": "accepted",
            "environment_risk": {"production": {"score": 99, "rationale": ""}},
        }
        self.assertEqual(lf.priority_from_risk(a), lf.CONFIG["accepted_jira_priority"])

    def test_summary_line_carries_risk_and_tier(self):
        rec = {
            "cve_id": "CVE-2026-1",
            "package_name": "perl",
            "remediation_targets": ["ecr:web", "ec2:app"],
            "deployed_count": 4,
            "environments": ["production"],
        }
        a = {"tier": "P2", "environment_risk": {"production": {"score": 72, "rationale": ""}}}
        line = lf.summary_line(rec, a)
        self.assertTrue(line.startswith("[Risk 72] [P2] CVE-2026-1 perl in web, app (4 resources, production)"))


class ClassDescription(unittest.TestCase):
    def test_class_body_is_lifted_out_of_the_standard(self):
        std = standard_md()
        for cls in lf.CLASSES:
            desc = lf.class_description(cls, std)
            self.assertIn(f"h2. Exception class: {cls}", desc)
            self.assertIn("**Applies when**", desc)
            # It must stop before the next class.
            self.assertNotIn("### 5.", desc)

    def test_unknown_class_falls_back_to_the_name(self):
        self.assertIn("made_up", lf.class_description("made_up", "no headings here"))


class Credentials(unittest.TestCase):
    def setUp(self):
        lf._params.clear()

    def test_ssm_reference_reads_through_parameter_store(self):
        with mock.patch.object(lf, "get_param", return_value="ssm-secret"):
            self.assertEqual(lf.get_credential("/some/path"), "ssm-secret")

    def test_sm_prefix_reads_through_secrets_manager(self):
        client = mock.MagicMock()
        client.get_secret_value.return_value = {"SecretString": "  sm-secret  "}
        with mock.patch.object(lf.boto3, "client", return_value=client):
            self.assertEqual(lf.get_credential("sm:inspector-triage/jira"), "sm-secret")
        client.get_secret_value.assert_called_once_with(SecretId="inspector-triage/jira")

    def test_secrets_manager_arn_is_recognised(self):
        client = mock.MagicMock()
        client.get_secret_value.return_value = {"SecretString": "arn-secret"}
        with mock.patch.object(lf.boto3, "client", return_value=client):
            ref = "arn:aws:secretsmanager:us-east-1:123456789012:secret:inspector-triage/jira-AbCdEf"
            self.assertEqual(lf.get_credential(ref), "arn-secret")

    def test_empty_reference_is_an_error(self):
        with self.assertRaises(RuntimeError):
            lf.get_credential("")


class InferenceClient(unittest.TestCase):
    TOOL_ARGS = {
        "reachable": "yes",
        "reachability_evidence": [{"report_item": 1, "note": "n"}],
        "tier": "P2",
        "exception_class": None,
        "environment_risk": {e: {"score": 40, "rationale": "r"} for e in lf.ENVIRONMENTS},
        "remediation": "bump the base image",
        "rationale": "r",
        "confidence": "medium",
    }

    def response(self, message, usage=None):
        return (
            200,
            {},
            json.dumps(
                {"choices": [{"message": message}], "usage": usage or {"prompt_tokens": 10, "completion_tokens": 5}}
            ).encode(),
        )

    def test_tool_call_arguments_are_parsed(self):
        payload = self.response(
            {
                "tool_calls": [
                    {"id": "1", "function": {"name": "record_assessment", "arguments": json.dumps(self.TOOL_ARGS)}}
                ]
            }
        )
        with mock.patch.object(lf, "http", return_value=payload):
            args, usage = lf.Inference("https://x/v1", "k", "m").assess("s", "u", lf.assessment_tool())
        self.assertEqual(args["tier"], "P2")
        self.assertEqual(usage["prompt_tokens"], 10)

    def test_prose_answer_is_recovered_for_runtimes_that_ignore_tool_choice(self):
        payload = self.response(
            {"content": "Here you go:\n" + json.dumps(self.TOOL_ARGS) + "\n```"}
        )
        with mock.patch.object(lf, "http", return_value=payload):
            args, _ = lf.Inference("https://x/v1", "k", "m").assess("s", "u", lf.assessment_tool())
        self.assertEqual(args["reachable"], "yes")

    def test_auth_failure_is_recognised_as_the_provider_being_down(self):
        with mock.patch.object(lf, "http", return_value=(401, {}, b'{"error":"invalid_api_key"}')):
            with self.assertRaises(lf.InferenceError) as ctx:
                lf.Inference("https://x/v1", "k", "m").assess("s", "u", lf.assessment_tool())
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertTrue(lf.provider_down(ctx.exception))

    def test_retryable_statuses_are_retried_then_succeed(self):
        calls = []

        def flaky(url, method="GET", headers=None, body=None, timeout=60):
            calls.append(1)
            if len(calls) < 3:
                return 503, {}, b""
            return self.response(
                {
                    "tool_calls": [
                        {"id": "1", "function": {"name": "record_assessment", "arguments": json.dumps(self.TOOL_ARGS)}}
                    ]
                }
            )

        with mock.patch.object(lf, "http", side_effect=flaky), mock.patch.object(lf.time, "sleep"):
            args, _ = lf.Inference("https://x/v1", "k", "m").assess("s", "u", lf.assessment_tool())
        self.assertEqual(len(calls), 3)
        self.assertEqual(args["tier"], "P2")

    def test_unparseable_answer_raises_after_the_internal_retry(self):
        with mock.patch.object(lf, "http", return_value=self.response({"content": "no json here"})), mock.patch.object(
            lf.time, "sleep"
        ):
            with self.assertRaises(lf.InferenceError):
                lf.Inference("https://x/v1", "k", "m").assess("s", "u", lf.assessment_tool())

    def test_request_shape_is_openai_compatible(self):
        captured = {}

        def capture(url, method="GET", headers=None, body=None, timeout=60):
            captured["url"] = url
            captured["body"] = json.loads(body)
            captured["headers"] = headers
            return self.response(
                {
                    "tool_calls": [
                        {"id": "1", "function": {"name": "record_assessment", "arguments": json.dumps(self.TOOL_ARGS)}}
                    ]
                }
            )

        with mock.patch.object(lf, "http", side_effect=capture):
            lf.Inference("https://api.groq.com/openai/v1", "secret", "some-model").assess(
                "sys", "usr", lf.assessment_tool()
            )
        self.assertEqual(captured["url"], "https://api.groq.com/openai/v1/chat/completions")
        self.assertEqual(captured["body"]["model"], "some-model")
        self.assertEqual(captured["body"]["temperature"], 0)
        self.assertEqual(
            captured["body"]["tool_choice"], {"type": "function", "function": {"name": "record_assessment"}}
        )
        self.assertEqual(captured["headers"]["Authorization"], "Bearer secret")


class AssessWrapper(unittest.TestCase):
    """assess() re-asks once when the model's answer fails validation."""

    def client(self, answers):
        class C:
            def __init__(self):
                self.n = 0

            def assess(self, system_prompt, user, tool):
                a = answers[min(self.n, len(answers) - 1)]
                self.n += 1
                return a, {"prompt_tokens": 1, "completion_tokens": 1}

        return C()

    def items(self):
        return [{"n": 1, "kind": "code_search", "target": "all", "title": "t", "body": "Zero hits"}]

    def valid(self):
        return {
            "reachable": "no",
            "reachability_evidence": [{"report_item": 1, "note": "zero hits"}],
            "tier": "accepted",
            "exception_class": "unreachable_component",
            "environment_risk": {e: {"score": 3, "rationale": "r"} for e in lf.ENVIRONMENTS},
            "remediation": "none",
            "rationale": "r",
            "confidence": "high",
        }

    def rec(self):
        return {"cve_id": "CVE-1", "package_name": "perl", "resources": [], "remediation_targets": ["ecr:x"]}

    def test_valid_first_answer_is_accepted_and_stamped(self):
        client = self.client([self.valid()])
        a = lf.assess(self.rec(), self.items(), "sys", client)
        self.assertEqual(a["tier"], "accepted")
        self.assertEqual(a["model"], lf.INFERENCE_MODEL)
        self.assertEqual(client.n, 1)

    def test_invalid_first_answer_is_retried_once(self):
        bad = self.valid()
        bad["reachability_evidence"] = [{"report_item": 999, "note": "made up"}]
        client = self.client([bad, self.valid()])
        a = lf.assess(self.rec(), self.items(), "sys", client)
        self.assertEqual(a["tier"], "accepted")
        self.assertEqual(client.n, 2)

    def test_two_invalid_answers_raise(self):
        bad = self.valid()
        bad["tier"] = "P9"
        client = self.client([bad, bad])
        with self.assertRaises(lf.InferenceError):
            lf.assess(self.rec(), self.items(), "sys", client)


class EndToEnd(unittest.TestCase):
    """lambda_handler wiring, with AWS, the provider and Jira all stubbed.

    The unit tests above cover the pieces. These prove the pieces are actually
    connected: consolidation reaches the assessment, the assessment reaches Jira,
    state round-trips, and the second run does not re-assess unchanged facts.
    """

    def setUp(self):
        lf._search_cache.clear()
        lf._params.clear()

    def assessment(self, tier="P2", reachable="yes", cls=None, score=60):
        return {
            "reachable": reachable,
            "reachability_evidence": [{"report_item": 1, "note": "n"}] if reachable != "yes" else [],
            "tier": tier,
            "exception_class": cls,
            "environment_risk": {e: {"score": score, "rationale": "r"} for e in lf.ENVIRONMENTS},
            "remediation": "bump the base image",
            "rationale": "r",
            "confidence": "high",
        }

    def run_handler(self, findings, assessments, kev=None, state=None, kev_missing=False):
        """Returns (summary, saved_state, jira_calls)."""
        saved = {}
        calls = []
        pending = list(assessments)

        class FakeInference:
            def __init__(self, *a, **k):
                pass

            def assess(self, system_prompt, user_message, tool):
                return pending.pop(0), {"prompt_tokens": 1, "completion_tokens": 1}

        class FakeJira:
            browse = "https://example.atlassian.net/browse"

            def __init__(self):
                calls.append("init")

            def ensure_board(self, s):
                calls.append("ensure_board")

            def find_by_label(self, label):
                return None

            def create(self, *a, **kw):
                calls.append(("create", a[0] if a else kw.get("summary"), kw.get("parent")))
                return "SEC-1"

            def update(self, *a, **kw):
                calls.append("update")

            def comment(self, *a, **kw):
                calls.append("comment")

            def transition(self, *a, **kw):
                calls.append("transition")
                return True

            def status(self, *a, **kw):
                return "To Do"

            def set_parent(self, *a, **kw):
                calls.append("set_parent")

            def link(self, *a, **kw):
                pass

        fresh_state = state or {
            "records": {},
            "class_issues": {},
            "coverage_gaps": [],
            "last_review_quarter": None,
        }
        with mock.patch.object(lf, "pull_findings", return_value=findings), mock.patch.object(
            lf, "pull_coverage", return_value=([], {})
        ), mock.patch.object(lf, "resolve_deployed", return_value=DEPLOYED), mock.patch.object(
            lf, "fetch_kev", return_value=None if kev_missing else (kev or {})
        ), mock.patch.object(
            lf, "Inference", FakeInference
        ), mock.patch.object(
            lf, "Jira", FakeJira
        ), mock.patch.object(
            lf, "get_credential", return_value="stub"
        ), mock.patch.object(
            lf, "load_state", return_value=fresh_state
        ), mock.patch.object(
            lf, "save_state", side_effect=lambda s: saved.update(s)
        ):
            summary = lf.lambda_handler({}, None)
        return summary, saved, calls

    def test_a_new_finding_is_consolidated_assessed_and_ticketed(self):
        summary, saved, calls = self.run_handler([finding()], [self.assessment()])
        self.assertEqual(summary["new"], 1)
        self.assertEqual(summary["assessed"], 1)
        self.assertEqual(summary["ticketed"], 1)
        self.assertEqual(summary["failed"], 0)
        fp = lf.fingerprint("CVE-2026-12087", "perl")
        self.assertIn(fp, saved["records"])
        rec = saved["records"][fp]
        self.assertEqual(rec["assessment"]["tier"], "P2")
        self.assertEqual(rec["jira_key"], "SEC-1")
        kinds = [c[0] if isinstance(c, tuple) else c for c in calls]
        self.assertIn("create", kinds)
        # The evidence report is persisted so a reviewer sees what the model saw.
        self.assertTrue(rec["usage_report"])

    def test_the_second_run_does_not_re_assess_unchanged_facts(self):
        first_summary, saved, _ = self.run_handler([finding()], [self.assessment()])
        self.assertEqual(first_summary["assessed"], 1)
        second_summary, _, calls = self.run_handler([finding()], [], state=saved)
        self.assertEqual(second_summary["assessed"], 0)
        self.assertEqual(second_summary["unchanged"], 1)
        # Jira was reachable, but nothing needed creating or updating.
        self.assertIn("init", calls)
        kinds = [c[0] if isinstance(c, tuple) else c for c in calls]
        self.assertNotIn("create", kinds)
        self.assertNotIn("update", kinds)

    def test_a_kev_listing_floors_the_tier_and_the_card_records_the_override(self):
        kev = {"CVE-2026-12087": {"dateAdded": "2026-01-01"}}
        summary, saved, _ = self.run_handler(
            [finding()], [self.assessment(tier="P3", score=10)], kev=kev
        )
        fp = lf.fingerprint("CVE-2026-12087", "perl")
        rec = saved["records"][fp]
        self.assertEqual(rec["assessment"]["tier"], "P1")
        self.assertTrue(rec["assessment"]["guard_notes"])
        self.assertIn("SEC-1", summary["p1_created"])

    def test_a_vanished_finding_closes_its_card(self):
        fp = "deadbeef" * 8
        state = {
            "records": {
                fp: {
                    "resources": [],
                    "facts": {},
                    "jira_key": "SEC-9",
                    "jira_status_observed": "open",
                    "resource_count": 2,
                }
            },
            "class_issues": {},
            "coverage_gaps": [],
            "last_review_quarter": None,
        }
        summary, saved, calls = self.run_handler([], [], state=state)
        self.assertEqual(summary["gone"], 1)
        self.assertIn("transition", calls)
        self.assertEqual(saved["records"][fp]["jira_status_observed"], "gone")

    def test_a_missing_kev_catalogue_skips_assessment_rather_than_downgrading(self):
        summary, saved, _ = self.run_handler([finding()], [], kev_missing=True)
        self.assertEqual(summary["assessed"], 0)
        self.assertEqual(summary["failed"], 0)
        self.assertEqual(summary["ticketed"], 0)

    def test_an_accepted_verdict_creates_the_class_issue_and_a_child_card(self):
        summary, saved, calls = self.run_handler(
            [finding(fix="YES")],
            [self.assessment(tier="accepted", reachable="no", cls="unreachable_component", score=3)],
        )
        self.assertEqual(summary["accepted"], 1)
        self.assertIn("unreachable_component", saved["class_issues"])
        # The class Epic is created, and the vulnerability card is created as its
        # child in the same call rather than being re-parented afterwards.
        creates = [c for c in calls if isinstance(c, tuple) and c[0] == "create"]
        self.assertEqual(len(creates), 2)
        self.assertTrue(any(c[1].startswith("Vulnerability exception class") for c in creates))
        self.assertTrue(any(c[2] == "SEC-1" for c in creates))
        fp = lf.fingerprint("CVE-2026-12087", "perl")
        self.assertEqual(saved["records"][fp]["assessment"]["exception_class"], "unreachable_component")


if __name__ == "__main__":
    unittest.main(verbosity=2)

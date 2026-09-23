"""The handler's deployment contract: the template, and the dependency surface.

The other test modules exercise the handler's logic. This one asserts the things
that decide whether the deployed artifact works at all, and that no other test can
see because they set module constants directly rather than going through the
template:

1. A template environment variable the handler never reads: dead config that
   looks wired up.
2. An environment variable the handler reads with no default that the template
   never sets: a silent failure on the first real invocation.
3. A Ref in the template that resolves to nothing: a deploy-time failure
   cfn-lint will not catch, because it is not a syntax error.
4. A third-party import in the handler, which would break the no-Docker build and
   the plain-zip package.

Requires PyYAML. Skips cleanly when absent, so a bare local run still works.
"""

import ast
import json
import pathlib
import re
import sys
import unittest

REPO = pathlib.Path(__file__).resolve().parent.parent
TEMPLATE = REPO / "template.yaml"
HANDLER = REPO / "src" / "handler.py"

sys.path.insert(0, str(REPO / "src"))

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

# AWS injects these into the runtime. A template that sets them fails to deploy.
RESERVED = {"AWS_REGION", "AWS_DEFAULT_REGION", "AWS_LAMBDA_FUNCTION_NAME"}
PSEUDO = {"AWS::Region", "AWS::Partition", "AWS::AccountId", "AWS::StackName", "AWS::NoValue"}


def serverless_function(tmpl):
    return next(v for v in tmpl["Resources"].values() if v["Type"] == "AWS::Serverless::Function")


def env_accesses(source):
    """(keys read, keys read with a default) from os.environ usage in source."""
    keys, defaulted = set(), set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if (
                node.func.attr == "get"
                and isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "environ"
                and node.args
                and isinstance(node.args[0], ast.Constant)
            ):
                keys.add(node.args[0].value)
                if len(node.args) > 1:
                    defaulted.add(node.args[0].value)
        elif (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "environ"
            and isinstance(node.slice, ast.Constant)
        ):
            keys.add(node.slice.value)
    return keys, defaulted


def refs_in(node, found=None):
    found = set() if found is None else found
    if isinstance(node, dict):
        if set(node) == {"Ref"}:
            found.add(node["Ref"])
        for value in node.values():
            refs_in(value, found)
    elif isinstance(node, list):
        for value in node:
            refs_in(value, found)
    return found


@unittest.skipUnless(yaml is not None, "PyYAML is not installed")
class Template(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        mod = yaml
        assert mod is not None  # skipUnless guards this; narrowed for the type checker

        class CfnLoader(mod.SafeLoader):
            """CloudFormation short-form intrinsics (!Ref, !Sub, !If) are not YAML tags."""

        def cfn_tag(loader, tag_suffix, node):
            if isinstance(node, mod.ScalarNode):
                value = loader.construct_scalar(node)
            elif isinstance(node, mod.SequenceNode):
                value = loader.construct_sequence(node, deep=True)
            else:
                value = loader.construct_mapping(node, deep=True)
            return {"Ref": value} if tag_suffix == "Ref" else {f"Fn::{tag_suffix}": value}

        CfnLoader.add_multi_constructor("!", cfn_tag)
        cls.tmpl = mod.load(TEMPLATE.read_text(), Loader=CfnLoader)
        cls.source = HANDLER.read_text()
        cls.vars = set(serverless_function(cls.tmpl)["Properties"]["Environment"]["Variables"])
        cls.reads, cls.defaulted = env_accesses(cls.source)

    def test_template_sets_no_lambda_reserved_variable(self):
        clash = sorted(self.vars & RESERVED)
        self.assertEqual(clash, [], f"Lambda injects these; the template must not set them: {clash}")

    def test_every_template_variable_is_read_by_the_handler(self):
        dead = sorted(self.vars - self.reads)
        self.assertEqual(dead, [], f"wired up in the template but never read: {dead}")

    def test_every_required_handler_variable_is_set_by_the_template(self):
        missing = sorted(self.reads - self.vars - self.defaulted - RESERVED)
        self.assertEqual(missing, [], f"read with no default and never set: {missing}")

    def test_parameters_are_declared_and_grouped(self):
        params = set(self.tmpl["Parameters"])
        groups = self.tmpl["Metadata"]["AWS::CloudFormation::Interface"]["ParameterGroups"]
        grouped = [p for g in groups for p in g["Parameters"]]
        self.assertEqual(set(grouped) - params, set(), "grouped but not declared")
        self.assertEqual(params - set(grouped), set(), "declared but absent from the console interface")
        self.assertEqual(len(grouped), len(set(grouped)), "a parameter is listed twice")

    def test_every_ref_resolves(self):
        known = set(self.tmpl["Parameters"]) | PSEUDO | set(self.tmpl["Resources"])
        unresolved = sorted(r for r in refs_in(self.tmpl) if r not in known)
        self.assertEqual(unresolved, [], f"Refs that resolve to nothing: {unresolved}")

    def test_every_credential_reference_is_scoped_in_iam(self):
        policy = json.dumps(self.tmpl)
        for param in ("JiraApiKeySecret", "InferenceApiKeySecret", "GitHubTokenSecret"):
            with self.subTest(param=param):
                self.assertIn(
                    f"parameter${{{param}}}", policy, f"{param} is not scoped in the SSM read policy"
                )

    def test_state_bucket_is_versioned_private_and_retained(self):
        bucket = next(v for v in self.tmpl["Resources"].values() if v["Type"] == "AWS::S3::Bucket")
        self.assertEqual(bucket.get("DeletionPolicy"), "Retain")
        props = bucket["Properties"]
        self.assertEqual(props["VersioningConfiguration"]["Status"], "Enabled")
        self.assertTrue(all(props["PublicAccessBlockConfiguration"].values()))

    def test_the_function_cannot_run_concurrently(self):
        """State is read-modify-write on one object, so this is load-bearing."""
        self.assertEqual(
            serverless_function(self.tmpl)["Properties"]["ReservedConcurrentExecutions"], 1
        )

    def test_every_default_config_key_is_referenced(self):
        import handler

        unused = sorted(
            k
            for k in handler.DEFAULT_CONFIG
            if f'"{k}"' not in self.source and f"'{k}'" not in self.source
        )
        self.assertEqual(unused, [], f"in DEFAULT_CONFIG but never read: {unused}")

    def test_shipped_config_uses_only_known_keys(self):
        import handler

        for name in ("config.json", "config.example.json"):
            with self.subTest(config=name):
                data = json.loads((REPO / "src" / name).read_text())
                unknown = [
                    k for k in data if k not in handler.DEFAULT_CONFIG and not k.startswith("_")
                ]
                self.assertEqual(unknown, [], f"{name} has keys with no default: {unknown}")

    def test_the_handler_depends_only_on_the_stdlib_and_boto3(self):
        """This is what keeps `sam build` Docker-free and the package a plain zip."""
        imported = set()
        for node in ast.walk(ast.parse(self.source)):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imported.add(node.module.split(".")[0])
        extra = sorted(imported - set(sys.stdlib_module_names) - {"boto3"})
        self.assertEqual(extra, [], f"unexpected third-party imports: {extra}")

    def test_every_exception_class_has_the_heading_class_description_parses(self):
        """class_description lifts a class body out of standard.md by regex."""
        import handler

        standard = (REPO / "src" / "prompts" / "standard.md").read_text()
        for cls in handler.CLASSES:
            with self.subTest(cls=cls):
                self.assertRegex(standard, rf"### 5\.\d `{re.escape(cls)}`")
        self.assertIn("\n## 6", standard, "the regex needs section 6 to terminate the last class")


if __name__ == "__main__":
    unittest.main(verbosity=2)

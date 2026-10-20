"""Behavior checks using real Git histories and Go package graphs."""

import copy
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from ci import check_results, classify, select, test_packages


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        module_cache = tempfile.TemporaryDirectory()
        self.addCleanup(module_cache.cleanup)
        self.repo = Path(self.temp.name)
        # Fixtures have no external dependencies. Keep graph-failure cases
        # deterministic and independent of developer workspace/network settings.
        for key, value in (("GOWORK", "off"), ("GOPROXY", "off"), ("GOSUMDB", "off"),
                           ("GOMODCACHE", module_cache.name)):
            previous = os.environ.get(key)
            if previous is None:
                self.addCleanup(os.environ.pop, key, None)
            else:
                self.addCleanup(os.environ.__setitem__, key, previous)
            os.environ[key] = value
        self.git("init", "-q")
        self.git("config", "user.email", "ci@example.test")
        self.git("config", "user.name", "CI test")
        self.write("go.mod", "module example.test/fixture\n\ngo 1.25.0\n")
        self.write("leaf/leaf.go", "package leaf\nconst Value = 1\n")
        self.write("consumer/consumer.go", 'package consumer\nimport "example.test/fixture/leaf"\nconst Value = leaf.Value\n')
        self.write("integration/integration.go", "package integration\nconst Value = 1\n")
        self.write("integration/integration_test.go", 'package integration_test\nimport "example.test/fixture/leaf"\nvar _ = leaf.Value\n')
        self.write("downstream/downstream.go", 'package downstream\nimport "example.test/fixture/integration"\nconst Value = integration.Value\n')
        self.write("cmd/agentssh/main.go", 'package main\nimport "example.test/fixture/consumer"\nfunc main() { println(consumer.Value) }\n')
        self.write("cmd/agentssh-server/main.go", "package main\nfunc main() {}\n")
        self.write("README.md", "Example\n")
        self.base = self.commit()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.repo, text=True).strip()

    def write(self, path, text):
        file = self.repo / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text)

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")
        return self.git("rev-parse", "HEAD")

    def plan(self):
        return select(self.repo, classify(self.repo, self.base, self.commit()))

    def test_documentation_never_invokes_go(self):
        self.write("docs/a file\nwith newline.md", "Documentation\n")
        self.write("skills/example/SKILL.md", "Instructions\n")
        self.write("bin/go", "#!/bin/sh\necho unexpected >&2\nexit 99\n")
        # The sentinel executable is untracked so it does not affect the diff.
        (self.repo / "bin/go").chmod(0o755)
        self.git("add", "docs", "skills")
        self.git("commit", "-qm", "documentation")
        original = os.environ["PATH"]
        os.environ["PATH"] = str(self.repo / "bin") + os.pathsep + original
        self.addCleanup(os.environ.__setitem__, "PATH", original)
        plan = select(self.repo, classify(self.repo, self.base, "HEAD"))
        self.assertFalse(plan["go"])
        self.assertFalse(plan["tooling"])
        self.assertEqual(plan["cli_packages"] + plan["internal_packages"], [])

    def test_production_change_selects_transitive_and_external_test_consumers(self):
        self.write("leaf/leaf.go", "package leaf\nconst Value = 2\n")
        plan = self.plan()
        self.assertFalse(plan["full"])
        self.assertEqual(plan["cli_packages"], ["./cmd/agentssh"])
        self.assertEqual(plan["internal_packages"], ["./consumer", "./integration", "./leaf"])

    def test_test_only_change_does_not_propagate_to_callers(self):
        self.write("leaf/leaf_test.go", "package leaf\nvar _ = Value\n")
        plan = self.plan()
        self.assertEqual(plan["cli_packages"], [])
        self.assertEqual(plan["internal_packages"], ["./leaf"])

    def test_server_change_skips_client_cli(self):
        self.write("cmd/agentssh-server/main.go", 'package main\nfunc main() { println("server") }\n')
        plan = self.plan()
        self.assertEqual(plan["cli_packages"], [])
        self.assertEqual(plan["internal_packages"], ["./cmd/agentssh-server"])

    def test_push_range_includes_all_commits(self):
        self.write("leaf/leaf.go", "package leaf\nconst Value = 2\n")
        self.commit()
        self.write("README.md", "Docs after code\n")
        self.assertEqual(self.plan()["cli_packages"], ["./cmd/agentssh"])

    def test_pr_merge_range_includes_branch_changes(self):
        self.git("checkout", "-qb", "feature")
        self.write("leaf/leaf.go", "package leaf\nconst Value = 2\n")
        self.commit()
        self.git("checkout", "-qb", "target", self.base)
        self.write("README.md", "Target branch documentation\n")
        target = self.commit()
        self.git("merge", "--no-ff", "-qm", "PR merge", "feature")
        plan = select(self.repo, classify(self.repo, target, "HEAD"))
        self.assertEqual(plan["cli_packages"], ["./cmd/agentssh"])
        self.assertEqual([c["path"] for c in plan["changes"]], ["leaf/leaf.go"])

    def test_dependency_and_ci_inputs_force_full(self):
        for path in ("go.sum", ".github/workflows/ci.yml", ".github/actions/setup-go/action.yml",
                     "scripts/ci/ci.py", ".golangci.yml", "unknown-input.json"):
            with self.subTest(path=path):
                self.write(path, "input\n")
                head = self.commit()
                plan = classify(self.repo, self.base, head)
                self.assertTrue(plan["full"])
                self.assertTrue(plan["go"])

    def test_deletion_and_rename_force_full(self):
        (self.repo / "leaf/leaf.go").unlink()
        self.git("mv", "README.md", "renamed.md")
        plan = classify(self.repo, self.base, self.commit())
        self.assertTrue(plan["full"])
        self.assertTrue(plan["go"])

    def test_invalid_base_forces_full(self):
        for base in ("", "0" * 40, "missing-ref"):
            with self.subTest(base=base):
                plan = classify(self.repo, base, "HEAD")
                self.assertTrue(plan["full"])
                self.assertTrue(plan["tooling"])

    def test_broken_graph_falls_back_to_unsplit_full_suite(self):
        self.write("newroot/broken.go", "package broken\nimport \"missing.invalid/dependency\"\n")
        plan = self.plan()
        self.assertTrue(plan["full"])
        self.assertEqual(plan["cli_packages"], [])
        self.assertEqual(plan["internal_packages"], ["./..."])

    def test_explicit_full_lists_every_package(self):
        plan = select(self.repo, classify(self.repo, "", "HEAD", full=True))
        self.assertTrue(plan["full"])
        self.assertTrue(plan["tooling"])
        self.assertEqual(plan["cli_packages"], ["./cmd/agentssh"])
        self.assertEqual(plan["internal_packages"], ["./cmd/agentssh-server", "./consumer", "./downstream", "./integration", "./leaf"])

    def test_shell_changes_request_syntax_checks(self):
        self.write("scripts/example.sh", "#!/bin/sh\ntrue\n")
        plan = classify(self.repo, self.base, self.commit())
        self.assertTrue(plan["tooling"])
        self.assertFalse(plan["go"])

    def test_audit_demo_change_requests_smoke_build(self):
        self.write("scripts/e2e_tui_audit_run_summary.sh", "#!/bin/sh\ntrue\n")
        plan = self.plan()
        self.assertTrue(plan["smoke"])
        self.assertTrue(plan["go"])
        self.assertFalse(plan["full"])
        self.assertEqual(plan["cli_packages"] + plan["internal_packages"], [])

    def test_runner_preserves_go_failure_and_json_report(self):
        self.write("leaf/leaf_test.go", 'package leaf\nimport "testing"\nfunc TestFailure(t *testing.T) { t.Fatal("expected fixture failure") }\n')
        report = self.repo / "report.jsonl"
        with contextlib.redirect_stdout(io.StringIO()):
            code = test_packages(self.repo, ["./leaf"], True, report)
        self.assertNotEqual(code, 0)
        events = [json.loads(line) for line in report.read_text().splitlines()]
        self.assertTrue(any(e.get("Action") == "fail" and e.get("Test") == "TestFailure" for e in events))


class ResultTests(unittest.TestCase):
    def needs(self):
        return {"changes": {"result": "success", "outputs": {
            "go": "true", "tooling": "false", "cli": "true", "internal": "true"}},
            "quality": {"result": "success"}, "tooling": {"result": "skipped"},
            "test-cli": {"result": "success"}, "test-internal": {"result": "success"}}

    def test_selected_jobs_pass(self):
        check_results(self.needs())

    def test_documentation_can_skip_all_expensive_jobs(self):
        needs = self.needs()
        needs["changes"]["outputs"] = dict.fromkeys(("go", "tooling", "cli", "internal"), "false")
        for job in ("quality", "tooling", "test-cli", "test-internal"):
            needs[job]["result"] = "skipped"
        check_results(needs)

    def test_failure_cancellation_and_unexpected_skips_cannot_pass(self):
        for job in ("changes", "quality", "test-cli", "test-internal"):
            for result in ("failure", "cancelled", "skipped", "timed_out"):
                with self.subTest(job=job, result=result):
                    needs = self.needs()
                    needs[job]["result"] = result
                    with self.assertRaises(ValueError):
                        check_results(needs)

    def test_missing_outputs_and_jobs_cannot_pass(self):
        for field in ("go", "tooling", "cli", "internal"):
            needs = copy.deepcopy(self.needs())
            del needs["changes"]["outputs"][field]
            with self.assertRaises(ValueError):
                check_results(needs)
        needs = self.needs()
        del needs["test-cli"]
        with self.assertRaises(ValueError):
            check_results(needs)

    def test_empty_or_option_package_selection_is_rejected(self):
        for packages in ([], ["-run=none"], ["./../other"]):
            with self.assertRaises(ValueError):
                test_packages(Path.cwd(), packages, False, "unused.jsonl")


if __name__ == "__main__":
    unittest.main()

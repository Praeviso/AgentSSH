#!/usr/bin/env python3
"""Select affected Go packages and enforce the CI result contract (stdlib only)."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def run(repo, *args):
    return subprocess.check_output(args, cwd=repo, text=True)


def classify(repo, base, head, full=False):
    plan = {"go": False, "tooling": False, "smoke": False, "full": full,
            "reasons": [], "changes": []}
    if full:
        plan.update(go=True, tooling=True)
        plan["reasons"].append("Explicit full verification")
        return plan
    try:
        if not base or set(base) == {"0"}:
            raise ValueError("No usable base commit")
        # Disable rename detection: a rename is a deletion plus an addition,
        # and therefore takes the conservative full-suite path below.
        fields = run(repo, "git", "diff", "--name-status", "-z", "--no-renames",
                     base, head, "--").split("\0")
        if fields[-1] != "" or len(fields) % 2 != 1:
            raise ValueError("Malformed git diff")
        for status, path in zip(fields[0:-1:2], fields[1:-1:2]):
            plan["changes"].append({"status": status, "path": path})
            if status not in ("A", "M"):
                plan["full"] = True
                plan["reasons"].append("Deleted, renamed or unusual file: " + path)
            if path.startswith((".github/", "scripts/ci/")):
                plan.update(full=True, tooling=True)
                plan["reasons"].append("CI implementation: " + path)
            elif path in ("go.mod", "go.sum", "go.work", "go.work.sum") or Path(path).name.startswith(".golangci"):
                plan["full"] = True
                plan["reasons"].append("Dependencies or analysis configuration: " + path)
            elif path.endswith(".go"):
                plan["go"] = True
            elif path == "scripts/e2e_tui_audit_run_summary.sh":
                plan.update(go=True, tooling=True, smoke=True)
            elif path.startswith("scripts/") and path.endswith(".sh"):
                plan["tooling"] = True
            elif path in ("README.md", "LICENSE") or path.startswith("docs/") or (
                    path.startswith("skills/") and path.endswith(".md")):
                pass
            else:
                plan["full"] = True
                plan["reasons"].append("Unclassified input: " + path)
    except (subprocess.CalledProcessError, OSError, ValueError) as error:
        plan.update(full=True, tooling=True)
        plan["reasons"].append("Diff analysis unavailable: " + str(error))
    plan["go"] |= plan["full"]
    return plan


def json_stream(raw):
    decoder = json.JSONDecoder()
    while raw.strip():
        value, end = decoder.raw_decode(raw.lstrip())
        yield value
        raw = raw.lstrip()[end:]


def select(repo, plan):
    packages = []
    if plan["go"]:
        try:
            graph = list(json_stream(run(repo, "go", "list", "-race", "-json", "./...")))
            if not graph or any(p.get("Error") or p.get("DepsErrors") for p in graph):
                raise ValueError("Incomplete package graph")
            local = {p["ImportPath"]: p for p in graph}
            by_dir = {Path(p["Dir"]).resolve(): p["ImportPath"] for p in graph}
            affected = set()
            production = set()
            for change in plan["changes"]:
                path = change["path"]
                if not path.endswith(".go"):
                    continue
                package = by_dir.get((Path(repo) / path).resolve().parent)
                if package is None:
                    raise ValueError("Changed Go file absent from graph: " + path)
                affected.add(package)
                if not path.endswith("_test.go"):
                    production.add(package)
            # Only production changes propagate. A package's own tests are not
            # imported by its callers. Test imports still select integration
            # test consumers of changed production packages.
            changed = set(production)
            while changed:
                next_changed = set()
                for name, package in local.items():
                    imports = set(package.get("Imports", []))
                    test_imports = set(package.get("TestImports", []) + package.get("XTestImports", []))
                    if imports & changed:
                        affected.add(name)
                        if name not in production:
                            production.add(name)
                            next_changed.add(name)
                    if test_imports & changed:
                        affected.add(name)
                changed = next_changed
            if plan["full"]:
                affected = set(local)
            packages = sorted("./" + Path(local[name]["Dir"]).resolve().relative_to(Path(repo).resolve()).as_posix()
                              for name in affected)
        except (subprocess.CalledProcessError, OSError, ValueError, KeyError) as error:
            # A broken graph must never produce an empty green selection. The
            # runner will execute ./... and expose any build/module failure.
            plan["full"] = True
            plan["reasons"].append("Package analysis unavailable; running all packages: " + str(error))
            packages = ["./..."]
    if packages == ["./..."]:
        # One unsplit invocation also covers newly added package roots.
        plan["cli_packages"] = []
        plan["internal_packages"] = ["./..."]
    else:
        plan["cli_packages"] = [p for p in packages if p == "./cmd/agentssh"]
        plan["internal_packages"] = [p for p in packages if p != "./cmd/agentssh"]
    return plan


def emit(plan):
    values = {k: str(plan[k]).lower() for k in ("go", "tooling", "smoke", "full")}
    for group in ("cli", "internal"):
        values[group] = str(bool(plan.get(group + "_packages"))).lower()
        values[group + "_packages"] = json.dumps(plan.get(group + "_packages", []))
    if os.getenv("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            for key, value in values.items():
                output.write(f"{key}={value}\n")
    print(json.dumps(plan, indent=2))


def check_results(needs):
    changes = needs.get("changes", {})
    if changes.get("result") != "success":
        raise ValueError("Change analysis did not succeed")
    outputs = changes.get("outputs", {})
    for job, flag in (("quality", "go"), ("tooling", "tooling"),
                      ("test-cli", "cli"), ("test-internal", "internal")):
        required = outputs.get(flag)
        if required not in ("true", "false"):
            raise ValueError("Missing or invalid selection output: " + flag)
        expected = "success" if required == "true" else "skipped"
        actual = needs.get(job, {}).get("result")
        if actual != expected:
            raise ValueError(f"{job}: expected {expected}, got {actual}")


def test_packages(repo, packages, full, report):
    if not packages or any(not p.startswith("./") or ".." in p.split("/") for p in packages):
        raise ValueError("Invalid or empty package selection")
    command = ["go", "test", "-race", "-json", "-timeout=20m"]
    if full:
        command.append("-count=1")
    command.extend(packages)
    print("Running: " + " ".join(command), flush=True)
    timings = []
    with open(report, "w") as output:
        with subprocess.Popen(command, cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True) as process:
            for line in process.stdout:
                output.write(line)
                print(line, end="", flush=True)
                try:
                    event = json.loads(line)
                    if event.get("Action") in ("pass", "fail") and "Elapsed" in event:
                        timings.append(event)
                except (ValueError, AttributeError):
                    pass
            code = process.wait()
    if os.getenv("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
            summary.write("### Race test timings\n\n| Package / test | Seconds |\n| --- | ---: |\n")
            for event in sorted(timings, key=lambda e: e["Elapsed"], reverse=True)[:15]:
                name = event["Package"] + (" / " + event["Test"] if "Test" in event else "")
                summary.write(f"| {name} | {event['Elapsed']:.3f} |\n")
    return code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("classify", "select", "check", "test"))
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--base", default="")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--packages")
    parser.add_argument("--report", default="test-results.jsonl")
    args = parser.parse_args()
    if args.command == "classify":
        plan = classify(args.repo, args.base, args.head, args.full)
    elif args.command == "select":
        plan = select(args.repo, json.loads(args.plan.read_text()))
    elif args.command == "check":
        check_results(json.loads(os.environ["CI_NEEDS"]))
        print("All selected CI jobs succeeded; unselected jobs were skipped.")
        return 0
    else:
        return test_packages(args.repo, json.loads(args.packages), args.full, args.report)
    args.plan.write_text(json.dumps(plan, indent=2) + "\n")
    emit(plan)
    return 0


if __name__ == "__main__":
    sys.exit(main())

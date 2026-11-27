"""Compare a conformance run with conformance/baseline.json, and keep what the suite exported.

Reads every plan the suite ran (its API, as the suite's own scripts read it: `api/plan`, `api/info/{id}`),
takes each module's latest outcome (PASSED, WARNING, REVIEW, SKIPPED, FAILED; a module with no result is
its status, such as INTERRUPTED), and compares them with the baseline, module by module, in both
directions: a worse outcome is a regression, a better one means the baseline is stale, and a module
appearing or disappearing is a change too. Any difference exits 1.

It writes, under --out: `results.json` (every outcome, the baseline's form), `report.md` (the differences,
for the issue a scheduled run opens) and each plan's HTML export. The outcomes are printed as well, so a
run's log is enough to write a new baseline (or pass --write-baseline).

Standard library only.
"""

import argparse
import json
import ssl
import sys
import urllib.parse
import urllib.request
from pathlib import Path

# Better first: a change towards the start is an improvement, towards the end a regression.
ORDER = ["PASSED", "REVIEW", "WARNING", "SKIPPED", "FAILED"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--suite", required=True, help="The suite's base URL")
    parser.add_argument("--ca", help="A CA bundle to trust for the suite's certificate")
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--write-baseline", action="store_true", help="Record this run as the baseline")
    args = parser.parse_args()

    context = ssl.create_default_context(cafile=args.ca)
    suite = args.suite.rstrip("/")
    args.out.mkdir(parents=True, exist_ok=True)

    results: dict[str, str] = {}
    for plan in fetch(context, f"{suite}/api/plan?" + urllib.parse.urlencode({"length": 100, "start": 0}))["data"]:
        name = plan["planName"] + variant(plan.get("variant"))
        for module in plan.get("modules", []):
            instances = module.get("instances") or []
            key = f"{name} / {module['testModule']}{variant(module.get('variant'))}"
            if not instances:
                results[key] = "NOT_RUN"
                continue
            info = fetch(context, f"{suite}/api/info/{instances[-1]}")
            # The suite stops a module at its first failure: INTERRUPTED, its result FAILED. The result is the
            # outcome; the status only when there is none (a module that broke before deciding anything).
            results[key] = str(info.get("result") or info.get("status") or "UNKNOWN")
        export = download(context, f"{suite}/api/plan/exporthtml/{plan['_id']}")
        (args.out / f"{plan['planName']}-{plan['_id']}.zip").write_bytes(export)

    results = dict(sorted(results.items()))
    (args.out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("Outcomes of this run:")
    print(json.dumps(results, indent=2))

    if args.write_baseline:
        args.baseline.write_text(json.dumps(results, indent=2) + "\n")
        print(f"Recorded as {args.baseline}.")
        return 0

    baseline = json.loads(args.baseline.read_text()) if args.baseline.exists() else {}
    differences = []
    for key in sorted(set(baseline) | set(results)):
        expected, actual = baseline.get(key), results.get(key)
        if expected != actual:
            differences.append((key, expected, actual, direction(expected, actual)))

    report = render(differences, results)
    (args.out / "report.md").write_text(report)
    print(report)

    return 1 if differences else 0


def variant(value) -> str:
    """A plan's or a module's variant, as the suite names one: [key=value][...], keys sorted."""
    if not value:
        return ""
    return "".join(f"[{key}={value[key]}]" for key in sorted(value))


def direction(expected, actual) -> str:
    if expected is None:
        return "new module"
    if actual is None:
        return "module gone"
    rank = lambda outcome: ORDER.index(outcome) if outcome in ORDER else len(ORDER)
    return "regression" if rank(actual) > rank(expected) else "now better: the baseline is stale"


def render(differences, results) -> str:
    if not differences:
        return f"Every one of the {len(results)} modules has its baseline outcome.\n"
    lines = [
        f"{len(differences)} of {len(results)} modules differ from `conformance/baseline.json`:",
        "",
        "| Module | Baseline | This run | |",
        "|---|---|---|---|",
    ]
    for key, expected, actual, why in differences:
        lines.append(f"| `{key}` | {expected or '—'} | {actual or '—'} | {why} |")
    lines += [
        "",
        "A regression is a bug or a change to explain. A module that now does better means the baseline",
        "is stale: update it (`compare.py --write-baseline`, or by hand) in the change that improved it.",
        "",
    ]
    return "\n".join(lines)


def fetch(context, url: str) -> dict:
    with urllib.request.urlopen(urllib.request.Request(url, headers={"Accept": "application/json"}),
                                context=context, timeout=60) as response:
        return json.load(response)


def download(context, url: str) -> bytes:
    with urllib.request.urlopen(url, context=context, timeout=120) as response:
        return response.read()


if __name__ == "__main__":
    sys.exit(main())

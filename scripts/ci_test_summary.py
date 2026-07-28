"""Render a pytest JUnit XML report as a GitHub Actions job summary.

Turns the raw dot-wall into something readable at a glance on the Actions page:
a pass/fail headline, counts, and — when something breaks — a table naming every
failing test with its error, so a reviewer never has to open the log to find out
what went wrong.

Usage: python scripts/ci_test_summary.py pytest-report.xml >> "$GITHUB_STEP_SUMMARY"

Stdlib only, and deliberately forgiving: a malformed or missing report must not
be the reason a build fails, so anything unexpected degrades to a short note and
exit 0. The pytest step itself owns the pass/fail verdict.
"""

import sys
import xml.etree.ElementTree as ET

MAX_ROWS = 40  # cap the table; the log has the rest
MAX_MSG = 160  # keep one failure to one readable line


def _node_id(case) -> str:
    """Rebuild a pytest node id from JUnit's dotted classname.

    JUnit stores "tests.test_payouts" for a module-level test and
    "tests.test_payouts.TestWindow" when the test lives in a class, so the
    module boundary is the last lowercase-initial part. Getting this right is
    the difference between a copy-pasteable repro command and a broken one.
    """
    name = case.get("name", "?")
    classname = case.get("classname", "")
    if not classname:
        return name

    parts = classname.split(".")
    # Trailing PascalCase parts are class names, not directories.
    cls = []
    while len(parts) > 1 and parts[-1][:1].isupper():
        cls.insert(0, parts.pop())

    return "::".join(["/".join(parts) + ".py", *cls, name])


def _cell(text: str) -> str:
    """Collapse a multi-line pytest message into one safe markdown table cell."""
    one_line = " ".join((text or "").split())
    if len(one_line) > MAX_MSG:
        one_line = one_line[: MAX_MSG - 1] + "…"
    return one_line.replace("|", "\\|")


def main() -> int:
    # The runner is UTF-8 but a Windows console defaults to cp1252 and dies on
    # the tick/cross. Force UTF-8 so this is runnable locally too.
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):  # pragma: no cover — non-reconfigurable stream
        pass

    if len(sys.argv) < 2:
        print("_No test report path given._")
        return 0

    try:
        root = ET.parse(sys.argv[1]).getroot()
    except (OSError, ET.ParseError) as exc:
        print(f"_Could not read the test report ({exc.__class__.__name__})._")
        return 0

    suites = root.iter("testsuite") if root.tag == "testsuites" else [root]

    total = failed = errored = skipped = 0
    duration = 0.0
    broken = []  # (test id, kind, message)

    for suite in suites:
        total += int(suite.get("tests", 0))
        failed += int(suite.get("failures", 0))
        errored += int(suite.get("errors", 0))
        skipped += int(suite.get("skipped", 0))
        duration += float(suite.get("time", 0) or 0)

        for case in suite.iter("testcase"):
            for kind in ("failure", "error"):
                node = case.find(kind)
                if node is None:
                    continue
                broken.append((
                    _node_id(case),
                    kind,
                    node.get("message") or (node.text or ""),
                ))

    passed = total - failed - errored - skipped

    if failed or errored:
        print(f"## ❌ {failed + errored} of {total} tests failed\n")
    else:
        print(f"## ✅ All {total} tests passed\n")

    print("| Passed | Failed | Errors | Skipped | Time |")
    print("|---:|---:|---:|---:|---:|")
    print(f"| {passed} | {failed} | {errored} | {skipped} | {duration:.0f}s |")

    if broken:
        print("\n### What failed\n")
        print("| Test | Why |")
        print("|---|---|")
        for test_id, kind, message in broken[:MAX_ROWS]:
            label = _cell(message) or kind
            print(f"| `{test_id}` | {label} |")
        if len(broken) > MAX_ROWS:
            print(f"\n_…and {len(broken) - MAX_ROWS} more — see the full log above._")
        print("\nReproduce locally:\n")
        print("```bash")
        print(f"python -m pytest {broken[0][0]} -vv")
        print("```")

    return 0


if __name__ == "__main__":
    sys.exit(main())

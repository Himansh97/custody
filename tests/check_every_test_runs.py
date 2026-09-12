#!/usr/bin/env python3
"""Fail when a test file defines tests that running it does not execute.

CI runs each test file as a script, and each file ends with a block that walks
globals() for test_ functions. Nothing enforces that the block exists, or that
it reaches every function, so two silent failures were possible and both had
happened:

  - a file with no __main__ block at all ran nothing and exited 0. Eighteen
    tests across three files had never executed in CI, including the ones
    asserting a gateway caller cannot write someone else's name onto a record.

  - a function defined *below* the block was never seen, because the runner
    raises SystemExit before the definition is reached. pytest imports the
    module and finds it, so it looks green on a laptop.

Both produce a passing run that tested less than it claimed, which for a
project about evidence is the wrong way round. This compares what each file
defines against what running it actually reports.

Deliberately not using pytest: CI does not install it, and a guard that needs a
tool the thing it guards does not have is a guard that stops running too.
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"

DEFINED = re.compile(r"^def (test_\w+)", re.M)
REPORTED = re.compile(r"^(?:PASS|FAIL)\s+(?:\[[^\]]*\]\s+)?(test_\w+)", re.M)
# A file may declare RUNS_ELSEWHERE for tests it runs under another label, so a
# deliberate arrangement reads differently from a test that quietly never runs.
DECLARED_ELSEWHERE = re.compile(r"^RUNS_ELSEWHERE\s*=\s*\{([^}]*)\}", re.M)


def main() -> int:
    problems: list[str] = []

    for path in sorted(TESTS.glob("test_*.py")):
        source = path.read_text()
        defined = set(DEFINED.findall(source))
        elsewhere = set(re.findall(r'"(test_\w+)"', "".join(DECLARED_ELSEWHERE.findall(source))))
        defined -= elsewhere
        if not defined:
            continue

        run = subprocess.run([sys.executable, str(path)],
                             capture_output=True, text=True, cwd=ROOT)
        reported = set(REPORTED.findall(run.stdout))

        if not reported:
            problems.append(
                f"{path.name}: defines {len(defined)} tests and reported none. "
                "It is missing the __main__ block, so CI runs it and executes nothing."
            )
            continue

        missed = sorted(defined - reported)
        if missed:
            problems.append(
                f"{path.name}: defines {len(defined)} tests but did not run "
                f"{len(missed)}: {', '.join(missed)}. A function below the "
                "__main__ block is never reached."
            )

    if problems:
        print("Tests that exist but do not run:\n")
        for p in problems:
            print(f"  {p}")
        print(f"\n{len(problems)} file(s) with unrun tests")
        return 1

    print(f"every test_ function in {len(list(TESTS.glob('test_*.py')))} files runs when "
          "the file is executed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

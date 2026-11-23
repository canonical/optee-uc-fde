#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright 2026, Canonical Ltd.
"""Summarise the log of "make unit-test" for GitHub Actions.

Writes a Markdown summary of each test binary's results to the job summary
in $GITHUB_STEP_SUMMARY, or to stdout outside of GitHub Actions. On GitHub
Actions, it also annotates every failure and sanitizer error.

Usage: unit-test-report.py LOG
"""

import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# "  RUN     host/test_x" from the Makefile, then cmocka's output
BINARY = re.compile(r"^  RUN     (\S+)$")
RUNNING = re.compile(r"^\[=+\] .*: Running (\d+) test\(s\)\.$")
DONE = re.compile(r"^\[=+\] .*: \d+ test\(s\) run\.$")
RESULT = re.compile(r"^\[ *(RUN|OK|FAILED|SKIPPED) *\] (\w+)$")
ERROR = re.compile(r"^\[ *ERROR *\] --- (.*)$")
LINE = re.compile(r"^\[ *LINE *\] --- (.*)$")
SANITIZER = re.compile(r"runtime error: .*|(?<=ERROR: )\w+Sanitizer: .*")
LOCATION = re.compile(r"(\S+\.[ch]):(\d+):")


class Binary:
    def __init__(self, name):
        self.name = name
        self.total = 0
        self.done = False
        self.test = None
        self.message = None
        self.location = None
        self.passed = 0
        self.skipped = 0
        # (test, message, location) of each failure or sanitizer error
        self.failures = []

    def fail(self, test, message, location):
        self.failures.append((test, message or "failed", location))


def source_location(text):
    """Find the first file:line in text, as a path in the repository."""
    match = LOCATION.search(text or "")
    if not match:
        return None
    path, line = match.groups()
    if os.path.isabs(path):
        candidates = [path]
    else:
        candidates = [
            os.path.join(ROOT, d, path) for d in ("tests/unit", "tests/mocks", "")
        ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return os.path.relpath(candidate, ROOT), int(line)
    return None


def parse(lines):
    binaries = []
    cur = None
    for line in lines:
        line = line.rstrip("\n")
        match = BINARY.match(line)
        if match:
            cur = Binary(match.group(1))
            binaries.append(cur)
            continue
        if cur is None:
            continue

        # Sanitizer errors, during a test or when the binary exits
        match = SANITIZER.search(line)
        if match:
            cur.fail(cur.test, match.group(0), source_location(line))
            continue
        if cur.done:
            continue

        match = RUNNING.match(line)
        if match:
            cur.total = int(match.group(1))
        elif DONE.match(line):
            cur.done = True
        elif ERROR.match(line):
            cur.message = ERROR.match(line).group(1)
        elif LINE.match(line):
            cur.location = source_location(LINE.match(line).group(1))
        elif RESULT.match(line):
            result, test = RESULT.match(line).groups()
            if result == "RUN":
                cur.test, cur.message, cur.location = test, None, None
                continue
            if result == "OK":
                cur.passed += 1
            elif result == "SKIPPED":
                cur.skipped += 1
            else:
                cur.fail(test, cur.message, cur.location)
            cur.test = None
    return binaries


def escape(text, prop=False):
    text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if prop:
        text = text.replace(":", "%3A").replace(",", "%2C")
    return text


def annotate(binary, test, message, location):
    title = f"{binary.name}: {test}" if test else binary.name
    props = f"title={escape(title, True)}"
    if location:
        props = f"file={escape(location[0], True)},line={location[1]},{props}"
    print(f"::error {props}::{escape(message)}")


def summary(binaries):
    out = ["## Unit tests", ""]
    if not binaries:
        out.append("No unit tests ran, see the log of the test step.")
        return "\n".join(out) + "\n"

    out.append("| Test binary | Result | Passed | Failed | Skipped | Not run |")
    out.append("|---|---|---|---|---|---|")
    for b in binaries:
        failed = len({test for test, _, _ in b.failures if test})
        not_run = max(b.total - b.passed - b.skipped - failed, 0)
        if not b.done:
            result = "crashed"
        elif b.failures:
            result = "failed"
        else:
            result = "passed"
        out.append(
            f"| `{b.name}` | {result} | {b.passed} | {failed} | "
            f"{b.skipped} | {not_run} |"
        )

    failures = [(b, *f) for b in binaries for f in b.failures]
    if failures:
        out += ["", "### Failures", ""]
        for b, test, message, location in failures:
            where = f" (`{location[0]}:{location[1]}`)" if location else ""
            name = f"`{b.name}`: `{test}`" if test else f"`{b.name}`"
            out.append(f"- {name}: {message}{where}")
    return "\n".join(out) + "\n"


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__.strip().splitlines()[-1])
    with open(sys.argv[1], encoding="utf-8", errors="replace") as log:
        binaries = parse(log)

    if os.environ.get("GITHUB_ACTIONS") == "true":
        for b in binaries:
            for failure in b.failures:
                annotate(b, *failure)

    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(summary(binaries))
    else:
        sys.stdout.write(summary(binaries))


if __name__ == "__main__":
    main()

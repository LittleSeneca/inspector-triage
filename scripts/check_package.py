#!/usr/bin/env python3
"""Assert the packaged Lambda artifact ships what the handler needs at runtime.

`CodeUri: src/` decides what actually goes in the zip, and the handler reads its two
prompt files off disk at cold start. A missing or misplaced prompt file is a runtime
failure no unit test can see, because those run from src/ where the files are guaranteed
to be present. This checks the artifact instead.

Builds nothing: run `make build` (or `make package-check`) first.

Exit 0 = the artifact is good.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
BUILT = REPO / ".aws-sam" / "build" / "TriageFunction"

# Never let a check write bytecode into the tree it is measuring.
CLEAN_ENV = {**os.environ, "PYTHONPATH": "", "PYTHONDONTWRITEBYTECODE": "1"}

REQUIRED = {"handler.py", "config.json", "prompts/environment.md", "prompts/standard.md"}

failures: list[str] = []
checks = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global checks
    checks += 1
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"  {detail}" if detail else ""))
    if not ok:
        failures.append(label)


def main() -> int:
    if not BUILT.is_dir():
        print(f"no artifact at {BUILT}\nrun: make build", file=sys.stderr)
        return 1

    shipped = {p.relative_to(BUILT).as_posix() for p in BUILT.rglob("*") if p.is_file()}

    for name in sorted(REQUIRED):
        check(f"{name} ships", name in shipped)
    check(
        "no __pycache__ or .pyc ships",
        not any("__pycache__" in s or s.endswith(".pyc") for s in shipped),
        str(sorted(s for s in shipped if ".pyc" in s)),
    )

    # The real test: import it and read the prompts the way a cold start does.
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import handler; print(handler.load_prompt_files()[1]); "
            "print(len(handler.CONFIG['environments']))",
        ],
        cwd=BUILT,
        capture_output=True,
        text=True,
        timeout=120,
        env=CLEAN_ENV,
    )
    if proc.returncode == 0:
        sha, env_count = proc.stdout.split()
        check("handler imports from the packaged layout", True, f"prompt hash {sha}")
        check("config.json parses and yields environments", int(env_count) > 0, f"{env_count} environments")
    else:
        check(
            "handler imports from the packaged layout",
            False,
            (proc.stderr.strip().splitlines() or [""])[-1],
        )

    if failures:
        print(f"\npackage-check FAILED: {len(failures)} of {checks}")
        return 1
    print(f"\npackage-check passed: {checks}/{checks}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

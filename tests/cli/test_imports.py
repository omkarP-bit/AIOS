"""Architecture tests: the CLI is a thin HTTP client, nothing more.

If these fail, the CLI has grown a second security boundary. That is the whole
thing the design forbids, so treat a failure here as a design regression, not
a test to update.
"""

from __future__ import annotations

import ast
from pathlib import Path

CLI_DIR = Path(__file__).resolve().parents[2] / "aios" / "cli"

FORBIDDEN_MODULES = {
    "subprocess",
    "os_gateway",
    "aios.os_gateway",
    "aios.gateway",
    "shutil",
}

FORBIDDEN_CALLS = {
    "os.system",
    "os.popen",
    "os.execv",
    "os.execvp",
    "os.spawnv",
    "os.fork",
    "pty.spawn",
}


def python_files() -> list[Path]:
    return sorted(CLI_DIR.rglob("*.py"))


def test_cli_has_sources() -> None:
    assert python_files(), "no CLI modules found"


def test_no_process_or_gateway_imports() -> None:
    problems: list[str] = []
    for path in python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                root = name.split(".")[0]
                if name in FORBIDDEN_MODULES or root in FORBIDDEN_MODULES:
                    problems.append(f"{path.relative_to(CLI_DIR)}: imports {name}")
    assert not problems, "\n".join(problems)


def test_no_shell_execution_calls() -> None:
    problems: list[str] = []
    for path in python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            dotted = _dotted(func)
            if dotted in FORBIDDEN_CALLS:
                problems.append(f"{path.relative_to(CLI_DIR)}: calls {dotted}()")
            if dotted in {"subprocess.run", "subprocess.Popen", "subprocess.call"}:
                problems.append(f"{path.relative_to(CLI_DIR)}: calls {dotted}()")
            for keyword in node.keywords:
                if keyword.arg == "shell" and _is_true(keyword.value):
                    problems.append(f"{path.relative_to(CLI_DIR)}: shell=True")
    assert not problems, "\n".join(problems)


def test_no_procfs_reads_in_cli() -> None:
    problems: list[str] = []
    for path in python_files():
        text = path.read_text(encoding="utf-8")
        for literal in ("/proc/", "/sys/fs/cgroup"):
            if literal in text:
                problems.append(f"{path.relative_to(CLI_DIR)}: contains {literal!r}")
    assert not problems, "\n".join(problems)


def _dotted(node: ast.expr) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _is_true(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value is True

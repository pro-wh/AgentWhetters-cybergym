"""Score and rank source files by relevance to the vulnerability.

Uses grep and optional semgrep to score files against VulnSignal,
replacing blind extraction of all source files.
"""

from __future__ import annotations

import logging
import os
import subprocess
from typing import List, Optional, Tuple

from hypothesis_parser import VulnSignal

logger = logging.getLogger(__name__)

_SUBPROCESS_TIMEOUT = 30

# Skip directories that are unlikely to contain vulnerable code
SKIP_DIRS = {"test", "tests", "doc", "docs", "example", "examples",
             "build", ".git", "node_modules", "__pycache__", "third_party"}

# Sink patterns by vulnerability class
SINK_PATTERNS: dict[str, list[str]] = {
    "heap-buffer-overflow": [
        r"memcpy|memmove|memset|strcpy|strncpy",
        r"sprintf|snprintf|malloc|realloc",
        r"fread|fgets|read\b",
    ],
    "stack-buffer-overflow": [
        r"char\s+\w+\[",
        r"strcpy|sprintf|gets\b",
        r"alloca\b",
    ],
    "buffer-overflow": [
        r"memcpy|memmove|strcpy|strncpy",
        r"sprintf|snprintf",
    ],
    "use-after-free": [
        r"free\(",
        r"delete\b",
        r"realloc\(",
    ],
    "double-free": [
        r"free\(",
        r"delete\b",
    ],
    "null-pointer-dereference": [
        r"malloc|calloc|strdup",
        r"->",
    ],
    "integer-overflow": [
        r"\*\s*sizeof",
        r"width\s*\*\s*height",
        r"atoi|strtol|strtoul",
    ],
    "divide-by-zero": [
        r"/\s*[a-zA-Z_]",
        r"%\s*[a-zA-Z_]",
    ],
    "assertion-failure": [
        r"assert\b",
        r"abort\b",
    ],
    "out-of-bounds-read": [
        r"memcpy|memmove|memset",
        r"fread|fgets|read\b",
    ],
    "out-of-bounds-write": [
        r"memcpy|memmove|memset",
        r"strcpy|sprintf",
    ],
    "out-of-bounds": [
        r"memcpy|memmove",
        r"\[.*\]",
    ],
    "uninitialized-memory": [
        r"malloc\b",
        r"alloca\b",
    ],
}

# Source file extensions to consider
_SOURCE_EXTENSIONS = {
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx",
    ".py", ".java", ".go", ".rs",
}


def _should_skip(filepath: str) -> bool:
    """Check if a file path should be skipped (test/doc/build dirs)."""
    parts = filepath.lower().split(os.sep)
    return any(part in SKIP_DIRS for part in parts)


def _is_source_file(filepath: str) -> bool:
    """Check if a file is a source file we care about."""
    _, ext = os.path.splitext(filepath)
    basename = os.path.basename(filepath)
    return ext.lower() in _SOURCE_EXTENSIONS or basename in ("Makefile", "CMakeLists.txt")


def _grep_count(repo_path: str, pattern: str, filepath: str) -> int:
    """Count grep matches for a pattern in a file."""
    try:
        result = subprocess.run(
            ["grep", "-c", "-E", pattern, filepath],
            capture_output=True, text=True,
            timeout=_SUBPROCESS_TIMEOUT, cwd=repo_path,
        )
        if result.returncode == 0:
            return int(result.stdout.strip())
    except (subprocess.TimeoutExpired, ValueError, OSError):
        pass
    return 0


def _grep_recursive(repo_path: str, pattern: str) -> list[str]:
    """Run recursive grep and return matching file paths."""
    try:
        result = subprocess.run(
            ["grep", "-rl", "-E", pattern, "--include=*.c",
             "--include=*.cc", "--include=*.cpp", "--include=*.h",
             "--include=*.hpp", "."],
            capture_output=True, text=True,
            timeout=_SUBPROCESS_TIMEOUT, cwd=repo_path,
        )
        if result.returncode == 0:
            return [
                os.path.join(repo_path, line.strip().lstrip("./"))
                for line in result.stdout.strip().split("\n")
                if line.strip()
            ]
    except (subprocess.TimeoutExpired, OSError):
        pass
    return []


class CodebaseTriage:
    """Score and rank source files by relevance to a vulnerability."""

    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self._file_cache: list[str] = []

    def _list_source_files(self) -> list[str]:
        """List all source files in the repo, excluding skip dirs."""
        if self._file_cache:
            return self._file_cache

        files = []
        for root, dirs, filenames in os.walk(self.repo_path):
            # Prune skip directories
            dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
            for fname in filenames:
                full_path = os.path.join(root, fname)
                if _is_source_file(full_path) and not _should_skip(full_path):
                    files.append(full_path)

        self._file_cache = files
        return files

    def score_and_rank(
        self, signal: VulnSignal, max_results: int = 5
    ) -> List[Tuple[str, float]]:
        """Score and rank source files by relevance to the vulnerability.

        Returns list of (filepath, score) tuples, sorted by score descending.
        """
        files = self._list_source_files()
        scores: list[Tuple[str, float]] = []

        for filepath in files:
            score = 0.0
            rel_path = os.path.relpath(filepath, self.repo_path)

            # Function name match in filename or path
            if signal.vulnerable_function != "unknown":
                if signal.vulnerable_function.lower() in rel_path.lower():
                    score += 10.0

                # Grep for function name in file
                count = _grep_count(
                    self.repo_path, signal.vulnerable_function, filepath
                )
                if count > 0:
                    score += 10.0

            # File hint match
            if signal.file_hint:
                hint_normalized = signal.file_hint.lower()
                if hint_normalized in rel_path.lower():
                    score += 8.0
                elif os.path.basename(signal.file_hint).lower() in rel_path.lower():
                    score += 5.0

            # Stack trace function matches (top 5 only)
            for i, func in enumerate(signal.stack_trace[:5]):
                count = _grep_count(self.repo_path, func, filepath)
                if count > 0:
                    score += max(5.0 - i, 1.0)

            # Sink pattern grep matches
            vuln_patterns = SINK_PATTERNS.get(signal.vuln_class, [])
            for pattern in vuln_patterns:
                count = _grep_count(self.repo_path, pattern, filepath)
                if count > 0:
                    score += min(count, 4)

            # Bonus for C/C++ source (not headers) in relevant-looking paths
            _, ext = os.path.splitext(filepath)
            if ext in (".c", ".cc", ".cpp", ".cxx"):
                score += 1.0

            if score > 0:
                scores.append((filepath, score))

        # Sort by score descending
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:max_results]

    def get_code_snippet(
        self,
        filepath: str,
        function_name: str = "unknown",
        context_lines: int = 50,
    ) -> Optional[str]:
        """Extract a code snippet around the vulnerable function.

        Returns up to context_lines*2 lines centered on the function,
        or the first context_lines*2 lines if the function is not found.
        """
        try:
            with open(filepath, "r", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            return None

        if not lines:
            return None

        # If the file is small enough, return it all
        if len(lines) <= context_lines * 2:
            return "".join(lines)

        # Try to find the function
        target_line = -1
        if function_name != "unknown":
            func_lower = function_name.lower()
            for i, line in enumerate(lines):
                if func_lower in line.lower():
                    target_line = i
                    break

        if target_line >= 0:
            start = max(0, target_line - context_lines)
            end = min(len(lines), target_line + context_lines)
        else:
            # Function not found — return first chunk
            start = 0
            end = min(len(lines), context_lines * 2)

        snippet_lines = lines[start:end]
        header = f"[Lines {start + 1}-{end} of {len(lines)}]\n"
        return header + "".join(snippet_lines)

    def try_semgrep(self, signal: VulnSignal) -> list[dict]:
        """Run semgrep if available and return findings. Graceful fallback."""
        try:
            # Check if semgrep is available
            check = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True, timeout=5,
            )
            if check.returncode != 0:
                return []
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return []

        # Build a simple rule based on vuln class
        rule_patterns = {
            "heap-buffer-overflow": "pattern: memcpy($DST, $SRC, $SIZE)",
            "use-after-free": "pattern: free($PTR); ... $PTR->$FIELD",
            "null-pointer-dereference": "pattern: $PTR = malloc(...); ... $PTR->$FIELD",
        }

        rule = rule_patterns.get(signal.vuln_class)
        if not rule:
            return []

        try:
            result = subprocess.run(
                ["semgrep", "--json", "-e", rule, self.repo_path],
                capture_output=True, text=True,
                timeout=_SUBPROCESS_TIMEOUT,
            )
            if result.returncode == 0:
                import json
                data = json.loads(result.stdout)
                return data.get("results", [])
        except (subprocess.TimeoutExpired, OSError, ValueError):
            pass

        return []

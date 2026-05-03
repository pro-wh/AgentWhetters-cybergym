"""Extract taint path using cscope/grep for call graph analysis.

Builds a data flow path from program entry point to vulnerable function,
providing the LLM with a structured understanding of how input reaches
the crash site. Zero LLM tokens consumed.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from hypothesis_parser import VulnSignal

logger = logging.getLogger(__name__)

_SUBPROCESS_TIMEOUT = 30

# Entry point functions to look for
_ENTRY_POINTS = [
    "LLVMFuzzerTestOneInput",
    "main",
    "fuzz_target",
    "harness",
]

# Magic byte patterns to grep for
_MAGIC_PATTERNS = [
    (r"magic|signature|header", "generic"),
    (r"0x89504e47|\\x89PNG|PNG", "png"),
    (r"0xffd8ff|\\xff\\xd8\\xff|JFIF|Exif", "jpeg"),
    (r"0x47494638|GIF8", "gif"),
    (r"0x49492a00|0x4d4d002a|TIFF|II\\*", "tiff"),
    (r"0x1f8b|\\x1f\\x8b", "gzip"),
    (r"0x504b0304|PK\\x03\\x04", "zip"),
    (r"0x8a4d4e47|MNG", "mng"),
    (r"0x25504446|%PDF", "pdf"),
    (r"ELF|\\x7fELF", "elf"),
]

# Transform function patterns
_TRANSFORM_PATTERNS = [
    r"ntohl|ntohs|htonl|htons",
    r"base64|b64",
    r"parse|decode|decompress|inflate|uncompress",
    r"read|load|import|open",
    r"malloc|calloc|realloc|alloc",
    r"memcpy|memmove|memset",
]


@dataclass
class TaintPath:
    """Structured taint path from entry to vulnerable sink."""

    source: Dict = field(default_factory=dict)
    sink: Dict = field(default_factory=dict)
    call_chain: List[str] = field(default_factory=list)
    transforms: List[str] = field(default_factory=list)
    trigger_field: str = "unknown"
    format_structure: str = "unknown"
    magic_bytes: str = "unknown"


class TaintPathExtractor:
    """Extract taint path using cscope and grep."""

    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self._cscope_available = False
        self._cscope_built = False

    def _build_cscope_db(self) -> bool:
        """Build cscope database for the repo."""
        if self._cscope_built:
            return self._cscope_available

        try:
            result = subprocess.run(
                ["cscope", "-Rb", "-s", self.repo_path],
                capture_output=True, timeout=_SUBPROCESS_TIMEOUT,
                cwd=self.repo_path,
            )
            self._cscope_available = result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            self._cscope_available = False

        self._cscope_built = True
        return self._cscope_available

    def _cscope_query_callers(self, function_name: str) -> list[str]:
        """Query cscope for functions that call the given function."""
        if not self._build_cscope_db():
            return []

        try:
            result = subprocess.run(
                ["cscope", "-d", "-L", "-3", function_name],
                capture_output=True, text=True,
                timeout=_SUBPROCESS_TIMEOUT, cwd=self.repo_path,
            )
            if result.returncode == 0:
                callers = []
                for line in result.stdout.strip().split("\n"):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            callers.append(parts[1])
                return callers
        except (subprocess.TimeoutExpired, OSError):
            pass
        return []

    def _grep_callers(self, function_name: str) -> list[str]:
        """Fallback: grep for function calls."""
        try:
            result = subprocess.run(
                ["grep", "-rn", f"{function_name}\\s*(", "--include=*.c",
                 "--include=*.cpp", "--include=*.cc", "--include=*.h",
                 self.repo_path],
                capture_output=True, text=True,
                timeout=_SUBPROCESS_TIMEOUT,
            )
            if result.returncode == 0:
                callers = set()
                func_def_re = re.compile(r"(\w+)\s*\(")
                for line in result.stdout.strip().split("\n"):
                    if line.strip() and function_name in line:
                        # Try to extract the enclosing function
                        # This is approximate — look for function-like patterns
                        matches = func_def_re.findall(line)
                        for m in matches:
                            if m != function_name and m.lower() not in (
                                "if", "for", "while", "switch", "return",
                                "sizeof", "typeof",
                            ):
                                callers.add(m)
                return list(callers)[:10]
        except (subprocess.TimeoutExpired, OSError):
            pass
        return []

    def _find_entry_point(self) -> dict:
        """Find the program entry point."""
        for entry_func in _ENTRY_POINTS:
            try:
                result = subprocess.run(
                    ["grep", "-rn", f"{entry_func}", "--include=*.c",
                     "--include=*.cpp", "--include=*.cc",
                     self.repo_path],
                    capture_output=True, text=True,
                    timeout=_SUBPROCESS_TIMEOUT,
                )
                if result.returncode == 0 and result.stdout.strip():
                    first_line = result.stdout.strip().split("\n")[0]
                    # Extract file:line
                    parts = first_line.split(":", 2)
                    if len(parts) >= 2:
                        return {
                            "function": entry_func,
                            "file": os.path.relpath(parts[0], self.repo_path),
                            "line": parts[1],
                        }
            except (subprocess.TimeoutExpired, OSError):
                continue
        return {"function": "unknown", "file": "unknown"}

    def _find_magic_bytes(self) -> str:
        """Grep for magic byte patterns in the source."""
        for pattern, format_name in _MAGIC_PATTERNS:
            try:
                result = subprocess.run(
                    ["grep", "-rn", "-E", "-i", pattern,
                     "--include=*.c", "--include=*.h",
                     "--include=*.cpp", "--include=*.hpp",
                     self.repo_path],
                    capture_output=True, text=True,
                    timeout=_SUBPROCESS_TIMEOUT,
                )
                if result.returncode == 0 and result.stdout.strip():
                    # Found magic bytes
                    first_match = result.stdout.strip().split("\n")[0]
                    return f"{format_name}: {first_match.split(':', 2)[-1].strip()[:80]}"
            except (subprocess.TimeoutExpired, OSError):
                continue
        return "unknown"

    def _find_transforms(self, call_chain: list[str]) -> list[str]:
        """Find data transformation functions in the call chain path."""
        transforms = []
        for pattern in _TRANSFORM_PATTERNS:
            try:
                result = subprocess.run(
                    ["grep", "-rn", "-E", pattern,
                     "--include=*.c", "--include=*.h",
                     "--include=*.cpp",
                     self.repo_path],
                    capture_output=True, text=True,
                    timeout=_SUBPROCESS_TIMEOUT,
                )
                if result.returncode == 0 and result.stdout.strip():
                    # Extract unique function names from matches
                    func_re = re.compile(r"\b(" + pattern + r")\b")
                    for line in result.stdout.strip().split("\n")[:5]:
                        m = func_re.search(line)
                        if m and m.group(1) not in transforms:
                            transforms.append(m.group(1))
            except (subprocess.TimeoutExpired, OSError):
                continue
        return transforms[:10]

    def extract(
        self,
        signal: VulnSignal,
        ranked_files: Optional[List[tuple]] = None,
    ) -> dict:
        """Extract taint path from entry to vulnerable function.

        Returns a dict suitable for injection into the system prompt.
        """
        taint = TaintPath()

        # 1. Find entry point
        taint.source = self._find_entry_point()

        # 2. Build sink info
        taint.sink = {
            "function": signal.vulnerable_function,
            "file": signal.file_hint or "unknown",
            "vuln_class": signal.vuln_class,
        }

        # 3. Build call chain (from sink backwards to entry)
        if signal.vulnerable_function != "unknown":
            # Try cscope first, fallback to grep
            callers = self._cscope_query_callers(signal.vulnerable_function)
            if not callers:
                callers = self._grep_callers(signal.vulnerable_function)

            # Build chain: entry -> ... -> callers -> vulnerable_function
            chain = []
            if taint.source.get("function", "unknown") != "unknown":
                chain.append(taint.source["function"])

            # Add callers (deduplicated, limited)
            seen = set(chain)
            for caller in callers[:5]:
                if caller not in seen:
                    chain.append(caller)
                    seen.add(caller)

            chain.append(signal.vulnerable_function)
            taint.call_chain = chain

        # 4. Find magic bytes
        taint.magic_bytes = self._find_magic_bytes()

        # 5. Find transforms
        taint.transforms = self._find_transforms(taint.call_chain)

        # 6. Use stack trace if available
        if signal.stack_trace and not taint.call_chain:
            taint.call_chain = list(reversed(signal.stack_trace))

        # Convert to dict for prompt injection
        return {
            "source": taint.source,
            "sink": taint.sink,
            "call_chain": taint.call_chain,
            "transforms": taint.transforms,
            "trigger_field": taint.trigger_field,
            "magic_bytes": taint.magic_bytes,
        }

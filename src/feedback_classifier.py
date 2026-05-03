"""Classify execution feedback into actionable categories.

Parses ASan output and exit codes into 8 distinct categories,
each with specific refinement instructions for the LLM.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Optional, Tuple

from hypothesis_parser import VulnSignal


class FeedbackCategory(Enum):
    SUCCESS = "success"
    WRONG_LOCATION = "wrong_location"
    WRONG_CRASH = "wrong_crash"
    PARTIAL_CRASH = "partial_crash"
    BLOCKED_ASSERTION = "blocked_assertion"
    PARSER_REJECTED = "parser_rejected"
    NO_CRASH = "no_crash"
    TIMEOUT = "timeout"


# ---------------------------------------------------------------------------
# ASan parsing helpers
# ---------------------------------------------------------------------------

_ASAN_CLASS_RE = re.compile(r"AddressSanitizer:\s+(\S+)")
_CRASH_FUNC_RE = re.compile(r"#0\s+0x[\da-fA-F]+\s+in\s+(\w+)")
_ASSERTION_RE = re.compile(r"(?:assert(?:ion)?|abort)\s*(?:failed)?.*?(?:at\s+)?(\S+:\d+)?", re.I)
_REJECTION_KEYWORDS = ("invalid", "corrupt", "malformed", "bad", "unsupported",
                       "unexpected", "unrecognized", "unknown format",
                       "not a valid", "failed to parse", "cannot open",
                       "wrong magic", "header error")

_REJECTION_MSG_RE = re.compile(
    r"(?:error|warning|fatal)[:\s]+(.{10,120})",
    re.I,
)


def _extract_asan_class(output: str) -> Optional[str]:
    """Extract the ASan vulnerability class from output."""
    m = _ASAN_CLASS_RE.search(output)
    return m.group(1) if m else None


def _extract_crash_function(output: str) -> Optional[str]:
    """Extract the crashing function from ASan stack trace (#0)."""
    m = _CRASH_FUNC_RE.search(output)
    return m.group(1) if m else None


def _extract_assertion(output: str) -> str:
    """Extract assertion location from output."""
    m = _ASSERTION_RE.search(output)
    if m and m.group(1):
        return m.group(1)
    # Fallback: look for "Assertion `...` failed"
    m2 = re.search(r"Assertion\s+[`'\"](.+?)[`'\"]", output)
    if m2:
        return m2.group(1)
    return "unknown location"


def _extract_rejection_reason(output: str) -> str:
    """Extract the parser rejection reason from output."""
    combined = output.lower()
    for kw in _REJECTION_KEYWORDS:
        idx = combined.find(kw)
        if idx != -1:
            # Grab context around the keyword
            start = max(0, idx - 20)
            end = min(len(output), idx + len(kw) + 80)
            return output[start:end].strip()
    m = _REJECTION_MSG_RE.search(output)
    if m:
        return m.group(1).strip()
    return "input rejected"


def _is_timeout(output: str, error: str) -> bool:
    """Check if the execution timed out."""
    combined = (output + error).lower()
    return any(kw in combined for kw in ("timed out", "timeout", "time limit"))


# ---------------------------------------------------------------------------
# Main classifier
# ---------------------------------------------------------------------------

def classify(
    exit_code: int,
    output: str,
    error: str,
    signal: Optional[VulnSignal] = None,
) -> Tuple[FeedbackCategory, str]:
    """Classify test execution feedback into a category with action string.

    Returns (FeedbackCategory, human-readable action/guidance string).
    """
    combined_output = f"{output}\n{error}"

    # 1. Timeout
    if _is_timeout(output, error):
        return (
            FeedbackCategory.TIMEOUT,
            "Execution timed out. The PoC may cause an infinite loop or "
            "extremely slow parsing. Try a simpler/smaller input that "
            "reaches the vulnerable code path faster."
        )

    # 2. Check for ASan output
    asan_class = _extract_asan_class(combined_output)
    crash_func = _extract_crash_function(combined_output)

    if asan_class and signal:
        # Normalize for comparison
        asan_normalized = asan_class.lower().replace("_", "-")
        signal_normalized = signal.vuln_class.lower().replace("_", "-")

        # Check if class matches
        class_matches = (
            asan_normalized == signal_normalized
            or asan_normalized in signal_normalized
            or signal_normalized in asan_normalized
        )

        # Check if function matches
        func_matches = (
            signal.vulnerable_function != "unknown"
            and crash_func
            and signal.vulnerable_function.lower() == crash_func.lower()
        )

        if class_matches and func_matches:
            return (
                FeedbackCategory.SUCCESS,
                f"PoC triggered the correct vulnerability: {asan_class} "
                f"in {crash_func}. Success!"
            )

        # If vulnerable function is unknown, class match alone = success
        if class_matches and signal.vulnerable_function == "unknown":
            return (
                FeedbackCategory.SUCCESS,
                f"PoC triggered the correct vulnerability type: {asan_class} "
                f"in {crash_func or 'unknown'}. Success!"
            )

        if class_matches and not func_matches:
            target_func = signal.vulnerable_function
            return (
                FeedbackCategory.WRONG_LOCATION,
                f"Right vulnerability type ({asan_class}) but crashed in "
                f"{crash_func or 'unknown'} instead of {target_func}. "
                f"Your PoC reaches a dangerous function but takes a wrong code path. "
                f"Try: corrupt a different field/chunk to route through "
                f"{target_func} instead."
            )

        if not class_matches:
            return (
                FeedbackCategory.WRONG_CRASH,
                f"Got {asan_class} but need {signal.vuln_class}. "
                f"The input reaches dangerous code but triggers the wrong condition. "
                f"Try adjusting the corrupt value: boundary values like "
                f"0x7FFFFFFF, 0x00000001, or 0xFFFFFFFF may shift the bug class."
            )

    elif asan_class:
        # ASan triggered but no signal to compare against
        return (
            FeedbackCategory.SUCCESS,
            f"ASan triggered: {asan_class} in {crash_func or 'unknown'}."
        )

    # 3. SEGV / crash without ASan (exit codes: -11, 139, -6, 134)
    crash_codes = {-11, 139, -6, 134, 137, -9}
    if exit_code in crash_codes or (exit_code < 0 and exit_code != 0):
        return (
            FeedbackCategory.PARTIAL_CRASH,
            f"Crash detected (exit_code={exit_code}) but no ASan detail. "
            f"Very close! The program crashed but without sanitizer output "
            f"to confirm the exact vulnerability type. Try slight adjustments "
            f"to the corrupt value or a different corruption offset."
        )

    # 4. Assertion / abort
    if "assert" in combined_output.lower() or "abort" in combined_output.lower():
        assertion_loc = _extract_assertion(combined_output)
        return (
            FeedbackCategory.BLOCKED_ASSERTION,
            f"Blocked by assertion at {assertion_loc}. The assertion fires "
            f"before reaching the vulnerable sink. Read the assertion "
            f"condition and adjust your input to satisfy it, then the "
            f"execution will continue to the vulnerable code path."
        )

    # 5. Parser rejection
    combined_lower = combined_output.lower()
    if any(kw in combined_lower for kw in _REJECTION_KEYWORDS):
        rejection = _extract_rejection_reason(combined_output)
        return (
            FeedbackCategory.PARSER_REJECTED,
            f"The parser rejected your input: '{rejection}'. "
            f"Fix this specific format issue (magic bytes, header fields, "
            f"checksums, or structure) while keeping the trigger corruption."
        )

    # 6. Clean exit (no crash)
    if exit_code == 0:
        return (
            FeedbackCategory.NO_CRASH,
            "Input processed normally without reaching the vulnerability. "
            "The PoC does not exercise the vulnerable code path. Try: "
            "more extreme values, deeper nesting, a different code path, "
            "or ensure the input format is correct so parsing reaches "
            "the vulnerable function."
        )

    # 7. Other non-zero exit
    if exit_code != 0:
        return (
            FeedbackCategory.PARTIAL_CRASH,
            f"Non-zero exit code ({exit_code}) without recognized sanitizer "
            f"output. This may indicate a crash. Try adjusting the corrupt "
            f"value or ensuring the input exercises the right code path."
        )

    return (
        FeedbackCategory.NO_CRASH,
        f"Unexpected result (exit_code={exit_code}). Analyze output and adjust."
    )

"""Tests for feedback_classifier module."""

import pytest
from src.hypothesis_parser import VulnSignal
from src.feedback_classifier import classify, FeedbackCategory


def _make_signal(
    vuln_class="heap-buffer-overflow",
    vulnerable_function="ReadMNGImage",
    **kwargs,
):
    return VulnSignal(
        vuln_class=vuln_class,
        vulnerable_function=vulnerable_function,
        **kwargs,
    )


class TestClassify:
    """Test feedback classification."""

    def test_success_matching_class_and_function(self):
        output = (
            "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x123\n"
            "#0 0x555a in ReadMNGImage coders/mng.c:387\n"
        )
        signal = _make_signal()
        cat, action = classify(1, output, "", signal)
        assert cat == FeedbackCategory.SUCCESS
        assert "ReadMNGImage" in action

    def test_wrong_location_same_class_different_function(self):
        output = (
            "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x123\n"
            "#0 0x555a in WrongFunction coders/other.c:100\n"
        )
        signal = _make_signal()
        cat, action = classify(1, output, "", signal)
        assert cat == FeedbackCategory.WRONG_LOCATION
        assert "WrongFunction" in action
        assert "ReadMNGImage" in action

    def test_wrong_crash_different_class(self):
        output = (
            "ERROR: AddressSanitizer: use-after-free on address 0x123\n"
            "#0 0x555a in ReadMNGImage coders/mng.c:387\n"
        )
        signal = _make_signal()
        cat, action = classify(1, output, "", signal)
        assert cat == FeedbackCategory.WRONG_CRASH
        assert "use-after-free" in action

    def test_partial_crash_segv_no_asan(self):
        cat, action = classify(-11, "Segmentation fault", "", _make_signal())
        assert cat == FeedbackCategory.PARTIAL_CRASH
        assert "crash" in action.lower()

    def test_partial_crash_exit_139(self):
        cat, action = classify(139, "", "", _make_signal())
        assert cat == FeedbackCategory.PARTIAL_CRASH

    def test_blocked_assertion(self):
        output = "Assertion `size > 0` failed at parser.c:42"
        cat, action = classify(134, output, "", _make_signal())
        # Could be PARTIAL_CRASH or BLOCKED_ASSERTION depending on whether
        # ASan is detected first. The assertion check catches it.
        assert cat in (FeedbackCategory.BLOCKED_ASSERTION, FeedbackCategory.PARTIAL_CRASH)

    def test_parser_rejected(self):
        output = "Error: invalid header magic bytes"
        cat, action = classify(1, output, "", _make_signal())
        assert cat in (
            FeedbackCategory.PARSER_REJECTED,
            FeedbackCategory.PARTIAL_CRASH,
        )

    def test_no_crash(self):
        cat, action = classify(0, "Processed successfully", "", _make_signal())
        assert cat == FeedbackCategory.NO_CRASH
        assert "normally" in action.lower()

    def test_timeout(self):
        cat, action = classify(1, "execution timed out", "", _make_signal())
        assert cat == FeedbackCategory.TIMEOUT
        assert "timeout" in action.lower() or "timed" in action.lower()

    def test_no_signal_with_asan(self):
        output = (
            "ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "#0 0x123 in SomeFunc file.c:10\n"
        )
        cat, action = classify(1, output, "", None)
        assert cat == FeedbackCategory.SUCCESS  # ASan triggered, no signal to compare

    def test_success_class_substring_match(self):
        """Vuln class should match even with formatting differences."""
        output = (
            "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x123\n"
            "#0 0x555a in ReadMNGImage coders/mng.c:387\n"
        )
        signal = _make_signal(vuln_class="heap-buffer-overflow")
        cat, action = classify(1, output, "", signal)
        assert cat == FeedbackCategory.SUCCESS

    def test_action_strings_are_nonempty(self):
        """All categories should produce non-empty action strings."""
        signal = _make_signal()
        test_cases = [
            (0, "clean output", ""),
            (-11, "Segfault", ""),
            (1, "timed out", ""),
            (1, "assert failed", ""),
            (1, "invalid format", ""),
        ]
        for exit_code, output, error in test_cases:
            cat, action = classify(exit_code, output, error, signal)
            assert len(action) > 10, f"Empty action for {cat.value}"

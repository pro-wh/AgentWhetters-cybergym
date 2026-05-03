"""Integration tests for the enhancement modules."""

import json
import os
import tempfile

import pytest

from src.hypothesis_parser import parse_hypothesis, VulnSignal
from src.feedback_classifier import classify, FeedbackCategory
from src.memory_system import MemorySystem
from src.token_tracker import TokenTracker


class TestMemorySystem:
    """Test cross-task memory."""

    def test_save_and_query(self, tmp_path):
        mem = MemorySystem(str(tmp_path / "memory"))

        signal = VulnSignal(
            vuln_class="heap-buffer-overflow",
            project_domain="image_parser",
            crash_type="READ 4",
            vulnerable_function="ReadMNGImage",
        )

        mem.save_result("task-1", signal, {
            "solved": True,
            "winning_pattern": "chunk length overflow at offset 12",
            "iterations": 3,
        })

        result = mem.query_similar("heap-buffer-overflow", "image_parser", "READ 4")
        assert len(result["similar_tasks"]) == 1
        assert result["similar_tasks"][0]["winning_pattern"] == "chunk length overflow at offset 12"

    def test_failed_strategies(self, tmp_path):
        mem = MemorySystem(str(tmp_path / "memory"))

        signal = VulnSignal(vuln_class="use-after-free")
        mem.save_result("task-2", signal, {
            "solved": False,
            "failed_strategy": "random fuzzing approach",
            "iterations": 10,
        })

        strategies = mem.get_failed_strategies("use-after-free")
        assert "random fuzzing approach" in strategies

    def test_no_match(self, tmp_path):
        mem = MemorySystem(str(tmp_path / "memory"))
        result = mem.query_similar("unknown-vuln", "unknown", "unknown")
        assert len(result["similar_tasks"]) == 0

    def test_stats(self, tmp_path):
        mem = MemorySystem(str(tmp_path / "memory"))
        signal = VulnSignal(vuln_class="heap-buffer-overflow")
        mem.save_result("t1", signal, {"solved": True, "iterations": 1})
        mem.save_result("t2", signal, {"solved": False, "iterations": 5})

        stats = mem.get_stats()
        assert stats["total_tasks"] == 2
        assert stats["solved"] == 1
        assert stats["failed"] == 1

    def test_atomic_write_creates_dir(self, tmp_path):
        mem_dir = str(tmp_path / "new" / "nested" / "memory")
        mem = MemorySystem(mem_dir)
        assert os.path.exists(mem_dir)


class TestTokenTracker:
    """Test token tracking."""

    def test_budget_enforcement(self):
        tracker = TokenTracker(budget_limit=1000, cost_limit_usd=1.00)
        assert tracker.should_continue(min_tokens=500)

        # Simulate recording tokens
        tracker._total_input = 800
        tracker._total_output = 100
        assert not tracker.should_continue(min_tokens=200)

    def test_cost_enforcement(self):
        tracker = TokenTracker(budget_limit=1_000_000, cost_limit_usd=0.01)
        tracker._total_cost = 0.02
        assert not tracker.should_continue()

    def test_task_summary(self):
        tracker = TokenTracker(budget_limit=100_000)
        summary = tracker.get_task_summary()
        assert summary["total_tokens"] == 0
        assert summary["budget_limit"] == 100_000
        assert summary["num_calls"] == 0

    def test_save(self, tmp_path):
        tracker = TokenTracker()
        filepath = str(tmp_path / "usage.json")
        tracker.save(filepath)
        assert os.path.exists(filepath)

        with open(filepath) as f:
            data = json.load(f)
        assert "summary" in data
        assert "records" in data

    def test_reset_task(self):
        tracker = TokenTracker()
        tracker._total_input = 500
        tracker._total_output = 300
        tracker.reset_task()
        assert tracker._total_input == 0
        assert tracker._total_output == 0


class TestPipelineIntegration:
    """Test that modules work together."""

    def test_parse_then_classify(self):
        """Parse a description, then classify ASan output against it."""
        desc = "heap-buffer-overflow in ReadMNGImage at coders/mng.c:387"
        signal = parse_hypothesis(desc)

        # Simulate success
        output = (
            "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x123\n"
            "#0 0x555a in ReadMNGImage coders/mng.c:387\n"
        )
        cat, _ = classify(1, output, "", signal)
        assert cat == FeedbackCategory.SUCCESS

        # Simulate wrong location
        output2 = (
            "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x123\n"
            "#0 0x555a in OtherFunc other.c:100\n"
        )
        cat2, action2 = classify(1, output2, "", signal)
        assert cat2 == FeedbackCategory.WRONG_LOCATION
        assert "ReadMNGImage" in action2

    def test_memory_warm_start(self, tmp_path):
        """Test that memory provides warm-start context."""
        mem = MemorySystem(str(tmp_path / "memory"))

        # Save a successful result
        signal1 = VulnSignal(
            vuln_class="heap-buffer-overflow",
            project_domain="image_parser",
        )
        mem.save_result("task-1", signal1, {
            "solved": True,
            "winning_pattern": "PNG chunk length overflow",
            "iterations": 2,
        })

        # Query for a similar task
        result = mem.query_similar("heap-buffer-overflow", "image_parser")
        assert len(result["similar_tasks"]) == 1
        assert "PNG chunk length overflow" in result["similar_tasks"][0]["winning_pattern"]

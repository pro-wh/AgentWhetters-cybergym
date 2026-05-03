"""Cross-task memory for learning from past vulnerability solutions.

Stores results after each task and queries at the start of each new
task to provide warm-start context. JSON-based, no external dependencies.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class MemorySystem:
    """JSON-based cross-task memory for vulnerability solving patterns."""

    def __init__(self, memory_dir: str = "./memory"):
        self.memory_dir = memory_dir
        self._solved_path = os.path.join(memory_dir, "solved_tasks.json")
        self._token_path = os.path.join(memory_dir, "token_usage.json")
        self._ensure_dir()

    def _ensure_dir(self) -> None:
        """Create memory directory and empty JSON files if they don't exist."""
        os.makedirs(self.memory_dir, exist_ok=True)
        for path in (self._solved_path, self._token_path):
            if not os.path.exists(path):
                self._atomic_write(path, [])

    def _atomic_write(self, filepath: str, data: Any) -> None:
        """Write JSON data atomically (write to temp, rename)."""
        dir_path = os.path.dirname(filepath)
        try:
            fd, tmp_path = tempfile.mkstemp(dir=dir_path, suffix=".tmp")
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2, default=str)
            os.replace(tmp_path, filepath)
        except OSError as e:
            logger.warning("[MEMORY] failed to write %s: %s", filepath, e)
            # Clean up temp file if it exists
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def _load_tasks(self) -> list[dict]:
        """Load the solved tasks list."""
        try:
            with open(self._solved_path, "r") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except (OSError, json.JSONDecodeError):
            return []

    def query_similar(
        self,
        vuln_class: str,
        domain: str = "unknown",
        crash_type: str = "unknown",
        limit: int = 3,
    ) -> dict:
        """Query memory for similar past tasks.

        Returns a dict with 'similar_tasks' and 'failed_strategies' keys.
        Scoring: +3 for vuln_class match, +2 for domain match, +1 for crash_type match.
        """
        tasks = self._load_tasks()
        if not tasks:
            return {"similar_tasks": [], "failed_strategies": []}

        scored: list[tuple[float, dict]] = []
        failed_strategies: list[str] = []

        for task in tasks:
            score = 0.0
            if task.get("vuln_class", "") == vuln_class:
                score += 3.0
            if task.get("domain", "") == domain and domain != "unknown":
                score += 2.0
            if task.get("crash_type", "") == crash_type and crash_type != "unknown":
                score += 1.0

            if score > 0:
                if task.get("solved"):
                    scored.append((score, task))
                else:
                    # Collect failed strategies for this vuln class
                    strategy = task.get("failed_strategy", "")
                    if strategy and strategy not in failed_strategies:
                        failed_strategies.append(strategy)

        # Sort by score descending
        scored.sort(key=lambda x: x[0], reverse=True)
        similar = [t for _, t in scored[:limit]]

        return {
            "similar_tasks": similar,
            "failed_strategies": failed_strategies[:limit],
        }

    def save_result(
        self,
        task_id: str,
        signal: Any,
        result: dict,
    ) -> None:
        """Save a task result (success or failure) to memory.

        Args:
            task_id: Unique identifier for the task.
            signal: VulnSignal instance.
            result: Dict with 'solved' (bool), 'winning_pattern' (str),
                    'iterations' (int), optional 'failed_strategy' (str).
        """
        tasks = self._load_tasks()

        entry: Dict[str, Any] = {
            "task_id": task_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "vuln_class": getattr(signal, "vuln_class", "unknown"),
            "domain": getattr(signal, "project_domain", "unknown"),
            "crash_type": getattr(signal, "crash_type", "unknown"),
            "vulnerable_function": getattr(signal, "vulnerable_function", "unknown"),
            "solved": result.get("solved", False),
            "winning_pattern": result.get("winning_pattern", ""),
            "iterations": result.get("iterations", 0),
            "failed_strategy": result.get("failed_strategy", ""),
        }

        tasks.append(entry)
        self._atomic_write(self._solved_path, tasks)
        logger.info(
            "[MEMORY] saved task %s (solved=%s, iterations=%d)",
            task_id, result.get("solved"), result.get("iterations", 0),
        )

    def get_failed_strategies(self, vuln_class: str) -> List[str]:
        """Get strategies that failed on similar vulnerability classes."""
        tasks = self._load_tasks()
        strategies = []
        for task in tasks:
            if (
                task.get("vuln_class") == vuln_class
                and not task.get("solved")
                and task.get("failed_strategy")
            ):
                strategy = task["failed_strategy"]
                if strategy not in strategies:
                    strategies.append(strategy)
        return strategies

    def get_stats(self) -> dict:
        """Get memory statistics."""
        tasks = self._load_tasks()
        solved = sum(1 for t in tasks if t.get("solved"))
        return {
            "total_tasks": len(tasks),
            "solved": solved,
            "failed": len(tasks) - solved,
            "vuln_classes": list({t.get("vuln_class", "unknown") for t in tasks}),
        }

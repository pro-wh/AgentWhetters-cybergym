"""Track token usage across all OpenAI API calls.

Works with both Chat Completions and Responses API formats.
Provides real-time logging and budget enforcement.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional

from log_config import TRACE

logger = logging.getLogger(__name__)

# Pricing per 1M tokens (estimates)
MODEL_PRICING: dict[str, dict[str, float]] = {
    "gpt-5.4": {"input": 5.00, "output": 15.00},
    "gpt-5": {"input": 5.00, "output": 15.00},
    "gpt-4.1": {"input": 2.00, "output": 8.00},
    "gpt-4.1-mini": {"input": 0.40, "output": 1.60},
    "gpt-4o": {"input": 2.50, "output": 10.00},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "o1": {"input": 15.00, "output": 60.00},
    "o3": {"input": 10.00, "output": 40.00},
    "o3-mini": {"input": 1.10, "output": 4.40},
    "o4-mini": {"input": 1.10, "output": 4.40},
}

# Default pricing for unknown models
_DEFAULT_PRICING = {"input": 5.00, "output": 15.00}


@dataclass
class TokenRecord:
    """Single API call token record."""

    timestamp: float
    model: str
    purpose: str
    input_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0
    latency_ms: float = 0.0
    success: bool = True


@dataclass
class TokenTracker:
    """Track token usage with budget enforcement."""

    budget_limit: int = 400_000
    cost_limit_usd: float = 50.00
    records: List[TokenRecord] = field(default_factory=list)
    _total_input: int = 0
    _total_output: int = 0
    _total_reasoning: int = 0
    _total_cost: float = 0.0
    _task_start: float = field(default_factory=time.time)

    def _get_pricing(self, model: str) -> dict[str, float]:
        """Get pricing for a model."""
        for prefix, pricing in MODEL_PRICING.items():
            if model.startswith(prefix):
                return pricing
        return _DEFAULT_PRICING

    def _calculate_cost(
        self, model: str, input_tokens: int, output_tokens: int
    ) -> float:
        """Calculate cost in USD for a set of tokens."""
        pricing = self._get_pricing(model)
        input_cost = (input_tokens / 1_000_000) * pricing["input"]
        output_cost = (output_tokens / 1_000_000) * pricing["output"]
        return input_cost + output_cost

    def record(
        self,
        response: Any,
        model: str,
        purpose: str = "analysis",
        start_time: Optional[float] = None,
        success: bool = True,
    ) -> None:
        """Record token usage from a Chat Completions response.

        Expects response.usage with prompt_tokens, completion_tokens, total_tokens.
        """
        usage = getattr(response, "usage", None)
        if not usage:
            return

        input_tokens = getattr(usage, "prompt_tokens", 0) or 0
        output_tokens = getattr(usage, "completion_tokens", 0) or 0
        total_tokens = getattr(usage, "total_tokens", 0) or (input_tokens + output_tokens)
        reasoning_tokens = 0

        # Some models report reasoning tokens in completion_tokens_details
        details = getattr(usage, "completion_tokens_details", None)
        if details:
            reasoning_tokens = getattr(details, "reasoning_tokens", 0) or 0

        cost = self._calculate_cost(model, input_tokens, output_tokens)
        latency = ((time.time() - start_time) * 1000) if start_time else 0.0

        record = TokenRecord(
            timestamp=time.time(),
            model=model,
            purpose=purpose,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            reasoning_tokens=reasoning_tokens,
            total_tokens=total_tokens,
            cost_usd=cost,
            latency_ms=latency,
            success=success,
        )

        self.records.append(record)
        self._total_input += input_tokens
        self._total_output += output_tokens
        self._total_reasoning += reasoning_tokens
        self._total_cost += cost

        total_used = self._total_input + self._total_output
        pct = (total_used / self.budget_limit * 100) if self.budget_limit > 0 else 0

        logger.log(
            TRACE if total_tokens < 500 else logging.INFO,
            "[TOKENS] %s: +%d tok  $%.4f | session %d/%d (%.0f%%)  total $%.4f",
            purpose, total_tokens, cost,
            total_used, self.budget_limit, pct, self._total_cost,
        )

    def record_responses_api(
        self,
        response: Any,
        purpose: str = "analysis",
        start_time: Optional[float] = None,
    ) -> None:
        """Record token usage from a Responses API response.

        The Responses API uses response.usage with input_tokens, output_tokens.
        """
        usage = getattr(response, "usage", None)
        if not usage:
            return

        input_tokens = getattr(usage, "input_tokens", 0) or 0
        output_tokens = getattr(usage, "output_tokens", 0) or 0
        total_tokens = input_tokens + output_tokens
        reasoning_tokens = getattr(usage, "reasoning_tokens", 0) or 0

        model = getattr(response, "model", "unknown")
        cost = self._calculate_cost(model, input_tokens, output_tokens)
        latency = ((time.time() - start_time) * 1000) if start_time else 0.0

        record = TokenRecord(
            timestamp=time.time(),
            model=model,
            purpose=purpose,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            reasoning_tokens=reasoning_tokens,
            total_tokens=total_tokens,
            cost_usd=cost,
            latency_ms=latency,
        )

        self.records.append(record)
        self._total_input += input_tokens
        self._total_output += output_tokens
        self._total_reasoning += reasoning_tokens
        self._total_cost += cost

        total_used = self._total_input + self._total_output
        pct = (total_used / self.budget_limit * 100) if self.budget_limit > 0 else 0

        logger.log(
            TRACE if total_tokens < 500 else logging.INFO,
            "[TOKENS] %s: +%d tok  $%.4f | session %d/%d (%.0f%%)  total $%.4f",
            purpose, total_tokens, cost,
            total_used, self.budget_limit, pct, self._total_cost,
        )

    def should_continue(self, min_tokens: int = 2000) -> bool:
        """Check if the budget allows continuing.

        Returns True if enough budget remains for at least min_tokens more.
        """
        total_used = self._total_input + self._total_output
        token_ok = (total_used + min_tokens) <= self.budget_limit
        cost_ok = self._total_cost < self.cost_limit_usd
        return token_ok and cost_ok

    def get_task_summary(self) -> dict:
        """Get a summary of token usage for the current task."""
        total_used = self._total_input + self._total_output
        elapsed = time.time() - self._task_start
        return {
            "total_input_tokens": self._total_input,
            "total_output_tokens": self._total_output,
            "total_reasoning_tokens": self._total_reasoning,
            "total_tokens": total_used,
            "total_cost_usd": round(self._total_cost, 4),
            "budget_limit": self.budget_limit,
            "budget_remaining": self.budget_limit - total_used,
            "budget_pct_used": round(
                total_used / self.budget_limit * 100, 1
            ) if self.budget_limit > 0 else 0,
            "cost_limit_usd": self.cost_limit_usd,
            "num_calls": len(self.records),
            "elapsed_seconds": round(elapsed, 1),
        }

    def save(self, filepath: str) -> None:
        """Save token usage records to a JSON file."""
        data = {
            "summary": self.get_task_summary(),
            "records": [asdict(r) for r in self.records],
        }
        try:
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2)
        except OSError as e:
            logger.warning("[TOKENS] failed to save usage to %s: %s", filepath, e)

    def reset_task(self) -> None:
        """Reset counters for a new task (keeps records)."""
        self._total_input = 0
        self._total_output = 0
        self._total_reasoning = 0
        self._total_cost = 0.0
        self._task_start = time.time()

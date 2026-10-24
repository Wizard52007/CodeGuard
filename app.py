from collections.abc import Callable
from typing import Any, Literal
import time

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from src.interceptor import guarded_operation


ThreatCategory = Literal[
    "secret_access",
    "data_exfiltration",
    "destructive_command",
    "persistence_or_privesc",
    "obfuscated_execution",
    "dependency_risk",
    "resource_exhaustion",
    "ssrf_network_exfil",
    "ai_targeted_instructions",
]

CodeLanguage = Literal[
    "python",
    "bash",
    "javascript",
    "sql",
    "yaml",
    "markdown",
    "unknown",
]


class EvaluateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=1)


class EvaluateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: Literal["allow", "block"]
    risk_score: float = Field(ge=0.0, le=1.0)
    categories: list[ThreatCategory]
    code_language: CodeLanguage
    reason: str
    vulnerable_lines: list[int]
    latency_ms: float = Field(ge=0.0)


class InterceptionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["allow", "block", "error"]
    analysis_complete: bool
    operation_called: bool
    reason: str


class InterceptDemoResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assessment: EvaluateResponse | None
    interception: InterceptionResult
    approved_operation_calls: int = Field(ge=0)


app = FastAPI(
    title="CodeGuard",
    description="CPU-based security analysis for AI-generated code",
    version="1.0.0",
)


def get_evaluator() -> Callable[[str], dict[str, Any]]:
    """Load the security detector when evaluation is requested."""
    try:
        from src.detector import evaluate_code
    except ImportError as exc:
        raise HTTPException(
            status_code=503,
            detail="Security detector unavailable. No analysis was performed.",
        ) from exc

    return evaluate_code


def measure_evaluation(
    code: str,
    evaluator: Callable[[str], dict[str, Any]],
) -> tuple[dict[str, Any], float]:
    """Run the detector and return its result and execution time."""
    start_time = time.perf_counter()
    result = evaluator(code)
    latency_ms = round((time.perf_counter() - start_time) * 1000, 3)

    if not isinstance(result, dict):
        raise ValueError("Detector returned an invalid result.")

    return dict(result), latency_ms


def build_api_assessment(
    result: dict[str, Any],
    latency_ms: float,
) -> EvaluateResponse:
    """Validate a detector result and add API latency."""
    result = dict(result)

    lines = result.get("vulnerable_lines")

    if not isinstance(lines, list):
        raise ValueError("Invalid vulnerable_lines field.")

    if any(
        not isinstance(line, int)
        or isinstance(line, bool)
        or line < 1
        for line in lines
    ):
        raise ValueError("Invalid source line number.")

    result["vulnerable_lines"] = sorted(set(lines))
    result["latency_ms"] = latency_ms

    return EvaluateResponse.model_validate(result)


@app.get("/health")
def health() -> dict[str, str]:
    """Check whether the API is running."""
    return {"status": "ok"}


@app.post("/evaluate", response_model=EvaluateResponse)
def evaluate(
    request: EvaluateRequest,
    evaluator: Callable[[str], dict[str, Any]] = Depends(get_evaluator),
) -> EvaluateResponse:
    """Analyze submitted code as text without executing it."""
    try:
        result, latency_ms = measure_evaluation(
            request.code,
            evaluator,
        )
        return build_api_assessment(result, latency_ms)

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Security analysis unavailable. Code was not executed.",
        ) from exc


@app.post(
    "/demo/intercept",
    response_model=InterceptDemoResponse,
)
def intercept_demo(
    request: EvaluateRequest,
    evaluator: Callable[[str], dict[str, Any]] = Depends(get_evaluator),
) -> InterceptDemoResponse:
    """Demonstrate a controlled execution gate.

    Submitted code is analyzed as text and is never executed.
    Only a harmless, pre-approved callback can be invoked.
    """
    captured: dict[str, Any] = {}
    marker = {"calls": 0}

    def capturing_evaluator(code: str) -> dict[str, Any]:
        result, latency_ms = measure_evaluation(code, evaluator)

        # Store a separate API assessment with latency.
        captured["assessment"] = {
            **result,
            "latency_ms": latency_ms,
        }

        # Return the original detector result to the interceptor.
        # This preserves its existing six-field validation contract.
        return result

    def approved_operation() -> None:
        marker["calls"] += 1

    try:
        interception = guarded_operation(
            request.code,
            capturing_evaluator,
            approved_operation,
        )

        assessment = None

        if "assessment" in captured:
            try:
                assessment = EvaluateResponse.model_validate(
                    captured["assessment"]
                )
            except Exception:
                # Invalid assessments must never authorize an operation.
                assessment = None

        return InterceptDemoResponse(
            assessment=assessment,
            interception=InterceptionResult.model_validate(interception),
            approved_operation_calls=marker["calls"],
        )

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                "Interception demonstration unavailable. "
                "Submitted code was not executed."
            ),
        ) from exc

from collections.abc import Callable
from typing import Literal

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


def get_evaluator() -> Callable[[str], dict]:
    """Load Sanket's real detector when evaluation is requested."""
    try:
        from src.detector import evaluate_code
    except ImportError as exc:
        raise HTTPException(
            status_code=503,
            detail="Security detector unavailable. No analysis was performed.",
        ) from exc

    return evaluate_code


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/evaluate", response_model=EvaluateResponse)
def evaluate(
    request: EvaluateRequest,
    evaluator: Callable[[str], dict] = Depends(get_evaluator),
) -> EvaluateResponse:
    """Analyze code without executing it."""
    try:
        result = evaluator(request.code)

        if not isinstance(result, dict):
            raise ValueError("Detector returned an invalid result.")

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

        return EvaluateResponse.model_validate(result)

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Security analysis unavailable. Code was not executed.",
        ) from exc

@app.post("/demo/intercept", response_model=InterceptDemoResponse)
def intercept_demo(
    request: EvaluateRequest,
    evaluator: Callable[[str], dict] = Depends(get_evaluator),
) -> InterceptDemoResponse:
    """Controlled execution-gate demonstration.

    The submitted code is analyzed as text only and is never executed.
    The approved operation only increments a counter local to this request
    and receives no submitted code. The counter shows whether the gate
    invoked the operation.
    """
    captured: dict = {}
    marker = {"calls": 0}

    def capturing_evaluator(code: str) -> dict:
        result = evaluator(code)
        captured["assessment"] = result
        return result

    def approved_operation() -> None:
        marker["calls"] += 1

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
            assessment = None

    return InterceptDemoResponse(
        assessment=assessment,
        interception=InterceptionResult.model_validate(interception),
        approved_operation_calls=marker["calls"],
    )

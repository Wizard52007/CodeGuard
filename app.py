from fastapi import FastAPI

app = FastAPI(
    title="CodeGuard",
    description="CPU-based security analysis for AI-generated code",
    version="1.0.0",
)

@app.get("/health")
def health():
    return {"status": "ok"}

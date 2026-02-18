"""FastAPI middleware integration example."""

from fastapi import FastAPI, Request
from starlette.responses import JSONResponse

from policyshield.client import PolicyShieldClient

app = FastAPI()
shield = PolicyShieldClient(base_url="http://localhost:8000/api/v1")


@app.middleware("http")
async def policy_check(request: Request, call_next):
    result = shield.check(request.url.path, dict(request.query_params))
    if result.verdict == "BLOCK":
        return JSONResponse(status_code=403, content={"error": "blocked"})
    return await call_next(request)


@app.get("/")
async def root():
    return {"message": "Hello World"}

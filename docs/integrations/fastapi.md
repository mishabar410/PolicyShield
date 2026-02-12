# FastAPI Integration

## Middleware

```python
from fastapi import FastAPI
from policyshield.integrations.fastapi import PolicyShieldMiddleware

app = FastAPI()
app.add_middleware(
    PolicyShieldMiddleware,
    rules_path="policies/rules.yaml",
    mode="ENFORCE",
)
```

## Per-route enforcement

```python
from policyshield import ShieldEngine

engine = ShieldEngine.from_yaml("policies/rules.yaml")

@app.post("/agent/tool-call")
async def tool_call(request: ToolCallRequest):
    verdict = engine.evaluate(
        tool=request.tool,
        args=request.args,
    )
    if verdict.action == "block":
        raise HTTPException(403, verdict.message)
    # proceed with tool call
```

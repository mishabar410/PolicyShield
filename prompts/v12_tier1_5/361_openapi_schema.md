# Prompt 361 — OpenAPI Schema Export

## Цель

Добавить `policyshield schema export --format openapi` для экспорта полной OpenAPI спецификации.

## Контекст

- FastAPI генерирует OpenAPI автоматически (`/docs`, `/openapi.json`)
- Но нужна CLI-команда для CI/CD: экспорт schema → SDK generation → publish

## Что сделать

```python
# cli/commands/schema.py
import click
import json

@click.command()
@click.option("--format", "fmt", type=click.Choice(["openapi", "json"]), default="openapi")
@click.option("--output", default=None, help="Output file (default: stdout)")
def export_schema(fmt, output):
    """Export API schema."""
    from policyshield.server.app import create_app
    from policyshield.shield.async_engine import AsyncShieldEngine

    engine = AsyncShieldEngine(rules="rules.yaml")
    app = create_app(engine)
    schema = app.openapi()

    result = json.dumps(schema, indent=2)
    if output:
        with open(output, "w") as f:
            f.write(result)
        click.echo(f"Schema exported to {output}")
    else:
        click.echo(result)
```

## Тесты

```python
class TestSchemaExport:
    def test_schema_is_valid_openapi(self, cli_runner):
        result = cli_runner.invoke(export_schema)
        data = json.loads(result.output)
        assert "openapi" in data
        assert "paths" in data

    def test_schema_has_check_endpoint(self, cli_runner):
        result = cli_runner.invoke(export_schema)
        data = json.loads(result.output)
        assert "/check" in str(data["paths"])
```

## Коммит

```
feat(cli): add schema export command (OpenAPI JSON)
```

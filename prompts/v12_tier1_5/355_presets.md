# Prompt 355 — Presets (strict / permissive / minimal)

## Цель

Добавить встроенные rule presets, которые можно подключить одной строкой: `policyshield init --preset strict`.

## Контекст

- Сейчас нужно вручную писать правила → friction для новых пользователей
- Presets: `strict` (block всё подозрительное), `permissive` (только critical), `minimal` (minimum viable)
- Связано с `policyshield doctor` и `generate-rules` из v11, но это — статические YAML наборы

## Что сделать

### 1. Создать preset YAML файлы

```
policyshield/presets/
  strict.yaml      # Block: file ops, network, shell, DB + honeypots
  permissive.yaml   # Block: only shell_injection, path_traversal
  minimal.yaml      # Block: nothing, just ALLOW + trace
```

### 2. CLI `init --preset`

```python
# cli/commands/init.py
import shutil
from importlib.resources import files

@click.command()
@click.option("--preset", type=click.Choice(["strict", "permissive", "minimal"]), default="strict")
@click.option("--output", default="rules.yaml")
def init(preset, output):
    """Initialize PolicyShield with a preset ruleset."""
    source = files("policyshield.presets").joinpath(f"{preset}.yaml")
    shutil.copy2(source, output)
    click.echo(f"Created {output} from '{preset}' preset ({source})")
```

## Тесты

```python
class TestPresets:
    @pytest.mark.parametrize("preset", ["strict", "permissive", "minimal"])
    def test_preset_loads(self, preset):
        from importlib.resources import files
        source = files("policyshield.presets").joinpath(f"{preset}.yaml")
        assert source.is_file()

    @pytest.mark.parametrize("preset", ["strict", "permissive", "minimal"])
    def test_preset_is_valid_yaml(self, preset):
        from importlib.resources import files
        import yaml
        content = files("policyshield.presets").joinpath(f"{preset}.yaml").read_text()
        data = yaml.safe_load(content)
        assert "rules" in data
```

## Самопроверка

```bash
pytest tests/test_dx.py::TestPresets -v
pytest tests/ -q
```

## Коммит

```
feat: add rule presets (strict/permissive/minimal) with CLI init
```

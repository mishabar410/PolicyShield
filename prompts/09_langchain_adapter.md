# Prompt 09 — LangChain Adapter

## Цель

Обёртка `PolicyShieldTool` для LangChain `BaseTool`, позволяющая оборачивать любой LangChain tool для прохождения через PolicyShield перед выполнением.

## Контекст

- LangChain — самый популярный фреймворк для AI-агентов
- `BaseTool` — базовый класс для всех tools в LangChain
- PolicyShield должен работать как middleware: оборачивает tool, проверяет вызов, пропускает или блокирует

## Что сделать

### 1. Добавить optional dependency

В `pyproject.toml`:
```toml
[project.optional-dependencies]
langchain = ["langchain-core>=0.2"]
```

### 2. Создать `policyshield/integrations/langchain/__init__.py`

Экспорт: `PolicyShieldTool`, `shield_all_tools`

### 3. Создать `policyshield/integrations/langchain/wrapper.py`

```python
from langchain_core.tools import BaseTool, ToolException
from policyshield.shield import ShieldEngine
from policyshield.core.models import Verdict

class PolicyShieldTool(BaseTool):
    """Wraps a LangChain tool with PolicyShield enforcement.
    
    Usage:
        from langchain_community.tools import ShellTool
        from policyshield.integrations.langchain import PolicyShieldTool
        
        engine = ShieldEngine("policies/rules.yaml")
        shell = ShellTool()
        safe_shell = PolicyShieldTool(wrapped_tool=shell, engine=engine)
        
        # Now use safe_shell instead of shell — PolicyShield checks every call
        result = safe_shell.invoke({"command": "ls -la"})  # ALLOW → executes
        result = safe_shell.invoke({"command": "rm -rf /"})  # BLOCK → ToolException
    """
    
    name: str = ""                    # заполняется из wrapped tool
    description: str = ""             # заполняется из wrapped tool
    wrapped_tool: BaseTool
    engine: ShieldEngine
    session_id: str = "default"
    block_behavior: str = "raise"     # "raise" | "return_message"
    
    def __init__(self, wrapped_tool: BaseTool, engine: ShieldEngine, **kwargs):
        super().__init__(
            name=wrapped_tool.name,
            description=wrapped_tool.description,
            wrapped_tool=wrapped_tool,
            engine=engine,
            **kwargs,
        )
    
    def _run(self, *args, **kwargs) -> str:
        """Run the tool with PolicyShield check."""
        # 1. Извлечь аргументы
        tool_input = kwargs or (args[0] if args else {})
        if isinstance(tool_input, str):
            tool_input = {"input": tool_input}
        
        # 2. Проверить через PolicyShield
        result = self.engine.check(
            tool_name=self.name,
            args=tool_input,
            session_id=self.session_id,
        )
        
        # 3. Обработать вердикт
        if result.verdict == Verdict.BLOCK:
            if self.block_behavior == "raise":
                raise ToolException(f"🛡️ PolicyShield BLOCKED: {result.message}")
            return f"🛡️ BLOCKED: {result.message}"
        
        if result.verdict == Verdict.REDACT:
            # Использовать redacted args
            tool_input = result.modified_args or tool_input
        
        # 4. Выполнить wrapped tool
        return self.wrapped_tool._run(**tool_input) if isinstance(tool_input, dict) else self.wrapped_tool._run(tool_input)
    
    async def _arun(self, *args, **kwargs) -> str:
        """Async version — delegates to sync for now."""
        return self._run(*args, **kwargs)


def shield_all_tools(tools: list[BaseTool], engine: ShieldEngine, **kwargs) -> list[PolicyShieldTool]:
    """Wrap all LangChain tools with PolicyShield.
    
    Usage:
        tools = [ShellTool(), WikipediaTool(), ...]
        safe_tools = shield_all_tools(tools, engine)
    """
    return [PolicyShieldTool(wrapped_tool=t, engine=engine, **kwargs) for t in tools]
```

### 4. Тесты: `tests/test_langchain_adapter.py`

Минимум 10 тестов. Используем mock tools (без реального LangChain если не установлен):

```python
import pytest

# Пропустить если langchain не установлен
langchain = pytest.importorskip("langchain_core")
```

```
test_wrap_tool_preserves_name              — PolicyShieldTool.name == wrapped.name
test_wrap_tool_preserves_description       — PolicyShieldTool.description == wrapped.description
test_allow_executes_wrapped                — ALLOW → wrapped tool выполняется, результат возвращается
test_block_raises_exception                — BLOCK → ToolException
test_block_return_message                  — block_behavior="return_message" → строка вместо exception
test_redact_passes_modified_args           — REDACT → wrapped tool получает modified_args
test_string_input_wrapped                  — строковый input → преобразуется в dict
test_shield_all_tools_count                — shield_all_tools(3 tools) → 3 PolicyShieldTool
test_shield_all_tools_names                — все имена сохранены
test_import_error_without_langchain        — без langchain → ImportError с подсказкой
```

### 5. Документация: обновить README

Добавить секцию "LangChain Integration" в README.md с quickstart примером.

## Самопроверки

```bash
pytest tests/ -q
ruff check policyshield/ tests/
pytest tests/ --cov=policyshield --cov-fail-under=85

# Если langchain установлен:
python -c "
from policyshield.integrations.langchain import PolicyShieldTool, shield_all_tools
print('LangChain adapter loaded successfully')
"
```

## Коммит

```
feat(langchain): add LangChain BaseTool adapter

- Add PolicyShieldTool wrapper for LangChain BaseTool
- Add shield_all_tools() convenience function
- Support block_behavior: raise or return_message
- Add REDACT support with modified_args passthrough
- Add 10+ tests (skipped if langchain not installed)
```

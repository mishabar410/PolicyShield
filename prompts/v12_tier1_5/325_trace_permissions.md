# Prompt 325 — Trace File Permissions

## Цель

Установить `0o600` (owner-only) на JSONL trace файлы при создании.

## Контекст

- `trace/recorder.py` использует `open(path, "a")` → default umask (обычно `0o644`)
- Trace файлы содержат tool names, args, verdicts → sensitive data
- Нужно: `chmod 0o600` на создание файла, проверка при start

## Что сделать

```python
# trace/recorder.py
import os
import stat

class TraceRecorder:
    def _open_file(self, path: Path) -> IO:
        """Open trace file with restricted permissions."""
        if not path.exists():
            path.touch(mode=0o600)
        else:
            # Fix permissions if file already exists with wrong perms
            current = path.stat().st_mode & 0o777
            if current != 0o600:
                os.chmod(path, 0o600)
                logger.warning("Fixed trace file permissions: %s (%o → 600)", path, current)
        return open(path, "a")
```

## Тесты

```python
class TestTraceFilePermissions:
    def test_new_trace_file_is_600(self, tmp_path):
        from policyshield.trace.recorder import TraceRecorder
        from policyshield.core.models import Verdict
        recorder = TraceRecorder(output_dir=tmp_path)
        recorder.record("s1", "test", Verdict.BLOCK)
        recorder.flush()
        files = list(tmp_path.glob("*.jsonl"))
        assert len(files) == 1
        perms = files[0].stat().st_mode & 0o777
        assert perms == 0o600

    def test_existing_file_gets_fixed(self, tmp_path):
        import os
        trace_file = tmp_path / "trace.jsonl"
        trace_file.touch(mode=0o644)
        assert (trace_file.stat().st_mode & 0o777) == 0o644
        # After recorder opens it, should fix
        from policyshield.trace.recorder import TraceRecorder
        recorder = TraceRecorder(output_dir=tmp_path)
        recorder._open_file(trace_file)
        assert (trace_file.stat().st_mode & 0o777) == 0o600
```

## Самопроверка

```bash
pytest tests/test_security_data.py::TestTraceFilePermissions -v
pytest tests/ -q
```

## Коммит

```
fix(trace): set 0o600 permissions on trace JSONL files
```

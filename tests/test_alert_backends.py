"""Tests for alert backends and dispatcher."""

from unittest.mock import MagicMock, patch

from policyshield.alerts import Alert, AlertSeverity
from policyshield.alerts.backends import (
    AlertDispatcher,
    ConsoleBackend,
    SlackBackend,
    TelegramBackend,
    WebhookBackend,
)


def _make_alert(**kw):
    return Alert(
        id="a1",
        rule_id="r1",
        rule_name="Test Rule",
        severity=kw.pop("severity", AlertSeverity.WARNING),
        message=kw.pop("message", "Test alert message"),
        **kw,
    )


class TestConsoleBackend:
    def test_send_prints(self, capsys):
        backend = ConsoleBackend()
        alert = _make_alert()
        assert backend.send(alert) is True
        out = capsys.readouterr().out
        assert "Test Rule" in out
        assert "WARNING" in out

    def test_send_with_logger(self):
        backend = ConsoleBackend(use_logger=True)
        alert = _make_alert()
        with patch("policyshield.alerts.backends.logger") as mock_logger:
            assert backend.send(alert) is True
            mock_logger.warning.assert_called_once()


class TestWebhookBackend:
    def test_send_success(self):
        backend = WebhookBackend(url="http://example.com/webhook")
        alert = _make_alert()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            assert backend.send(alert) is True

    def test_send_failure(self):
        backend = WebhookBackend(url="http://example.com/webhook")
        alert = _make_alert()
        with patch("urllib.request.urlopen", side_effect=Exception("Connection refused")):
            assert backend.send(alert) is False


class TestSlackBackend:
    def test_send_success(self):
        backend = SlackBackend(webhook_url="https://hooks.slack.com/test", channel="#alerts")
        alert = _make_alert()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            assert backend.send(alert) is True

    def test_send_failure(self):
        backend = SlackBackend(webhook_url="https://hooks.slack.com/test")
        alert = _make_alert()
        with patch("urllib.request.urlopen", side_effect=Exception("Timeout")):
            assert backend.send(alert) is False


class TestTelegramBackend:
    def test_send_success(self):
        backend = TelegramBackend(bot_token="123:ABC", chat_id="456")
        alert = _make_alert()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            assert backend.send(alert) is True

    def test_send_failure(self):
        backend = TelegramBackend(bot_token="123:ABC", chat_id="456")
        alert = _make_alert()
        with patch("urllib.request.urlopen", side_effect=Exception("Timeout")):
            assert backend.send(alert) is False


class TestAlertDispatcher:
    def test_dispatch_to_multiple_backends(self, capsys):
        d = AlertDispatcher()
        d.add_backend(ConsoleBackend())
        d.add_backend(ConsoleBackend())

        alerts = [_make_alert(), _make_alert(message="Second")]
        results = d.dispatch(alerts)
        assert results["ConsoleBackend"] == 2

    def test_dispatch_empty_alerts(self):
        d = AlertDispatcher()
        d.add_backend(ConsoleBackend())
        results = d.dispatch([])
        assert results["ConsoleBackend"] == 0

    def test_dispatch_no_backends(self):
        d = AlertDispatcher()
        results = d.dispatch([_make_alert()])
        assert results == {}


class TestDispatcherFromConfig:
    def test_from_config_console(self):
        config = {"backends": [{"type": "console"}]}
        d = AlertDispatcher.from_config(config)
        assert len(d.backends) == 1
        assert isinstance(d.backends[0], ConsoleBackend)

    def test_from_config_webhook(self):
        config = {"backends": [{"type": "webhook", "url": "http://example.com"}]}
        d = AlertDispatcher.from_config(config)
        assert isinstance(d.backends[0], WebhookBackend)

    def test_from_config_slack(self):
        config = {"backends": [{"type": "slack", "webhook_url": "https://hooks.slack.com"}]}
        d = AlertDispatcher.from_config(config)
        assert isinstance(d.backends[0], SlackBackend)

    def test_from_config_telegram(self):
        config = {"backends": [{"type": "telegram", "bot_token": "123:ABC", "chat_id": "456"}]}
        d = AlertDispatcher.from_config(config)
        assert isinstance(d.backends[0], TelegramBackend)

    def test_from_config_multiple(self):
        config = {
            "backends": [
                {"type": "console"},
                {"type": "webhook", "url": "http://example.com"},
            ]
        }
        d = AlertDispatcher.from_config(config)
        assert len(d.backends) == 2


class TestSeverityIcons:
    def test_critical_icon(self, capsys):
        backend = ConsoleBackend()
        alert = _make_alert(severity=AlertSeverity.CRITICAL)
        backend.send(alert)
        out = capsys.readouterr().out
        assert "🚨" in out

    def test_info_icon(self, capsys):
        backend = ConsoleBackend()
        alert = _make_alert(severity=AlertSeverity.INFO)
        backend.send(alert)
        out = capsys.readouterr().out
        assert "ℹ️" in out

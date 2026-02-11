"""Test that all package imports work correctly."""


def test_import_policyshield():
    import policyshield

    assert policyshield is not None


def test_version():
    import policyshield

    assert policyshield.__version__ == "0.3.0"


def test_import_core():
    import policyshield.core

    assert policyshield.core is not None


def test_import_shield():
    import policyshield.shield

    assert policyshield.shield is not None


def test_import_trace():
    import policyshield.trace

    assert policyshield.trace is not None


def test_import_cli():
    import policyshield.cli

    assert policyshield.cli is not None


def test_import_integrations():
    import policyshield.integrations

    assert policyshield.integrations is not None


def test_import_integrations_nanobot():
    import policyshield.integrations.nanobot

    assert policyshield.integrations.nanobot is not None

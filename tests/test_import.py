"""Test that all package imports work correctly."""


def test_import_policyshield():
    import policyshield

    assert policyshield is not None


def test_version():
    import policyshield

    version = tuple(int(x) for x in policyshield.__version__.split("."))
    assert version >= (0, 6, 0)


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

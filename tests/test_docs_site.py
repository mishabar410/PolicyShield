"""Tests for MkDocs documentation site configuration."""

from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent.parent
MKDOCS_PATH = ROOT / "mkdocs.yml"
DOCS_DIR = ROOT / "docs"


def _load_mkdocs() -> dict:
    """Load mkdocs.yml."""
    return yaml.safe_load(MKDOCS_PATH.read_text())


class TestMkDocsConfig:
    def test_mkdocs_exists(self):
        assert MKDOCS_PATH.exists()

    def test_site_name(self):
        data = _load_mkdocs()
        assert data["site_name"] == "PolicyShield"

    def test_theme_is_material(self):
        data = _load_mkdocs()
        assert data["theme"]["name"] == "material"

    def test_nav_sections(self):
        data = _load_mkdocs()
        nav = data["nav"]
        section_names = []
        for item in nav:
            if isinstance(item, dict):
                section_names.extend(item.keys())
            elif isinstance(item, str):
                section_names.append(item)
        assert "Getting Started" in section_names
        assert "Guides" in section_names
        assert "Integrations" in section_names


class TestDocPages:
    def _get_all_pages(self) -> list[str]:
        """Get all page paths from mkdocs nav."""
        data = _load_mkdocs()
        pages = []

        def _extract(obj):
            if isinstance(obj, str):
                pages.append(obj)
            elif isinstance(obj, dict):
                for val in obj.values():
                    _extract(val)
            elif isinstance(obj, list):
                for item in obj:
                    _extract(item)

        _extract(data["nav"])
        return pages

    def test_all_pages_exist(self):
        pages = self._get_all_pages()
        missing = []
        for page in pages:
            if not (DOCS_DIR / page).exists():
                missing.append(page)
        assert missing == [], f"Missing docs pages: {missing}"

    def test_index_page_exists(self):
        assert (DOCS_DIR / "index.md").exists()

    def test_installation_page(self):
        assert (DOCS_DIR / "getting-started" / "installation.md").exists()

    def test_quickstart_page(self):
        assert (DOCS_DIR / "getting-started" / "quickstart.md").exists()

    def test_cli_page(self):
        assert (DOCS_DIR / "guides" / "cli.md").exists()


class TestDocContent:
    def test_index_has_features(self):
        content = (DOCS_DIR / "index.md").read_text()
        assert "pip install policyshield" in content

    def test_installation_has_extras(self):
        content = (DOCS_DIR / "getting-started" / "installation.md").read_text()
        assert "[langchain]" in content
        assert "[all]" in content

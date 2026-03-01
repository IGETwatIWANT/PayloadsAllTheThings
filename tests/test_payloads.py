"""Tests for payload parser and database."""

import asyncio
import pytest
from pathlib import Path

from bas.payloads.parser import PayloadParser, CATEGORY_MAP
from bas.payloads.database import PayloadDatabase
from bas.payloads.loader import PayloadLoader


REPO_PATH = Path(__file__).parent.parent


class TestPayloadParser:
    def test_parse_all_finds_categories(self):
        parser = PayloadParser(REPO_PATH)
        categories = parser.parse_all()
        assert len(categories) > 0
        names = [c.canonical_name for c in categories]
        assert "sqli" in names
        assert "xss" in names
        assert "cmdi" in names

    def test_parse_single_category(self):
        parser = PayloadParser(REPO_PATH)
        cat = parser.parse_category("SQL Injection")
        assert cat is not None
        assert cat.canonical_name == "sqli"
        assert len(cat.payloads) > 0
        assert len(cat.intruder_payloads) > 0

    def test_parse_xss_has_intruder_files(self):
        parser = PayloadParser(REPO_PATH)
        cat = parser.parse_category("XSS Injection")
        assert cat is not None
        assert len(cat.intruder_payloads) > 0

    def test_parse_command_injection(self):
        parser = PayloadParser(REPO_PATH)
        cat = parser.parse_category("Command Injection")
        assert cat is not None
        assert cat.canonical_name == "cmdi"

    def test_category_map_coverage(self):
        # Ensure we have mappings for major categories
        required = ["SQL Injection", "XSS Injection", "Command Injection",
                     "Server Side Request Forgery", "Server Side Template Injection"]
        for name in required:
            assert name in CATEGORY_MAP, f"Missing category mapping for {name}"

    def test_parse_nonexistent_returns_none(self):
        parser = PayloadParser(REPO_PATH)
        assert parser.parse_category("Nonexistent Category") is None


class TestPayloadDatabase:
    @pytest.fixture
    def db(self):
        """Create an in-memory database."""
        async def _create():
            db = PayloadDatabase(":memory:")
            await db.initialize()
            return db
        return asyncio.get_event_loop().run_until_complete(_create())

    def test_database_initializes(self, db):
        async def _test():
            stats = await db.get_stats()
            assert stats["categories"] == 0
            assert stats["total_payloads"] == 0
            await db.close()
        asyncio.get_event_loop().run_until_complete(_test())

    def test_import_and_retrieve(self, db):
        async def _test():
            from bas.payloads.parser import ParsedCategory, ParsedPayload
            cat = ParsedCategory(
                name="Test Category",
                canonical_name="test",
                description="Test",
                payloads=[
                    ParsedPayload(payload="' OR 1=1--", category="test"),
                    ParsedPayload(payload="<script>alert(1)</script>", category="test"),
                ],
                intruder_payloads={"test.txt": ["payload1", "payload2", "payload3"]},
            )
            await db.import_category(cat)

            stats = await db.get_stats()
            assert stats["categories"] == 1
            assert stats["inline_payloads"] == 2
            assert stats["intruder_payloads"] == 3

            payloads = await db.get_payloads("test")
            assert len(payloads) == 5  # 2 inline + 3 intruder

            await db.close()
        asyncio.get_event_loop().run_until_complete(_test())

    def test_search_payloads(self, db):
        async def _test():
            from bas.payloads.parser import ParsedCategory, ParsedPayload
            cat = ParsedCategory(
                name="SQLi",
                canonical_name="sqli",
                payloads=[
                    ParsedPayload(payload="' UNION SELECT NULL--", category="sqli"),
                    ParsedPayload(payload="1 AND SLEEP(5)--", category="sqli"),
                ],
            )
            await db.import_category(cat)

            results = await db.search_payloads("UNION")
            assert len(results) == 1
            assert "UNION" in results[0]["payload"]

            results = await db.search_payloads("SLEEP")
            assert len(results) == 1

            await db.close()
        asyncio.get_event_loop().run_until_complete(_test())


class TestPayloadLoader:
    def test_full_load(self):
        async def _test():
            loader = PayloadLoader(REPO_PATH, ":memory:")
            db = await loader.load_all()
            stats = await db.get_stats()

            # Should have loaded many categories and payloads
            assert stats["categories"] > 10, f"Only {stats['categories']} categories loaded"
            assert stats["total_payloads"] > 100, f"Only {stats['total_payloads']} payloads loaded"

            # Verify specific categories exist
            categories = await db.get_categories()
            cat_names = [c["canonical_name"] for c in categories]
            assert "sqli" in cat_names
            assert "xss" in cat_names

            await db.close()
        asyncio.get_event_loop().run_until_complete(_test())

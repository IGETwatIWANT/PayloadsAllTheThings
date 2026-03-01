"""
SQLite-backed payload database.

Provides fast indexed access to payloads by category, tag, and semantic search.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import aiosqlite

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    canonical_name TEXT NOT NULL UNIQUE,
    description TEXT DEFAULT '',
    tools TEXT DEFAULT '[]',
    references_json TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS payloads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category_id INTEGER NOT NULL,
    payload TEXT NOT NULL,
    subcategory TEXT DEFAULT '',
    source_file TEXT DEFAULT '',
    tags TEXT DEFAULT '[]',
    context TEXT DEFAULT '',
    encoding TEXT DEFAULT 'raw',
    FOREIGN KEY (category_id) REFERENCES categories(id)
);

CREATE TABLE IF NOT EXISTS intruder_sets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    payload_count INTEGER DEFAULT 0,
    FOREIGN KEY (category_id) REFERENCES categories(id)
);

CREATE TABLE IF NOT EXISTS intruder_payloads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    set_id INTEGER NOT NULL,
    payload TEXT NOT NULL,
    line_number INTEGER DEFAULT 0,
    FOREIGN KEY (set_id) REFERENCES intruder_sets(id)
);

CREATE INDEX IF NOT EXISTS idx_payloads_category ON payloads(category_id);
CREATE INDEX IF NOT EXISTS idx_payloads_tags ON payloads(tags);
CREATE INDEX IF NOT EXISTS idx_intruder_set ON intruder_payloads(set_id);
CREATE INDEX IF NOT EXISTS idx_categories_canonical ON categories(canonical_name);

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class PayloadDatabase:
    """
    SQLite database for fast payload access.

    Indexes all parsed payloads for quick retrieval by category,
    subcategory, and tags.
    """

    def __init__(self, db_path: str | Path = ":memory:"):
        self._db_path = str(db_path)
        self._db: aiosqlite.Connection | None = None

    async def initialize(self) -> None:
        """Create database and schema."""
        self._db = await aiosqlite.connect(self._db_path)
        await self._db.executescript(SCHEMA)
        await self._db.commit()
        logger.info(f"Payload database initialized at {self._db_path}")

    async def close(self) -> None:
        if self._db:
            await self._db.close()

    async def __aenter__(self) -> PayloadDatabase:
        await self.initialize()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    async def import_category(self, category: Any) -> int:
        """Import a ParsedCategory into the database. Returns category ID."""
        assert self._db is not None

        cursor = await self._db.execute(
            "INSERT OR REPLACE INTO categories (name, canonical_name, description, tools, references_json) VALUES (?, ?, ?, ?, ?)",
            (category.name, category.canonical_name, category.description,
             json.dumps(category.tools), json.dumps(category.references)),
        )
        category_id = cursor.lastrowid
        assert category_id is not None

        # Import inline payloads
        for payload in category.payloads:
            await self._db.execute(
                "INSERT INTO payloads (category_id, payload, subcategory, source_file, tags, context, encoding) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (category_id, payload.payload, payload.subcategory, payload.source_file,
                 json.dumps(payload.tags), payload.context, payload.encoding),
            )

        # Import intruder payloads
        for filename, payloads in category.intruder_payloads.items():
            cursor = await self._db.execute(
                "INSERT INTO intruder_sets (category_id, filename, payload_count) VALUES (?, ?, ?)",
                (category_id, filename, len(payloads)),
            )
            set_id = cursor.lastrowid
            for i, payload in enumerate(payloads):
                await self._db.execute(
                    "INSERT INTO intruder_payloads (set_id, payload, line_number) VALUES (?, ?, ?)",
                    (set_id, payload, i + 1),
                )

        await self._db.commit()
        return category_id

    async def get_payloads(
        self,
        category: str,
        limit: int = 100,
        offset: int = 0,
        source: str = "all",
    ) -> list[str]:
        """Get payloads for a category."""
        assert self._db is not None

        cat_row = await self._db.execute_fetchall(
            "SELECT id FROM categories WHERE canonical_name = ?", (category,)
        )
        if not cat_row:
            return []

        category_id = cat_row[0][0]
        payloads: list[str] = []

        if source in ("all", "inline"):
            rows = await self._db.execute_fetchall(
                "SELECT payload FROM payloads WHERE category_id = ? LIMIT ? OFFSET ?",
                (category_id, limit, offset),
            )
            payloads.extend(row[0] for row in rows)

        if source in ("all", "intruder"):
            set_rows = await self._db.execute_fetchall(
                "SELECT id FROM intruder_sets WHERE category_id = ?", (category_id,)
            )
            for (set_id,) in set_rows:
                rows = await self._db.execute_fetchall(
                    "SELECT payload FROM intruder_payloads WHERE set_id = ? LIMIT ? OFFSET ?",
                    (set_id, limit, offset),
                )
                payloads.extend(row[0] for row in rows)

        return payloads

    async def search_payloads(self, query: str, limit: int = 50) -> list[dict[str, Any]]:
        """Search payloads by text match."""
        assert self._db is not None

        results = []
        rows = await self._db.execute_fetchall(
            """SELECT p.payload, c.canonical_name, p.source_file
               FROM payloads p JOIN categories c ON p.category_id = c.id
               WHERE p.payload LIKE ? LIMIT ?""",
            (f"%{query}%", limit),
        )
        for row in rows:
            results.append({"payload": row[0], "category": row[1], "source": row[2]})

        rows = await self._db.execute_fetchall(
            """SELECT ip.payload, c.canonical_name, s.filename
               FROM intruder_payloads ip
               JOIN intruder_sets s ON ip.set_id = s.id
               JOIN categories c ON s.category_id = c.id
               WHERE ip.payload LIKE ? LIMIT ?""",
            (f"%{query}%", limit),
        )
        for row in rows:
            results.append({"payload": row[0], "category": row[1], "source": row[2]})

        return results

    async def get_categories(self) -> list[dict[str, Any]]:
        """List all categories with payload counts."""
        assert self._db is not None

        rows = await self._db.execute_fetchall(
            """SELECT c.canonical_name, c.name, c.description,
                      (SELECT COUNT(*) FROM payloads WHERE category_id = c.id) as inline_count,
                      (SELECT COALESCE(SUM(payload_count), 0) FROM intruder_sets WHERE category_id = c.id) as intruder_count
               FROM categories c ORDER BY c.name"""
        )
        return [
            {
                "canonical_name": row[0],
                "name": row[1],
                "description": row[2],
                "inline_payloads": row[3],
                "intruder_payloads": row[4],
                "total_payloads": row[3] + row[4],
            }
            for row in rows
        ]

    async def get_stats(self) -> dict[str, int]:
        """Get database statistics."""
        assert self._db is not None

        stats = {}
        for table, label in [
            ("categories", "categories"),
            ("payloads", "inline_payloads"),
            ("intruder_payloads", "intruder_payloads"),
            ("intruder_sets", "intruder_sets"),
        ]:
            rows = await self._db.execute_fetchall(f"SELECT COUNT(*) FROM {table}")
            stats[label] = rows[0][0]

        stats["total_payloads"] = stats["inline_payloads"] + stats["intruder_payloads"]
        return stats

    async def set_metadata(self, key: str, value: str) -> None:
        assert self._db is not None
        await self._db.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)", (key, value)
        )
        await self._db.commit()

    async def get_metadata(self, key: str) -> str | None:
        assert self._db is not None
        rows = await self._db.execute_fetchall(
            "SELECT value FROM metadata WHERE key = ?", (key,)
        )
        return rows[0][0] if rows else None

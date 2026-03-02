"""
Payload loader - orchestrates parsing and database loading.

Provides a simple interface to ingest the PayloadsAllTheThings
repository into the payload database.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

from bas.payloads.parser import PayloadParser
from bas.payloads.database import PayloadDatabase

logger = logging.getLogger(__name__)


class PayloadLoader:
    """Loads PayloadsAllTheThings data into the payload database."""

    def __init__(self, repo_path: str | Path, db_path: str | Path = ":memory:"):
        self._repo_path = Path(repo_path)
        self._db_path = db_path
        self._parser = PayloadParser(repo_path)
        self._db: PayloadDatabase | None = None

    async def load_all(self) -> PayloadDatabase:
        """Parse and load all payload categories into the database."""
        self._db = PayloadDatabase(self._db_path)
        await self._db.initialize()

        logger.info(f"Parsing payloads from {self._repo_path}")
        categories = self._parser.parse_all()

        for category in categories:
            await self._db.import_category(category)
            logger.info(f"  Loaded {category.name} ({category.canonical_name})")

        stats = await self._db.get_stats()
        await self._db.set_metadata("loaded_at", datetime.now().isoformat())
        await self._db.set_metadata("repo_path", str(self._repo_path))
        await self._db.set_metadata("total_categories", str(stats["categories"]))
        await self._db.set_metadata("total_payloads", str(stats["total_payloads"]))

        logger.info(
            f"Loaded {stats['categories']} categories, "
            f"{stats['total_payloads']} total payloads "
            f"({stats['inline_payloads']} inline + {stats['intruder_payloads']} intruder)"
        )

        return self._db

    async def load_category(self, category_name: str) -> PayloadDatabase:
        """Load a single category."""
        if not self._db:
            self._db = PayloadDatabase(self._db_path)
            await self._db.initialize()

        category = self._parser.parse_category(category_name)
        if category:
            await self._db.import_category(category)
            logger.info(f"Loaded {category.name}")

        return self._db

    @property
    def database(self) -> PayloadDatabase | None:
        return self._db

"""Deduplication utilities for reconnaissance data."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional, TypeVar

from reconductor.core.logger import get_logger

logger = get_logger(__name__)

T = TypeVar("T")


class Deduplicator:
    """
    Anew-like deduplication for subdomain lists.

    Maintains a set of seen items and provides deduplication
    against both in-memory sets and file-based master lists.
    """

    def __init__(
        self,
        master_file: Optional[Path] = None,
        case_sensitive: bool = False,
    ):
        """
        Initialize deduplicator.

        Args:
            master_file: Optional file to persist seen items
            case_sensitive: Whether to treat items as case-sensitive
        """
        self.master_file = master_file
        self.case_sensitive = case_sensitive
        self._seen: set[str] = set()

        # Load existing master file if present
        if master_file and master_file.exists():
            self._load_master()

    def _normalize(self, item: str) -> str:
        """Normalize an item for comparison."""
        item = item.strip()
        if not self.case_sensitive:
            item = item.lower()
        return item

    def _load_master(self) -> None:
        """Load items from master file."""
        if not self.master_file:
            return

        try:
            content = self.master_file.read_text()
            for line in content.strip().split("\n"):
                if line.strip():
                    self._seen.add(self._normalize(line))
            logger.debug(f"Loaded {len(self._seen)} items from master file")
        except Exception as e:
            logger.warning(f"Failed to load master file: {e}")

    def _save_master(self) -> None:
        """Save items to master file."""
        if not self.master_file:
            return

        try:
            self.master_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.master_file, "w") as f:
                for item in sorted(self._seen):
                    f.write(f"{item}\n")
        except Exception as e:
            logger.warning(f"Failed to save master file: {e}")

    def add(self, item: str) -> bool:
        """
        Add an item to seen set.

        Args:
            item: Item to add

        Returns:
            True if item was new, False if already seen
        """
        normalized = self._normalize(item)
        if normalized in self._seen:
            return False

        self._seen.add(normalized)
        return True

    def is_new(self, item: str) -> bool:
        """
        Check if an item is new (not seen before).

        Args:
            item: Item to check

        Returns:
            True if new, False if already seen
        """
        return self._normalize(item) not in self._seen

    def deduplicate(
        self,
        items: list[str],
        update_seen: bool = True,
    ) -> list[str]:
        """
        Deduplicate a list of items against the seen set.

        Args:
            items: List of items to deduplicate
            update_seen: Whether to add new items to seen set

        Returns:
            List of new (unseen) items
        """
        new_items = []
        for item in items:
            normalized = self._normalize(item)
            if normalized not in self._seen:
                new_items.append(item)
                if update_seen:
                    self._seen.add(normalized)

        return new_items

    def deduplicate_batch(
        self,
        items: list[str],
        batch_size: int = 1000,
        update_seen: bool = True,
        save_interval: int = 10000,
    ) -> list[str]:
        """
        Deduplicate a large list in batches.

        Args:
            items: List of items to deduplicate
            batch_size: Number of items per batch
            update_seen: Whether to add new items to seen set
            save_interval: How often to save master file

        Returns:
            List of new (unseen) items
        """
        new_items = []
        added_count = 0

        for i in range(0, len(items), batch_size):
            batch = items[i:i + batch_size]
            new_batch = self.deduplicate(batch, update_seen=update_seen)
            new_items.extend(new_batch)

            if update_seen:
                added_count += len(new_batch)
                if added_count >= save_interval:
                    self._save_master()
                    added_count = 0

        # Final save
        if update_seen and self.master_file:
            self._save_master()

        return new_items

    def deduplicate_with_key(
        self,
        items: list[T],
        key_func: Callable[[T], str],
        update_seen: bool = True,
    ) -> list[T]:
        """
        Deduplicate objects using a key function.

        Args:
            items: List of objects to deduplicate
            key_func: Function to extract key from object
            update_seen: Whether to add new items to seen set

        Returns:
            List of new (unseen) objects
        """
        new_items = []
        for item in items:
            key = key_func(item)
            normalized = self._normalize(key)
            if normalized not in self._seen:
                new_items.append(item)
                if update_seen:
                    self._seen.add(normalized)

        return new_items

    @property
    def count(self) -> int:
        """Get number of seen items."""
        return len(self._seen)

    def clear(self) -> None:
        """Clear all seen items."""
        self._seen.clear()

    def save(self) -> None:
        """Save current state to master file."""
        self._save_master()

    def get_all(self) -> set[str]:
        """Get all seen items."""
        return self._seen.copy()


def deduplicate_subdomains(
    subdomains: list[str],
    master_file: Optional[Path] = None,
) -> tuple[list[str], int]:
    """
    Convenience function to deduplicate a list of subdomains.

    Args:
        subdomains: List of subdomains
        master_file: Optional master file for persistence

    Returns:
        Tuple of (unique_subdomains, duplicate_count)
    """
    dedup = Deduplicator(master_file=master_file)
    unique = dedup.deduplicate(subdomains)
    duplicate_count = len(subdomains) - len(unique)

    logger.info(
        "Deduplication complete",
        total=len(subdomains),
        unique=len(unique),
        duplicates=duplicate_count,
    )

    return unique, duplicate_count


def merge_and_deduplicate(
    *sources: list[str],
    master_file: Optional[Path] = None,
) -> list[str]:
    """
    Merge multiple sources and deduplicate.

    Args:
        *sources: Multiple lists to merge
        master_file: Optional master file for persistence

    Returns:
        Merged and deduplicated list
    """
    all_items = []
    for source in sources:
        all_items.extend(source)

    dedup = Deduplicator(master_file=master_file)
    return dedup.deduplicate(all_items)

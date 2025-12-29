"""Secure temporary file management with automatic cleanup."""

from __future__ import annotations

import atexit
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional
import threading

from reconductor.core.logger import get_logger

logger = get_logger(__name__)


class TempFileManager:
    """
    Secure temporary file manager with cleanup tracking.

    Uses tempfile.mkstemp() for secure file creation and tracks
    all created files for cleanup on exit.
    """

    _instance: Optional["TempFileManager"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "TempFileManager":
        """Singleton pattern for global temp file tracking."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._init()
        return cls._instance

    def _init(self) -> None:
        """Initialize the manager."""
        self._temp_files: set[Path] = set()
        self._temp_dirs: set[Path] = set()
        self._cleanup_lock = threading.Lock()
        # Register cleanup on exit
        atexit.register(self.cleanup_all)

    def create_temp_file(
        self,
        suffix: str = "",
        prefix: str = "reconductor_",
        dir: Optional[Path] = None,
        text: bool = True,
    ) -> Path:
        """
        Create a secure temporary file.

        Uses tempfile.mkstemp() which atomically creates the file
        with secure permissions (0600).

        Args:
            suffix: File suffix (e.g., ".txt", ".json")
            prefix: File prefix
            dir: Directory to create file in
            text: Whether file is text mode

        Returns:
            Path to created file
        """
        fd, path = tempfile.mkstemp(
            suffix=suffix,
            prefix=prefix,
            dir=str(dir) if dir else None,
            text=text,
        )
        # Close the file descriptor - we just need the path
        os.close(fd)

        path_obj = Path(path)
        with self._cleanup_lock:
            self._temp_files.add(path_obj)

        logger.debug(f"Created temp file: {path_obj}")
        return path_obj

    def create_temp_dir(
        self,
        suffix: str = "",
        prefix: str = "reconductor_",
        dir: Optional[Path] = None,
    ) -> Path:
        """
        Create a secure temporary directory.

        Args:
            suffix: Directory suffix
            prefix: Directory prefix
            dir: Parent directory

        Returns:
            Path to created directory
        """
        path = tempfile.mkdtemp(
            suffix=suffix,
            prefix=prefix,
            dir=str(dir) if dir else None,
        )

        path_obj = Path(path)
        with self._cleanup_lock:
            self._temp_dirs.add(path_obj)

        logger.debug(f"Created temp dir: {path_obj}")
        return path_obj

    def cleanup_file(self, path: Path) -> bool:
        """
        Clean up a specific temp file.

        Args:
            path: Path to file

        Returns:
            True if cleaned up successfully
        """
        try:
            if path.exists():
                path.unlink()
                logger.debug(f"Cleaned up temp file: {path}")
            with self._cleanup_lock:
                self._temp_files.discard(path)
            return True
        except Exception as e:
            logger.warning(f"Failed to clean up {path}: {e}")
            return False

    def cleanup_dir(self, path: Path) -> bool:
        """
        Clean up a specific temp directory.

        Args:
            path: Path to directory

        Returns:
            True if cleaned up successfully
        """
        import shutil
        try:
            if path.exists():
                shutil.rmtree(path)
                logger.debug(f"Cleaned up temp dir: {path}")
            with self._cleanup_lock:
                self._temp_dirs.discard(path)
            return True
        except Exception as e:
            logger.warning(f"Failed to clean up {path}: {e}")
            return False

    def cleanup_all(self) -> None:
        """Clean up all tracked temp files and directories."""
        with self._cleanup_lock:
            files = list(self._temp_files)
            dirs = list(self._temp_dirs)

        cleaned_files = 0
        cleaned_dirs = 0

        for path in files:
            if self.cleanup_file(path):
                cleaned_files += 1

        for path in dirs:
            if self.cleanup_dir(path):
                cleaned_dirs += 1

        if cleaned_files or cleaned_dirs:
            logger.info(
                f"Cleaned up {cleaned_files} temp files and {cleaned_dirs} temp dirs"
            )


# Global manager instance
_manager: Optional[TempFileManager] = None


def get_temp_manager() -> TempFileManager:
    """Get the global temp file manager."""
    global _manager
    if _manager is None:
        _manager = TempFileManager()
    return _manager


def secure_temp_file(
    suffix: str = "",
    prefix: str = "reconductor_",
    dir: Optional[Path] = None,
) -> Path:
    """
    Create a secure temporary file.

    Convenience function for quick temp file creation.

    Args:
        suffix: File suffix
        prefix: File prefix
        dir: Directory

    Returns:
        Path to created file
    """
    return get_temp_manager().create_temp_file(
        suffix=suffix,
        prefix=prefix,
        dir=dir,
    )


def secure_temp_dir(
    suffix: str = "",
    prefix: str = "reconductor_",
    dir: Optional[Path] = None,
) -> Path:
    """
    Create a secure temporary directory.

    Args:
        suffix: Directory suffix
        prefix: Directory prefix
        dir: Parent directory

    Returns:
        Path to created directory
    """
    return get_temp_manager().create_temp_dir(
        suffix=suffix,
        prefix=prefix,
        dir=dir,
    )


@contextmanager
def temp_file_context(
    suffix: str = "",
    prefix: str = "reconductor_",
    dir: Optional[Path] = None,
) -> Iterator[Path]:
    """
    Context manager for temporary file with automatic cleanup.

    Args:
        suffix: File suffix
        prefix: File prefix
        dir: Directory

    Yields:
        Path to temp file
    """
    manager = get_temp_manager()
    path = manager.create_temp_file(suffix=suffix, prefix=prefix, dir=dir)
    try:
        yield path
    finally:
        manager.cleanup_file(path)


@contextmanager
def temp_dir_context(
    suffix: str = "",
    prefix: str = "reconductor_",
    dir: Optional[Path] = None,
) -> Iterator[Path]:
    """
    Context manager for temporary directory with automatic cleanup.

    Args:
        suffix: Directory suffix
        prefix: Directory prefix
        dir: Parent directory

    Yields:
        Path to temp directory
    """
    manager = get_temp_manager()
    path = manager.create_temp_dir(suffix=suffix, prefix=prefix, dir=dir)
    try:
        yield path
    finally:
        manager.cleanup_dir(path)


def cleanup_temp_files() -> None:
    """Clean up all temporary files created by this module."""
    get_temp_manager().cleanup_all()

"""
ReconDuctor v2.0.0 - Subdomain reconnaissance toolkit.
"""

__version__ = "2.0.0"
__author__ = "ReconDuctor Team"

from reconductor.core.config import Settings, get_settings
from reconductor.core.logger import get_logger, setup_logging

__all__ = [
    "__version__",
    "Settings",
    "get_settings",
    "get_logger",
    "setup_logging",
]

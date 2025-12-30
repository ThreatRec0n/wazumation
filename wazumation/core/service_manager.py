"""
Compatibility service manager module.

The project originally placed service logic under `wazumation.features.service_manager`.
This module provides a stable import path for code/docs that expect:
  `wazumation.core.service_manager`
without duplicating implementation.
"""

from __future__ import annotations

from wazumation.features.service_manager import WazuhServiceManager

__all__ = ["WazuhServiceManager"]



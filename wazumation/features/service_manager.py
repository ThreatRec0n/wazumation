"""
Smart Wazuh service management with graceful handling.

This module is intentionally defensive:
- Works only on Linux/posix hosts with systemd (`systemctl` available).
- Never raises on status checks; returns "unknown" when it can't determine state.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from typing import Tuple

logger = logging.getLogger(__name__)


class WazuhServiceManager:
    """Manages Wazuh service operations intelligently."""

    SERVICE_NAME = "wazuh-manager"

    @classmethod
    def _systemctl_available(cls) -> bool:
        return os.name == "posix" and shutil.which("systemctl") is not None

    @classmethod
    def daemon_reload(cls) -> Tuple[bool, str]:
        """Best-effort reload of systemd unit files."""
        if not cls._systemctl_available():
            return False, "systemctl not available"
        try:
            result = subprocess.run(
                ["systemctl", "daemon-reload"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return False, f"daemon-reload failed: {(result.stderr or '').strip()}"
            return True, "daemon-reload completed"
        except subprocess.TimeoutExpired:
            return False, "daemon-reload timed out"
        except Exception as e:
            return False, f"daemon-reload error: {e}"

    @classmethod
    def is_running(cls) -> bool:
        """Check if Wazuh is currently running."""
        if not cls._systemctl_available():
            return False
        try:
            result = subprocess.run(
                ["systemctl", "is-active", cls.SERVICE_NAME],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0 and "active" in (result.stdout or "").lower()
        except Exception as e:
            logger.warning(f"Could not check service status: {e}")
            return False

    @classmethod
    def get_status(cls) -> str:
        """Get detailed service status: running/stopped/failed/unknown."""
        if not cls._systemctl_available():
            return "unknown"

        try:
            # Prefer machine-readable `is-active` first.
            r = subprocess.run(
                ["systemctl", "is-active", cls.SERVICE_NAME],
                capture_output=True,
                text=True,
                timeout=5,
            )
            out = (r.stdout or "").strip().lower()
            if r.returncode == 0:
                return "running"
            if out in {"inactive", "deactivating"}:
                return "stopped"
            if out == "failed":
                return "failed"

            # Fallback to `status` parsing when `is-active` is inconclusive.
            r2 = subprocess.run(
                ["systemctl", "status", cls.SERVICE_NAME],
                capture_output=True,
                text=True,
                timeout=5,
            )
            s = (r2.stdout or "").lower()
            if "active (running)" in s:
                return "running"
            if "inactive" in s or "dead" in s:
                return "stopped"
            if "failed" in s:
                return "failed"
            return "unknown"
        except Exception:
            return "unknown"

    @classmethod
    def start(cls) -> Tuple[bool, str]:
        """Start Wazuh service."""
        if not cls._systemctl_available():
            return False, "systemctl not available"
        try:
            # CRITICAL: systemd sometimes requires daemon-reload before service ops.
            cls.daemon_reload()
            logger.info("Starting Wazuh service...")
            result = subprocess.run(
                ["systemctl", "start", cls.SERVICE_NAME],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return False, f"Failed to start: {(result.stderr or '').strip()}"

            time.sleep(3)
            if cls.is_running():
                return True, "Service started successfully"
            return False, "Service started but not running"
        except subprocess.TimeoutExpired:
            return False, "Service start timed out"
        except Exception as e:
            return False, f"Error starting service: {e}"

    @classmethod
    def stop(cls) -> Tuple[bool, str]:
        """Stop Wazuh service."""
        if not cls._systemctl_available():
            return False, "systemctl not available"
        try:
            # Best-effort daemon-reload (doesn't hurt, but may fix unit-change warnings).
            cls.daemon_reload()
            logger.info("Stopping Wazuh service...")
            result = subprocess.run(
                ["systemctl", "stop", cls.SERVICE_NAME],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return False, f"Failed to stop: {(result.stderr or '').strip()}"
            time.sleep(2)
            return True, "Service stopped successfully"
        except subprocess.TimeoutExpired:
            return False, "Service stop timed out"
        except Exception as e:
            return False, f"Error stopping service: {e}"

    @classmethod
    def restart(cls) -> Tuple[bool, str]:
        """Restart Wazuh service with smart handling."""
        if not cls._systemctl_available():
            return False, "systemctl not available"

        # CRITICAL: systemd sometimes requires daemon-reload before service ops.
        cls.daemon_reload()

        # If stopped, start instead of restart (avoids noisy failures in some systemd setups).
        if not cls.is_running():
            logger.info("Service is stopped. Starting instead of restarting...")
            return cls.start()

        try:
            logger.info("Restarting Wazuh service...")
            result = subprocess.run(
                ["systemctl", "restart", cls.SERVICE_NAME],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return False, f"Failed to restart: {(result.stderr or '').strip()}"

            time.sleep(5)
            if cls.is_running():
                return True, "Service restarted successfully"
            return False, "Service restarted but not running"
        except subprocess.TimeoutExpired:
            return False, "Service restart timed out"
        except Exception as e:
            return False, f"Error restarting service: {e}"

    @classmethod
    def reload(cls) -> Tuple[bool, str]:
        """Reload Wazuh configuration without full restart; fall back to restart."""
        if not cls._systemctl_available():
            return False, "systemctl not available"
        try:
            logger.info("Reloading Wazuh configuration...")
            cls.daemon_reload()

            result = subprocess.run(
                ["systemctl", "reload", cls.SERVICE_NAME],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                time.sleep(2)
                return True, "Configuration reloaded successfully"

            logger.info("Reload not supported or failed, using restart...")
            return cls.restart()
        except subprocess.TimeoutExpired:
            return False, "Service reload timed out"
        except Exception as e:
            logger.warning(f"Reload failed ({e}), using restart...")
            return cls.restart()

    @classmethod
    def ensure_running(cls) -> Tuple[bool, str]:
        """Ensure service is running, start if needed."""
        if cls.is_running():
            return True, "Service already running"
        return cls.start()



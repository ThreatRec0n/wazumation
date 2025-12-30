"""Tests for self test runner on a sandboxed ossec.conf (no real system paths)."""

import tempfile
import unittest
from pathlib import Path

from wazumation.core.audit import AuditChain, AuditLogger
from wazumation.core.backup import BackupManager
from wazumation.core.applier import PlanApplier
from wazumation.core.validator import ConfigValidator
from wazumation.features.self_test import run_self_test


class TestSelfTestRunner(unittest.TestCase):
    def test_self_test_passes_on_temp_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            cfg = tmp / "ossec.conf"
            cfg.write_text(
                """<?xml version="1.0"?>
<ossec_config>
  <syscheck>
    <disabled>no</disabled>
  </syscheck>
</ossec_config>
""",
                encoding="utf-8",
            )

            data_dir = tmp / "data"
            audit_chain = AuditChain(data_dir / "audit.db")
            audit_logger = AuditLogger(audit_chain)
            backup_manager = BackupManager(data_dir / "backups")
            validator = ConfigValidator(wazuh_manager_path=tmp)  # no wazuh-control in temp; falls back to XML
            applier = PlanApplier(backup_manager, validator, audit_logger, dry_run=False)

            res = run_self_test(
                config_path=cfg,
                data_dir=data_dir,
                applier=applier,
                validator=validator,
                is_manager_fn=lambda p: (True, ""),
            )
            self.assertTrue(res.passed, msg=res.render())


if __name__ == "__main__":
    unittest.main()



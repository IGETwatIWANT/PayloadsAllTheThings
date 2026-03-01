"""Tests for the BAS engine core."""

import pytest
from bas.core.scope import ScopeConfig, AuthorizationLevel
from bas.core.engine import BASEngine, EngineState
from bas.utils.logging import AuditLogger


class TestBASEngine:
    def setup_method(self):
        self.scope_config = ScopeConfig(
            engagement_id="TEST-001",
            engagement_name="Test Engagement",
            authorized_by="Test User",
            target_hosts=["target.internal"],
            target_cidrs=["10.0.0.0/24"],
            auth_level=AuthorizationLevel.STANDARD,
            dry_run=True,
        )
        self.engine = BASEngine(scope_config=self.scope_config)

    def test_initial_state(self):
        assert self.engine.state == EngineState.IDLE
        assert self.engine.engagement_id == "TEST-001"

    def test_register_module(self):
        class FakeModule:
            pass
        self.engine.register_module("test", FakeModule())
        assert "test" in self.engine.list_modules()

    def test_emergency_stop(self):
        self.engine.emergency_stop()
        assert self.engine.state == EngineState.STOPPED


class TestAuditLogger:
    def test_log_and_verify(self, tmp_path):
        logger = AuditLogger(
            engagement_id="TEST-AUDIT",
            log_dir=tmp_path,
            console_output=False,
        )

        logger.log("test_event_1", {"key": "value1"})
        logger.log("test_event_2", {"key": "value2"})
        logger.log("test_event_3", {"key": "value3"})

        valid, count = logger.verify_chain()
        assert valid is True
        assert count == 3

    def test_tamper_detection(self, tmp_path):
        logger = AuditLogger(
            engagement_id="TEST-TAMPER",
            log_dir=tmp_path,
            console_output=False,
        )

        logger.log("event_1", {"data": "test"})
        logger.log("event_2", {"data": "test"})

        # Tamper with the log
        log_file = tmp_path / "TEST-TAMPER.audit.jsonl"
        content = log_file.read_text()
        lines = content.strip().split("\n")
        # Modify a line
        import json
        entry = json.loads(lines[0])
        entry["detail"]["data"] = "TAMPERED"
        lines[0] = json.dumps(entry)
        log_file.write_text("\n".join(lines) + "\n")

        valid, count = logger.verify_chain()
        assert valid is False

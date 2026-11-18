"""Unit tests for ELF inspection and the report formats."""

import json
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchval import exitcodes, hardening, report
from patchval.model import Finding, FUNC_OK


def test_defect5_hardening_on_missing_or_non_elf_file_is_unknown(tmp_path):
    h = hardening.inspect(str(tmp_path / "nope"))
    assert not h.valid and h.nx is None and h.relro == "unknown"
    txt = tmp_path / "f.txt"; txt.write_text("hello")
    assert not hardening.inspect(str(txt)).valid
    d = hardening.compare(h, hardening.inspect(sys.executable))
    assert d.regressed is None


def test_report_formats_with_legacy_fields(tmp_path):
    result = SimpleNamespace(
        config_name="sample", exit_code=exitcodes.INCONCLUSIVE, analysis_complete=False,
        builds={}, diff_summary={}, findings=[Finding("sample", "functional", FUNC_OK)],
        hardening={}, reproducers=[], regression_entries=[], errors=[],
    )
    data = report.to_json(result)
    assert data["target"] == "sample"
    assert data["verdict"]["exit_code"] == exitcodes.INCONCLUSIVE
    assert data["findings"][0]["status"] == FUNC_OK
    assert data["regression_tests"] == []
    assert "analysis INCOMPLETE" in report.to_text(result)

    result.isolation = {"backend": "test", "level": "test", "network": "disabled"}
    result.checks = {"replays_per_finding": 3}
    result.executions = [{"test_id": "sample"}]
    target = tmp_path / "report.json"
    report.write_json(result, str(target))
    saved = json.loads(target.read_text())
    assert saved["isolation"]["backend"] == "test"
    assert saved["executions"] == [{"test_id": "sample"}]
    assert "3 replays per finding" in report.to_text(result)

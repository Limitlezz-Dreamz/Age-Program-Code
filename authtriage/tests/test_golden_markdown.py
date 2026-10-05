"""Golden markdown on the committed Sentinel lab sample."""

from pathlib import Path

import pytest

from authtriage.ioc import write_csv
from authtriage.parsers.authlog_v1 import PARSER_VERSION, AuthlogV1Parser
from authtriage.parsers.base import parse_lines
from authtriage.report import write_markdown
from authtriage.triage import triage

ROOT = Path(__file__).resolve().parents[1]
SENTINEL = ROOT / "testdata" / "sentinel_sample_auth.log"
ELASTIC_SNIPPET = ROOT / "testdata" / "elastic_auth_snippet.log"


def test_golden_sentinel_markdown(tmp_path: Path):
    if not SENTINEL.is_file():
        pytest.skip("missing testdata/sentinel_sample_auth.log")
    events, stats = parse_lines(
        SENTINEL.read_text(encoding="utf-8").splitlines(),
        AuthlogV1Parser(),
    )
    result = triage(events, stats)
    md_path = write_markdown(
        result, stats, tmp_path / "report.md", SENTINEL.name, PARSER_VERSION
    )
    csv_path = write_csv(result, tmp_path / "iocs.csv")
    markdown = md_path.read_text(encoding="utf-8")
    assert "Top source" in markdown
    assert len(result.top_source_ips) >= 1
    assert len(result.fail_then_success) >= 1
    assert "185.220.101.45" in markdown
    assert "fail_then_success" in csv_path.read_text(encoding="utf-8")
    assert stats.unparsed > 0  # sudo / useradd lines


def test_golden_elastic_snippet_if_present():
    if not ELASTIC_SNIPPET.is_file():
        pytest.skip("missing testdata/elastic_auth_snippet.log")
    events, stats = parse_lines(
        ELASTIC_SNIPPET.read_text(encoding="utf-8").splitlines(),
        AuthlogV1Parser(),
    )
    result = triage(events, stats)
    assert len(result.top_source_ips) >= 1
    assert stats.parsed >= 1

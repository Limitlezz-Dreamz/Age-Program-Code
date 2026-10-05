"""CLI help, missing file, and lab banner."""

from pathlib import Path

from authtriage.cli import main
from authtriage.report import LAB_BANNER


def test_help_exits_zero():
    try:
        main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0
    else:
        raise AssertionError("argparse --help should SystemExit(0)")


def test_missing_file(tmp_path: Path, capsys):
    missing = tmp_path / "nope.log"
    code = main([str(missing)])
    err = capsys.readouterr().err
    assert code == 2
    assert LAB_BANNER in err


def test_run_writes_report(tmp_path: Path, capsys):
    log = tmp_path / "auth.log"
    log.write_text(
        "Apr 19 03:12:01 host sshd[1]: Invalid user admin from 192.0.2.1 port 1\n"
        "Apr 19 03:12:02 host sshd[1]: Failed password for root from 192.0.2.1 port 2 ssh2\n"
        "Apr 19 03:12:03 host sshd[1]: Accepted password for ubuntu from 192.0.2.1 port 3 ssh2\n"
        "not a real line\n",
        encoding="utf-8",
    )
    out = tmp_path / "out"
    code = main([str(log), "-o", str(out)])
    err = capsys.readouterr().err
    assert code == 0
    assert LAB_BANNER in err
    assert "unparsed=1" in err
    assert (out / "report.md").is_file()
    assert (out / "iocs.csv").is_file()
    assert (out / "report.html").is_file()
    md = (out / "report.md").read_text(encoding="utf-8")
    assert "Top source" in md
    assert "192.0.2.1" in md
    assert "successful logon after prior failures" in md
    html = (out / "report.html").read_text(encoding="utf-8")
    assert "sparkline" in html
    assert "T1110" in html


def test_stdin_dash(tmp_path: Path, capsys, monkeypatch):
    text = (
        "Apr 19 03:12:01 host sshd[1]: Invalid user admin from 192.0.2.9 port 1\n"
        "noise\n"
    )
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(text))
    out = tmp_path / "out"
    code = main(["-", "-o", str(out), "--format", "md"])
    err = capsys.readouterr().err
    assert code == 0
    assert "inputs=1" in err
    assert (out / "report.md").is_file()
    assert "192.0.2.9" in (out / "report.md").read_text(encoding="utf-8")


def test_batch_directory(tmp_path: Path, capsys):
    folder = tmp_path / "logs"
    folder.mkdir()
    (folder / "a.log").write_text(
        "Apr 19 03:12:01 host sshd[1]: Failed password for root from 198.51.100.1 port 1 ssh2\n",
        encoding="utf-8",
    )
    (folder / "b.log").write_text(
        "Apr 19 03:12:02 host sshd[1]: Accepted password for ubuntu from 198.51.100.1 port 2 ssh2\n",
        encoding="utf-8",
    )
    (folder / "readme.txt").write_text("not a syslog line\n", encoding="utf-8")
    out = tmp_path / "out"
    code = main([str(folder), "-o", str(out), "--format", "both"])
    assert code == 0
    md = (out / "report.md").read_text(encoding="utf-8")
    assert "198.51.100.1" in md
    assert "successful logon after prior failures" in md
    assert not (out / "report.html").exists()


"""Collect log text from a file, directory, or stdin. Read-only."""

from __future__ import annotations

from pathlib import Path

STDIN_NAME = "<stdin>"
LOG_SUFFIXES = {".log", ".txt"}


def resolve_sources(
    path_arg: str,
    *,
    recursive: bool = False,
    stdin_text: str | None = None,
) -> list[tuple[str, list[str]]]:
    """Return ``[(display_name, lines), ...]``.

    ``path_arg`` of ``-`` means stdin (caller passes ``stdin_text``).
    A directory collects ``*.log`` / ``*.txt`` (non-recursive unless asked).
    """
    if path_arg == "-":
        if stdin_text is None:
            raise ValueError("stdin_text is required when path is '-'")
        return [(STDIN_NAME, stdin_text.splitlines())]

    path = Path(path_arg)
    if path.is_file():
        text = path.read_text(encoding="utf-8", errors="replace")
        return [(path.name, text.splitlines())]
    if path.is_dir():
        files = _list_logs(path, recursive=recursive)
        if not files:
            raise FileNotFoundError(
                f"no .log/.txt files in directory: {path}"
            )
        out: list[tuple[str, list[str]]] = []
        for file_path in files:
            text = file_path.read_text(encoding="utf-8", errors="replace")
            label = str(file_path.relative_to(path))
            out.append((label, text.splitlines()))
        return out
    raise FileNotFoundError(f"log file or directory not found: {path}")


def _list_logs(root: Path, *, recursive: bool) -> list[Path]:
    iterator = root.rglob("*") if recursive else root.glob("*")
    files = [
        item
        for item in iterator
        if item.is_file()
        and item.suffix.lower() in LOG_SUFFIXES
        and not item.name.startswith(".")
        and item.name.lower() != "readme.md"
    ]
    return sorted(files)

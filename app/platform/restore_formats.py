"""Every shape a restore upload is allowed to take.

The panel produced ``tar.gz`` archives, so that was all the upload accepted —
until an operator arrived with what every other panel actually hands you:

* Marzban's own backup is a **zip** holding a **MySQL dump** (``db_backup.sql``),
  not a database file at all;
* 3x-ui exports are often a **bare ``x-ui.db``**, zipped or not;
* people rename things, so the extension cannot be trusted — the bytes decide.

So the rule here is: classify by magic number, fall back to the extension, and
refuse with an explanation when neither says anything we know.

The second job is *safe* extraction. A restore unpacks into the live data
directory, where a core binary is currently executing: overwriting it raises
``ETXTBSY`` (Text file busy) — which used to abort the whole restore half
done. A file that is running cannot be replaced, and a half-restored panel is
worse than a skipped binary, so in-use files are skipped and reported.
"""
from __future__ import annotations

import bz2
import gzip
import lzma
import os
import re
import sqlite3
import tarfile
import zipfile
from pathlib import Path
from typing import Iterable, Iterator

from app.platform.restore_errors import RestoreFormatError

# -------------------------------------------------------------------------- #
# classification
# -------------------------------------------------------------------------- #
ARCHIVE_SUFFIXES: tuple[str, ...] = (
    ".tar.gz", ".tgz", ".tar", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".zip",
)
DB_SUFFIXES: tuple[str, ...] = (
    ".db", ".sqlite", ".sqlite3", ".sqlite4", ".sqlitedb", ".db3", ".sdb",
)
SQL_SUFFIXES: tuple[str, ...] = (".sql",)
# Every upload extension the API accepts.
ACCEPTED_SUFFIXES: tuple[str, ...] = ARCHIVE_SUFFIXES + DB_SUFFIXES + SQL_SUFFIXES

_SQLITE_MAGIC = b"SQLite format 3\x00"
# A dump is a text file: cheap to sniff, and the only way to tell
# ``db_backup.sql`` from a file that merely has that name.
_DUMP_HINTS = (
    "-- mysql dump", "-- sqlite", "/*!", "create table", "insert into",
    "drop table", "mysqldump", "pg_dump",
)


def _head(path: Path, size: int = 4096) -> bytes:
    with open(path, "rb") as handle:
        return handle.read(size)


def _matches_suffix(name: str, suffixes: Iterable[str]) -> bool:
    lowered = name.lower()
    return any(lowered.endswith(suffix) for suffix in suffixes)


def classify(path: str | os.PathLike[str]) -> str:
    """``archive``, ``database``, ``sqldump`` — or raise :class:`RestoreFormatError`."""
    target = Path(path)
    if not target.is_file():
        raise RestoreFormatError(f"upload not found: {target}")
    if target.stat().st_size == 0:
        raise RestoreFormatError("the uploaded file is empty")

    head = _head(target)
    name = target.name

    if head.startswith(_SQLITE_MAGIC):
        return "database"
    if head.startswith(b"PK\x03\x04"):
        return "archive"
    if head.startswith((b"\x1f\x8b", b"BZh", b"\xfd7zXZ")):
        return "archive"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "archive"

    # Text: a SQL dump if it says so, otherwise an unknown text file.
    try:
        text = head.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        text = ""
    if text:
        lowered = text[:2048].lower()
        if any(hint in lowered for hint in _DUMP_HINTS):
            return "sqldump"
        if "create table" in lowered or "insert into" in lowered:
            return "sqldump"
        raise RestoreFormatError(
            f"'{name}' is a text file we cannot read as a database dump")

    # Bytes we do not recognise: trust the extension or refuse.
    if _matches_suffix(name, DB_SUFFIXES):
        return "database"
    if _matches_suffix(name, SQL_SUFFIXES):
        return "sqldump"
    if _matches_suffix(name, ARCHIVE_SUFFIXES):
        return "archive"
    raise RestoreFormatError(
        f"cannot tell what '{name}' is (accepted: "
        f"{', '.join(ARCHIVE_SUFFIXES)}, {', '.join(DB_SUFFIXES + SQL_SUFFIXES)})")


def is_archive(path: str | os.PathLike[str]) -> bool:
    return classify(path) == "archive"


# -------------------------------------------------------------------------- #
# extraction
# -------------------------------------------------------------------------- #
def _within(dest: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(dest.resolve())
    except ValueError:
        return False
    return True


def extract(archive: str | os.PathLike[str], dest: str | os.PathLike[str],
            *, live: bool = False) -> tuple[list[str], list[str]]:
    """Unpack *archive* into *dest*.

    Returns ``(written, skipped)``. When *live* is true the destination is the
    running panel's data directory, so a file that is currently executing is
    skipped with a reason instead of aborting the restore.
    """
    target = Path(archive)
    out = Path(dest)
    out.mkdir(parents=True, exist_ok=True)
    if zipfile.is_zipfile(target):
        return _extract_zip(target, out, live=live)
    return _extract_tar(target, out, live=live)


def _record_skip(skipped: list[str], name: str, reason: str) -> None:
    skipped.append(f"{name} ({reason})")


def _extract_zip(archive: Path, dest: Path, *, live: bool) -> tuple[list[str], list[str]]:
    written: list[str] = []
    skipped: list[str] = []
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            name = info.filename
            resolved = (dest / name).resolve()
            if not _within(dest, resolved):
                _record_skip(skipped, name, "path escapes the destination")
                continue
            if name.endswith("/"):
                dest.joinpath(name).mkdir(parents=True, exist_ok=True)
                continue
            resolved.parent.mkdir(parents=True, exist_ok=True)
            try:
                with zf.open(info) as src, open(resolved, "wb") as dst:
                    for chunk in iter(lambda: src.read(1 << 20), b""):
                        dst.write(chunk)
                written.append(name)
            except OSError as exc:
                if not live:
                    raise
                _record_skip(skipped, name, f"in use: {exc.strerror or exc}")
    return written, skipped


def _tar_open(archive: Path) -> tarfile.TarFile:
    try:
        return tarfile.open(archive, "r:*")
    except tarfile.ReadError as exc:
        raise RestoreFormatError(f"not a readable archive: {exc}") from exc


def _extract_tar(archive: Path, dest: Path, *, live: bool) -> tuple[list[str], list[str]]:
    written: list[str] = []
    skipped: list[str] = []
    with _tar_open(archive) as tar:
        for member in tar.getmembers():
            if not (member.isfile() or member.isdir()):
                _record_skip(skipped, member.name, "not a regular file or directory")
                continue
            resolved = (dest / member.name).resolve()
            if not _within(dest, resolved):
                _record_skip(skipped, member.name, "path escapes the destination")
                continue
            try:
                try:
                    tar.extract(member, dest, filter="data")
                except TypeError:  # pragma: no cover - Python < 3.12
                    tar.extract(member, dest)
                written.append(member.name)
            except OSError as exc:
                if not live:
                    raise
                _record_skip(skipped, member.name, f"in use: {exc.strerror or exc}")
    return written, skipped


# -------------------------------------------------------------------------- #
# SQL dumps
# -------------------------------------------------------------------------- #
def _split_statements(sql: str) -> Iterator[str]:
    """Yield SQL statements, split on ``;`` outside quotes and comments."""
    buffer: list[str] = []
    quote: str | None = None
    index = 0
    length = len(sql)
    while index < length:
        char = sql[index]
        if quote:
            buffer.append(char)
            if char == "\\" and quote == "'" and index + 1 < length:
                buffer.append(sql[index + 1])
                index += 2
                continue
            if char == quote:
                # '' is an escaped quote in SQL, not a terminator
                if quote == "'" and index + 1 < length and sql[index + 1] == "'":
                    buffer.append(sql[index + 1])
                    index += 2
                    continue
                quote = None
            index += 1
            continue
        if char in "'\"`":
            quote = char
            buffer.append(char)
            index += 1
            continue
        if sql.startswith("--", index):
            newline = sql.find("\n", index)
            index = length if newline == -1 else newline
            continue
        if sql.startswith("/*", index):
            end = sql.find("*/", index + 2)
            index = length if end == -1 else end + 2
            continue
        if char == ";":
            statement = "".join(buffer).strip()
            if statement:
                yield statement
            buffer = []
            index += 1
            continue
        buffer.append(char)
        index += 1
    tail = "".join(buffer).strip()
    if tail:
        yield tail


_MYSQL_ESCAPES = {
    "0": "\0", "b": "\b", "n": "\n", "r": "\r", "t": "\t",
    "Z": "\x1a", "\\": "\\", "'": "'", '"': '"',
}


def _translate_literals(statement: str, *, mysql_escapes: bool) -> str:
    """Rewrite MySQL string literals into ones SQLite parses the same way.

    ``mysqldump`` escapes with backslashes (``\\'``, ``\\\\``, ``\\n``); SQLite
    does not understand those and would store the backslash itself, silently
    corrupting every value that contains a quote.
    """
    out: list[str] = []
    index = 0
    length = len(statement)
    while index < length:
        char = statement[index]
        if char != "'":
            out.append(char)
            index += 1
            continue
        # consume one single-quoted literal
        out.append("'")
        index += 1
        while index < length:
            current = statement[index]
            if mysql_escapes and current == "\\" and index + 1 < length:
                nxt = statement[index + 1]
                if nxt in _MYSQL_ESCAPES:
                    mapped = _MYSQL_ESCAPES[nxt]
                    out.append("''" if mapped == "'" else mapped)
                    index += 2
                    continue
                out.append(current)
                index += 1
                continue
            if current == "'":
                if index + 1 < length and statement[index + 1] == "'":
                    out.append("''")
                    index += 2
                    continue
                out.append("'")
                index += 1
                break
            out.append(current)
            index += 1
        else:  # pragma: no cover - unterminated literal in a truncated dump
            out.append("'")
    return "".join(out)


_CREATE_CLEANUPS: tuple[tuple[re.Pattern[str], str], ...] = (
    # SQLite only accepts *numeric* arguments in a type name, so
    # `enum('tls','none')` is a syntax error there, not a type. The values do
    # not matter to us — we only read the rows.
    (re.compile(r"\b(ENUM|SET)\s*\([^)]*\)", re.I), "text"),
    # `AUTO_INCREMENT=3` appears on the ENGINE line: the value must go too,
    # or the statement ends up with a dangling `=3`.
    (re.compile(r"\s*AUTO_INCREMENT(\s*=\s*\d+)?", re.I), " "),
    (re.compile(r"\s+ENGINE\s*=\s*\w+", re.I), " "),
    (re.compile(r"\s+DEFAULT\s+CHARSET\s*=\s*\w+", re.I), " "),
    (re.compile(r"\s+COLLATE\s*=\s*\w+", re.I), " "),
    (re.compile(r"\s+COLLATE\s+\w+", re.I), " "),
    (re.compile(r"\s+CHARACTER\s+SET\s+\w+", re.I), " "),
    (re.compile(r"\s+ON\s+UPDATE\s+CURRENT_TIMESTAMP", re.I), " "),
    (re.compile(r"\s+ON\s+DELETE\s+(CASCADE|SET\s+NULL|RESTRICT|NO\s+ACTION)", re.I), " "),
    (re.compile(r"\s+UNSIGNED\b", re.I), " "),
    (re.compile(r"\s+COMMENT\s+'[^']*'", re.I), " "),
    (re.compile(r"\s*,?\s*(UNIQUE\s+)?KEY\s+`[^`]*`\s*\([^)]*\)", re.I), " "),
    (re.compile(r"\s*,?\s*CONSTRAINT\s+`[^`]*`\s+FOREIGN\s+KEY\s*\([^)]*\)"
                r"\s+REFERENCES\s+`[^`]*`\s*\([^)]*\)", re.I), " "),
    (re.compile(r"\s*,?\s*(UNIQUE|INDEX|KEY)\s+[A-Za-z_][\w]*\s*\([^)]*\)", re.I), " "),
    (re.compile(r"\s*,?\s*FULLTEXT\s+(KEY|INDEX)[^,)]*", re.I), " "),
    (re.compile(r"\s*,(\s*\))", re.I), r"\1"),  # trailing comma before ')'
)

_DIRECTIVE = re.compile(r"^/\*!\d*", re.M)
_MYSQL_SET = re.compile(r"^(SET|LOCK TABLES|UNLOCK TABLES|START TRANSACTION|COMMIT)\b", re.I)


def _clean_statement(statement: str) -> str:
    cleaned = statement
    for pattern, replacement in _CREATE_CLEANUPS:
        cleaned = pattern.sub(replacement, cleaned)
    return cleaned.strip().rstrip(";").strip()


def sql_dump_to_sqlite(sql_text: str, dest: str | os.PathLike[str]) -> Path:
    """Replay a MySQL/SQLite dump into a throwaway SQLite database.

    Marzban ships its backup as a ``mysqldump`` — a dialect SQLite cannot
    execute: backslash escapes, ``ENGINE=InnoDB``, ``KEY`` clauses inside
    ``CREATE TABLE`` and ``LOCK TABLES`` around the data. Rather than try to
    be a SQL parser, this strips the dialect-specific decoration and replays
    the two statements that carry information: ``CREATE TABLE`` and
    ``INSERT INTO``.
    """
    target = Path(dest)
    if target.exists():
        target.unlink()
    target.parent.mkdir(parents=True, exist_ok=True)

    mysql = "mysql dump" in sql_text[:512].lower() or "/*!4" in sql_text[:512]
    con = sqlite3.connect(str(target))
    try:
        con.execute("PRAGMA foreign_keys=OFF")
        created = inserted = 0
        for statement in _split_statements(sql_text):
            stripped = statement.lstrip()
            if _DIRECTIVE.match(stripped) or _MYSQL_SET.match(stripped):
                continue
            head = stripped[:12].lower()
            if head.startswith("create table"):
                con.execute(_translate_literals(_clean_statement(statement),
                                                mysql_escapes=mysql))
                created += 1
            elif head.startswith("insert into"):
                con.execute(_translate_literals(statement, mysql_escapes=mysql))
                inserted += 1
            elif head.startswith("drop table"):
                try:
                    con.execute(statement)
                except sqlite3.Error:
                    pass  # dropping something we never created is fine
        con.commit()
        if created == 0:
            raise RestoreFormatError(
                "the SQL dump contains no CREATE TABLE statement — "
                "is it a database dump?")
        if inserted == 0:
            raise RestoreFormatError(
                "the SQL dump has tables but no data to import")
    except sqlite3.Error as exc:
        con.close()
        raise RestoreFormatError(f"could not replay the SQL dump: {exc}") from exc
    con.close()
    return target


def materialize_database(path: str | os.PathLike[str],
                         workdir: str | os.PathLike[str]) -> Path:
    """Return a SQLite file that can be read, whatever the upload was."""
    source = Path(path)
    kind = classify(source)
    if kind == "database":
        return source
    if kind != "sqldump":
        raise RestoreFormatError(f"{source.name} is not a database or SQL dump")
    text = source.read_text(encoding="utf-8", errors="replace")
    return sql_dump_to_sqlite(text, Path(workdir) / "from-dump.sqlite3")


def open_compressed(path: str | os.PathLike[str]):
    """Open a gzip/bz2/xz-compressed text file transparently."""
    target = Path(path)
    head = _head(target, 6)
    if head.startswith(b"\x1f\x8b"):
        return gzip.open(target, "rt", encoding="utf-8", errors="replace")
    if head.startswith(b"BZh"):
        return bz2.open(target, "rt", encoding="utf-8", errors="replace")
    if head.startswith(b"\xfd7zXZ"):
        return lzma.open(target, "rt", encoding="utf-8", errors="replace")
    return open(target, "rt", encoding="utf-8", errors="replace")

"""Backup & Restore (Settings → Backup & Restore, alpha.9.4).

The three things that must never break:

  * an archive is **byte-compatible with the host CLI** and excludes what must
    not be in it (core binaries, the backup folder itself, live DB files);
  * a restore from *another panel* is preview-first — ``inspect`` writes
    nothing, and only ``apply`` touches rows;
  * credentials that arrive from a panel whose hashing we cannot verify are
    re-issued, never imported blindly — an unusable admin is a lockout.

Run: pytest tests/platform/test_backup_restore.py -q
"""
from __future__ import annotations

import sqlite3
import sys
import zipfile
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402

from app.persistence.base import create_schema, create_session_factory  # noqa: E402
from app.persistence.cipher import SecretsCipher  # noqa: E402
from app.persistence.migration import LegacyImportService  # noqa: E402
from app.persistence.models import AdminModel, UserModel  # noqa: E402
from app.persistence import repositories as repos  # noqa: E402
from app.platform import backup_service, backup_store, restore_service  # noqa: E402
from app.platform import restore_formats, restore_sources  # noqa: E402
from app.platform.restore_errors import (  # noqa: E402
    RestoreError,
    RestoreFormatError,
)
from app.utils.passwords import verify_password  # noqa: E402


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture()
def data_dir(tmp_path):
    """A data directory that looks like a real deployment."""
    root = tmp_path / "var"
    (root / "certs").mkdir(parents=True)
    (root / "cores" / "xray" / "bin").mkdir(parents=True)
    (root / "cache").mkdir()
    (root / "subscription-templates").mkdir()
    (root / "certs" / "server.crt").write_text("CERT")
    (root / "cores" / "xray" / "bin" / "xray").write_bytes(b"binary")
    (root / "cores" / "xray" / "config.json").write_text("{}")
    (root / "cache" / "junk").write_bytes(b"x" * 4096)
    db = root / "zagros.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)")
    con.execute("INSERT INTO users (username) VALUES ('alice')")
    con.commit()
    con.close()
    return root


@pytest.fixture()
def session_factory(tmp_path):
    factory = create_session_factory(f"sqlite:///{tmp_path / 'platform.db'}")
    create_schema(factory)
    return factory


@pytest.fixture()
def importer(session_factory):
    cipher = SecretsCipher.from_master_secret("s" * 32)
    return LegacyImportService(session_factory, repos.UserRepository(session_factory, cipher),
                               cipher), cipher


@pytest.fixture()
def xui_db(tmp_path):
    """A 3x-ui ``x-ui.db`` with two clients, traffic and a panel admin."""
    import json

    db = tmp_path / "x-ui.db"
    con = sqlite3.connect(db)
    con.executescript(
        """
        CREATE TABLE users (id integer PRIMARY KEY AUTOINCREMENT, username text,
                            password text, login_secret text);
        CREATE TABLE inbounds (id integer PRIMARY KEY AUTOINCREMENT, user_id integer,
            up integer, down integer, total integer, remark text, enable numeric,
            expiry_time integer, listen text, port integer, protocol text, settings text,
            stream_settings text, sniffing text, tag text);
        CREATE TABLE client_traffics (id integer PRIMARY KEY AUTOINCREMENT,
            inbound_id integer, enable numeric, email text, up integer, down integer,
            expiry_time integer, total integer, reset integer DEFAULT 0);
        """)
    con.execute(
        "INSERT INTO inbounds (id,remark,enable,listen,port,protocol,settings,"
        "stream_settings,tag) VALUES (?,?,?,?,?,?,?,?,?)",
        (1, "Main-VLESS", 1, "0.0.0.0", 443, "vless",
         json.dumps({"clients": [
             {"id": "cid-1", "email": "Ali@Mail.com", "limitIp": 4, "flow": "xtls-rprx-vision"},
             {"id": "cid-2", "email": "sara", "limitIp": 0}]}),
         json.dumps({"security": "reality",
                     "realitySettings": {"serverNames": ["sni.test"]},
                     "wsSettings": {"path": "/p", "headers": {"Host": "h"}}}),
         "in-1"))
    con.execute("INSERT INTO client_traffics (inbound_id,enable,email,up,down,expiry_time,total)"
                " VALUES (?,?,?,?,?,?,?)", (1, 1, "Ali@Mail.com", 1000, 2000, 0, 0))
    con.execute("INSERT INTO client_traffics (inbound_id,enable,email,up,down,expiry_time,total)"
                " VALUES (?,?,?,?,?,?,?)", (1, 0, "sara", 5, 5, 1789000000000, 107374182400))
    con.execute("INSERT INTO users (username,password) VALUES (?,?)", ("boss", "nothash"))
    con.commit()
    con.close()
    return db


# --------------------------------------------------------------------------- #
# backup archive
# --------------------------------------------------------------------------- #
def test_archive_layout_and_exclusions(data_dir):
    artifact = backup_store.create(data_dir=data_dir,
                                   database_url=f"sqlite:///{data_dir / 'zagros.db'}",
                                   panel_version="1.0.0-alpha.9.4")
    path = backup_store.path_for(artifact.name, data_dir)

    with tarfile.open(path) as tar:
        names = set(tar.getnames())
    assert {"manifest.json", "manifest.meta", "db/zagros.sqlite3",
            "data/panel-data.tar.gz"} <= names

    with tarfile.open(path) as tar:
        inner = tar.extractfile("data/panel-data.tar.gz").read()
    inner_path = data_dir.parent / "inner.tar.gz"
    inner_path.write_bytes(inner)
    with tarfile.open(inner_path) as tar:
        inner_names = tar.getnames()

    assert any("certs/server.crt" in n for n in inner_names)
    assert any("cores/xray/config.json" in n for n in inner_names)
    assert not any("/bin/xray" in n for n in inner_names), "core binaries must be excluded"
    assert not any(n.startswith("cache") for n in inner_names), "cache must be excluded"
    assert not any("zagros.db" in n for n in inner_names), "databases are dumped separately"


def test_hot_copy_is_readable_and_verify_passes(data_dir):
    artifact = backup_store.create(data_dir=data_dir,
                                   database_url=f"sqlite:///{data_dir / 'zagros.db'}")
    path = backup_store.path_for(artifact.name, data_dir)
    assert backup_store.verify(path)["ok"] is True

    with tarfile.open(path) as tar:
        payload = tar.extractfile("db/zagros.sqlite3").read()
    copy = data_dir.parent / "copy.db"
    copy.write_bytes(payload)
    assert sqlite3.connect(copy).execute("SELECT username FROM users").fetchone() == ("alice",)


def test_prune_keeps_newest(data_dir):
    for _ in range(3):
        backup_store.create(data_dir=data_dir,
                            database_url=f"sqlite:///{data_dir / 'zagros.db'}")
    assert len(backup_store.list_artifacts(data_dir)) == 3
    removed = backup_store.prune(1, data_dir)
    assert len(removed) == 2
    assert len(backup_store.list_artifacts(data_dir)) == 1


def test_archive_name_cannot_escape(tmp_path):
    """A hostile name is either rejected or flattened — never followed."""
    with pytest.raises(backup_store.BackupError):
        backup_store.safe_name("my backup.tar.gz")          # illegal characters
    # traversal is stripped to a basename, so the result stays inside the dir
    resolved = backup_store.path_for("../../etc/passwd.tar.gz", tmp_path)
    assert resolved.parent.resolve() == backup_store.directory(tmp_path).resolve()
    assert resolved.name == "passwd.tar.gz"


# --------------------------------------------------------------------------- #
# scheduled service
# --------------------------------------------------------------------------- #
def test_token_is_sealed_masked_and_preserved(session_factory):
    store = backup_service.SQLBackupServiceStore(
        session_factory, SecretsCipher.from_master_secret("t" * 32))
    saved = store.save(backup_service.BackupServiceSettings(
        enabled=True, chat_id="-100123", bot_token="999:SECRET"))

    assert "SECRET" not in str(saved.public_dict())
    assert saved.public_dict()["has_token"] is True
    assert store.load()[0].bot_token == "999:SECRET"

    # the UI never sees the token, so it cannot echo it back — keep ours
    again = store.save(backup_service.BackupServiceSettings(
        enabled=True, chat_id="-100123", bot_token="", keep=5))
    assert again.bot_token == "999:SECRET"
    assert again.keep == 5


def test_presets_become_cron():
    settings = backup_service.BackupServiceSettings(schedule="weekly", weekday=2,
                                                    at_hour=4, at_minute=30)
    assert settings.cron_expression() == "30 4 * * 2"
    assert backup_service.BackupServiceSettings(schedule="hourly", at_minute=15).cron_expression() \
        == "15 * * * *"


def test_validation_rejects_bad_configuration():
    settings = backup_service.BackupServiceSettings(enabled=True, chat_id="abc", bot_token="")
    assert any("numeric" in problem for problem in settings.validate())
    assert any("cron" in problem
               for problem in backup_service.BackupServiceSettings(
                   schedule="cron", cron="not a cron").validate())


# --------------------------------------------------------------------------- #
# foreign panels
# --------------------------------------------------------------------------- #
def test_3x_ui_mapping(xui_db):
    assert restore_sources.identify_database(xui_db)["source"] == "3x-ui"
    snapshot, notes = restore_sources.read_3x_ui(xui_db)

    by_name = {u["username"]: u for u in snapshot.users}
    assert set(by_name) == {"ali_mail_com", "sara"}
    assert by_name["ali_mail_com"]["device_limit"] == 4          # limitIp
    assert by_name["ali_mail_com"]["used_traffic"] == 3000       # up + down
    assert by_name["sara"]["status"] == "disabled"               # enable = 0
    assert by_name["sara"]["expire"] == 1789000000               # ms → s
    assert by_name["sara"]["data_limit"] == 107374182400
    assert snapshot.hosts[0]["port"] == 443
    assert snapshot.hosts[0]["sni"] == "sni.test"
    assert {a["username"] for a in snapshot.admins} == {"boss"}
    assert notes["generated_admin_passwords"]["boss"]


def test_username_sanitisation_is_unique():
    taken: set[str] = set()
    first, note = restore_sources.sanitize_username("Ali@Mail.com", taken)
    assert first == "ali_mail_com" and note
    second, _ = restore_sources.sanitize_username("ali mail com", taken)
    assert second != first


def test_import_is_preview_first_then_idempotent(xui_db, session_factory, importer, tmp_path):
    from sqlalchemy import select

    service, cipher = importer
    archive = tmp_path / "3xui.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(xui_db, arcname="x-ui.db")

    data = tmp_path / "data"
    data.mkdir()
    staged = restore_service.save_upload(archive, "3xui.tar.gz", data_dir=data)

    preview = restore_service.inspect(staged, "3x-ui", session_factory=session_factory,
                                      cipher=cipher,
                                      users_repo=repos.UserRepository(session_factory, cipher))
    assert preview.dry_run is True
    with session_factory() as session:
        assert session.scalars(select(UserModel)).all() == []

    report = restore_service.restore_foreign(
        staged, "3x-ui", session_factory=session_factory, cipher=cipher,
        users_repo=repos.UserRepository(session_factory, cipher))
    assert report.dry_run is False
    with session_factory() as session:
        users = {(u.username, u.device_limit) for u in session.scalars(select(UserModel)).all()}
        admin_hashes = {a.username: a.password_hash
                        for a in session.scalars(select(AdminModel)).all()}
    assert ("ali_mail_com", 4) in users
    assert verify_password(report.credentials["boss"], admin_hashes["boss"])

    # running again must not duplicate anything
    restore_sources_snapshot, _ = restore_sources.read_3x_ui(xui_db)
    service.migrate(restore_sources_snapshot, dry_run=False)
    with session_factory() as session:
        assert len(session.scalars(select(UserModel)).all()) == len(users)
        assert len(session.scalars(select(AdminModel)).all()) == len(admin_hashes)


# --------------------------------------------------------------------------- #
# zagros restore
# --------------------------------------------------------------------------- #
def test_zagros_restore_round_trip(data_dir, tmp_path):
    artifact = backup_store.create(data_dir=data_dir,
                                   database_url=f"sqlite:///{data_dir / 'zagros.db'}",
                                   panel_version="1.0.0-alpha.9.4")
    archive = backup_store.path_for(artifact.name, data_dir)

    target = tmp_path / "restored"
    target.mkdir()
    (target / "certs").mkdir(parents=True)
    (target / "certs" / "server.crt").write_text("OLD")
    staged = restore_service.save_upload(archive, "upload.tar.gz", data_dir=target)

    report = restore_service.restore_zagros(
        staged, data_dir=target, database_url=f"sqlite:///{target / 'zagros.db'}")
    assert report.ok is True
    assert (target / "certs" / "server.crt").read_text() == "CERT"
    assert sqlite3.connect(target / "zagros.db").execute(
        "SELECT username FROM users").fetchone() == ("alice",)
    # no host agent in a test environment: the panel must say so, not pretend
    assert report.restart["accepted"] is False
    assert "install-host-agent" in (report.restart.get("detail") or "")
    restore_service.discard(staged)


def test_restart_requires_a_capable_agent(tmp_path):
    root = tmp_path / "data"
    (root / "host-actions").mkdir(parents=True)
    assert restore_service.request_restart(root)["reason"] == "host agent not installed"

    (root / "host-actions" / ".agent-ready").write_text("")
    assert restore_service.request_restart(root)["reason"] == "host agent too old for restart requests"

    (root / "host-actions" / ".agent-capabilities").write_text(
        '{"version":2,"actions":["apply-network","restart-panel"]}')
    assert restore_service.request_restart(root)["accepted"] is True
    assert (root / "host-actions" / "panel-restart.request.json").is_file()


# --------------------------------------------------------------------------- #
# upload formats (what operators actually hand us)
# --------------------------------------------------------------------------- #
class TestFormats:
    """A backup arrives in whatever shape the other panel happened to write."""

    def test_classify_by_content_not_extension(self, tmp_path):
        """The bytes decide: people rename archives, and Marzban writes zips."""
        bare = tmp_path / "backup.dat"
        bare.write_bytes(b"SQLite format 3\x00" + b"\x00" * 60)
        assert restore_formats.classify(bare) == "database"

        zipped = tmp_path / "backup.tar.gz"          # named .tar.gz, is a zip
        with zipfile.ZipFile(zipped, "w") as zf:
            zf.writestr("x-ui.db", b"SQLite format 3\x00")
        assert restore_formats.classify(zipped) == "archive"

        dump = tmp_path / "db_backup.sql"
        dump.write_text("-- MySQL dump 10.13\nCREATE TABLE `t` (`i` int);\n")
        assert restore_formats.classify(dump) == "sqldump"

        mystery = tmp_path / "notes.bin"
        mystery.write_bytes(b"\x00\x01\x02\x03")
        with pytest.raises(RestoreFormatError):
            restore_formats.classify(mystery)

    def test_mysql_dump_becomes_a_readable_database(self, tmp_path):
        """Marzban backs up as a mysqldump, not a database file.

        The dialect has to survive the trip: backslash escapes (or every value
        containing a quote is corrupted), ``ENUM('a','b')`` (a syntax error in
        SQLite, which only accepts numbers in a type name) and the ENGINE/KEY
        clauses.
        """
        dump = tmp_path / "db_backup.sql"
        dump.write_text(
            "-- MySQL dump 10.13  Distrib 8.4.10\n"
            "/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;\n"
            "DROP TABLE IF EXISTS `users`;\n"
            "CREATE TABLE `users` (\n"
            "  `id` int NOT NULL AUTO_INCREMENT,\n"
            "  `username` varchar(34) DEFAULT NULL,\n"
            "  `status` enum('active','disabled') NOT NULL DEFAULT 'active',\n"
            "  `used_traffic` bigint DEFAULT NULL,\n"
            "  PRIMARY KEY (`id`),\n"
            "  KEY `ix_users_username` (`username`)\n"
            ") ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4;\n"
            "LOCK TABLES `users` WRITE;\n"
            "INSERT INTO `users` VALUES (1,'Ali\\'s','active',42),(2,'bob','disabled',0);\n"
            "UNLOCK TABLES;\n",
            encoding="utf-8")
        built = restore_formats.materialize_database(dump, tmp_path)
        con = sqlite3.connect(built)
        try:
            rows = con.execute(
                "SELECT username, status, used_traffic FROM users ORDER BY id").fetchall()
        finally:
            con.close()
        # the backslash escape was decoded, not stored literally
        assert rows == [("Ali's", "active", 42), ("bob", "disabled", 0)]

    def test_a_dump_without_data_is_refused_loudly(self, tmp_path):
        dump = tmp_path / "empty.sql"
        dump.write_text("CREATE TABLE `t` (`i` int);\n", encoding="utf-8")
        with pytest.raises(RestoreFormatError):
            restore_formats.materialize_database(dump, tmp_path)

    def test_bare_database_upload(self, tmp_path, session_factory):
        """3x-ui exports are often just the database file, zipped or not."""
        from app.persistence.cipher import SecretsCipher

        db = tmp_path / "x-ui.db"
        con = sqlite3.connect(db)
        con.executescript(
            "CREATE TABLE inbounds (id integer PRIMARY KEY, remark text, enable numeric,"
            " listen text, port integer, protocol text, settings text, stream_settings text,"
            " tag text);"
            "CREATE TABLE client_traffics (id integer PRIMARY KEY, inbound_id integer,"
            " enable numeric, email text, up integer, down integer, expiry_time integer,"
            " total integer, reset integer);"
            "CREATE TABLE users (id integer PRIMARY KEY, username text, password text);")
        con.execute("INSERT INTO inbounds VALUES (1,'Main',1,'0.0.0.0',443,'vless',?,?,?)",
                    ('{"clients":[{"id":"c1","email":"zoe@example.com","limitIp":2}]}',
                     '{"security":"tls"}', 'in-1'))
        con.execute("INSERT INTO client_traffics VALUES (1,1,1,'zoe@example.com',10,20,0,0,0)")
        con.execute("INSERT INTO users VALUES (1,'root','x')")
        con.commit(); con.close()

        cipher = SecretsCipher.from_master_secret("f" * 32)
        users_repo = repos.UserRepository(session_factory, cipher)
        report = restore_service.restore_foreign(
            db, "3x-ui", session_factory=session_factory, cipher=cipher,
            users_repo=users_repo)
        assert report.counts["users_migrated"] == 1
        # the email becomes a legal, unique username; the IP limit survives
        imported = _usernames(session_factory)
        assert [u.username for u in imported] == ["zoe_example_com"]
        assert imported[0].device_limit == 2
        # the imported admin got a password we can actually verify
        assert report.credentials, "3x-ui hashes are unusable — a password must be issued"

    def test_in_use_file_is_skipped_not_fatal(self, tmp_path):
        """A restore unpacks over running cores; overwriting one fails.

        The restore must carry on and report the file, instead of dying half
        way through (which is what left the panel worse than before).
        """
        data = tmp_path / "data"
        (data / "cores" / "x").mkdir(parents=True)
        protected = data / "cores" / "x" / "binary"
        protected.write_bytes(b"old")
        protected.chmod(0o444)          # unwritable, like a busy executable

        payload = tmp_path / "payload"
        (payload / "cores" / "x").mkdir(parents=True)
        (payload / "cores" / "x" / "binary").write_bytes(b"new")
        (payload / "config.json").write_text("{}")
        archive = tmp_path / "panel-data.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(payload / "cores", arcname="cores")
            tar.add(payload / "config.json", arcname="config.json")

        written, skipped = restore_formats.extract(archive, data, live=True)
        assert "config.json" in written
        assert any("binary" in item for item in skipped)
        assert (data / "config.json").read_text() == "{}"
        protected.chmod(0o644)

    def test_a_refusal_is_an_error_the_api_can_explain(self):
        """The endpoint catches RestoreError — every refusal must be one."""
        assert issubclass(restore_sources.RestoreSourceError, RestoreError)
        assert issubclass(RestoreFormatError, RestoreError)


def _usernames(session_factory):
    from sqlalchemy import select

    from app.persistence.models import UserModel

    with session_factory() as session:
        return list(session.scalars(select(UserModel)).all())

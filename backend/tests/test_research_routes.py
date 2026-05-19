from app.api import routes_research


def test_research_db_size_handles_non_sqlite(monkeypatch):
    monkeypatch.setattr(routes_research.settings, "database_url", "postgresql+asyncpg://ntth:test@db/ntth")

    assert routes_research._sqlite_db_path() is None
    assert routes_research._db_size_bytes() is None


def test_research_db_size_handles_missing_sqlite_file(monkeypatch, tmp_path):
    db_path = tmp_path / "missing.db"
    monkeypatch.setattr(routes_research.settings, "database_url", f"sqlite+aiosqlite:///{db_path}")

    assert routes_research._sqlite_db_path() == db_path
    assert routes_research._db_size_bytes() is None


def test_research_db_size_for_sqlite_file(monkeypatch, tmp_path):
    db_path = tmp_path / "ntth.db"
    db_path.write_bytes(b"abc")
    monkeypatch.setattr(routes_research.settings, "database_url", f"sqlite+aiosqlite:///{db_path}")

    assert routes_research._db_size_bytes() == 3

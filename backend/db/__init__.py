"""SQLAlchemy bootstrap.

Tries PostgreSQL first; if `DB_ALLOW_SQLITE_FALLBACK=1` and Postgres is
unreachable, falls back to a local SQLite file so the user can still run a
demo without installing Postgres.
"""
from __future__ import annotations

import logging
from contextlib import contextmanager

from sqlalchemy        import create_engine
from sqlalchemy.orm    import sessionmaker, scoped_session
from sqlalchemy.exc    import OperationalError, ArgumentError

import config

log = logging.getLogger("aisecops.db")

_engine          = None
_SessionFactory  = None
_active_url      = None
_active_dialect  = None


def _try_engine(url: str):
    eng = create_engine(url, future=True, pool_pre_ping=True)
    # actually probe the connection
    with eng.connect() as c:
        c.execute(__import__("sqlalchemy").text("SELECT 1"))
    return eng


def init_engine() -> tuple[str, str]:
    """Initialise the global engine. Returns (url-used, dialect-name)."""
    global _engine, _SessionFactory, _active_url, _active_dialect
    if _engine is not None:
        return _active_url, _active_dialect

    last_err = None
    candidates = [config.DATABASE_URL]
    if config.DB_ALLOW_SQLITE_FALLBACK:
        candidates.append(config.SQLITE_FALLBACK_URL)

    for url in candidates:
        try:
            eng = _try_engine(url)
            _engine = eng
            _SessionFactory = scoped_session(sessionmaker(
                bind=eng, autoflush=False, expire_on_commit=False, future=True,
            ))
            _active_url     = url
            _active_dialect = eng.dialect.name
            log.warning("[db] connected: %s (%s)", url.split("@")[-1], _active_dialect)
            # Create tables
            from db.models import Base
            Base.metadata.create_all(eng)
            return _active_url, _active_dialect
        except (OperationalError, ArgumentError, Exception) as e:        # noqa: BLE001
            last_err = e
            log.warning("[db] could not connect to %s: %s",
                        url.split("@")[-1], e)
            continue

    raise RuntimeError(f"No database backend available; last error: {last_err}")


def session_factory():
    if _SessionFactory is None:
        init_engine()
    return _SessionFactory


@contextmanager
def session_scope():
    """Use as a context-manager: `with session_scope() as s: ...`."""
    s = session_factory()()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def info() -> dict:
    return {
        "url_redacted": (_active_url or "?").split("@")[-1],
        "dialect":      _active_dialect or "?",
        "connected":    _engine is not None,
    }

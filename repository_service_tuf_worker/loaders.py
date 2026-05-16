# SPDX-FileCopyrightText: 2023-2025 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from repository_service_tuf_worker.models.settings import RSTUFSettings, RSTUFLocks

def load(obj, env=None, silent=True, key=None, filename=None):
    """
    Reads and loads in to "obj" a single key or all keys from database.
    """
    db_server = obj.get("DB_SERVER")
    if not db_server:
        logging.debug("DB_SERVER not found in settings, skipping DB loader")
        return

    try:
        engine = create_engine(db_server)
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        with SessionLocal() as session:
            if key:
                setting = session.query(RSTUFSettings).filter_by(key=key).first()
                if setting:
                    obj.update({key: setting.value})
            else:
                settings = session.query(RSTUFSettings).all()
                data = {s.key: s.value for s in settings}
                obj.update(data)
    except Exception as e:
        if not silent:
            raise e
        logging.error(f"Error loading settings from DB: {e}")

def write(obj, data: Dict[str, Any]):
    """
    Writes data to database.
    """
    db_server = obj.get("DB_SERVER")
    if not db_server:
        raise AttributeError("DB_SERVER not found in settings")

    engine = create_engine(db_server)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    with SessionLocal() as session:
        for key, value in data.items():
            setting = session.query(RSTUFSettings).filter_by(key=key).first()
            if setting:
                setting.value = value
            else:
                setting = RSTUFSettings(key=key, value=value)
                session.add(setting)
        session.commit()

def acquire_lock(obj, name: str, expire: int) -> bool:
    """
    Acquires a lock in the database.
    """
    db_server = obj.get("DB_SERVER")
    if not db_server:
        return False

    engine = create_engine(db_server)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    with SessionLocal() as session:
        now = datetime.now(timezone.utc)
        lock = session.query(RSTUFLocks).filter_by(name=name).first()
        if lock:
            if lock.expires < now:
                lock.expires = now + timedelta(seconds=expire)
                session.commit()
                return True
            else:
                return False
        else:
            lock = RSTUFLocks(name=name, expires=now + timedelta(seconds=expire))
            session.add(lock)
            session.commit()
            return True

def release_lock(obj, name: str):
    """
    Releases a lock in the database.
    """
    db_server = obj.get("DB_SERVER")
    if not db_server:
        return

    engine = create_engine(db_server)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    with SessionLocal() as session:
        lock = session.query(RSTUFLocks).filter_by(name=name).first()
        if lock:
            session.delete(lock)
            session.commit()

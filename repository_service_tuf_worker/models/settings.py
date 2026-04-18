# SPDX-FileCopyrightText: 2023-2025 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT
from sqlalchemy import Column, DateTime, String
from sqlalchemy.dialects.postgresql import JSON

from repository_service_tuf_worker.models.targets import Base


class RSTUFSettings(Base):
    __tablename__ = "rstuf_settings"
    key = Column(String, primary_key=True, index=True)
    value = Column(JSON, nullable=False)


class RSTUFLocks(Base):
    __tablename__ = "rstuf_locks"
    name = Column(String, primary_key=True, index=True)
    expires = Column(DateTime, nullable=False)

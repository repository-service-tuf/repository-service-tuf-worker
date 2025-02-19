# SPDX-FileCopyrightText: 2023 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
)
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.orm import relationship

from repository_service_tuf_worker.models.targets import Base, schemas


class RSTUFTargetFiles(Base):
    __tablename__ = "rstuf_target_files"
    id = Column(Integer, primary_key=True, index=True)
    path = Column(String, unique=True, index=True, nullable=False)
    info = Column(JSON, nullable=False)
    published = Column(Boolean, default=False, nullable=False)
    action = Column(
        Enum(schemas.TargetAction),
        nullable=False,
    )
    last_update = Column(DateTime, default=datetime.now(timezone.utc))
    targets_role = Column(Integer, ForeignKey("rstuf_target_roles.id"))


class RSTUFTargetRoles(Base):
    __tablename__ = "rstuf_target_roles"
    id = Column(Integer, primary_key=True, index=True)
    rolename = Column(String, nullable=False, unique=True, index=True)
    expires = Column(DateTime, nullable=False)
    version = Column(Integer, nullable=False)
    active = Column(Boolean, default=True, nullable=False)
    last_update = Column(DateTime, default=datetime.now(timezone.utc))
    target_files = relationship(RSTUFTargetFiles, backref="rstuf_target_roles")

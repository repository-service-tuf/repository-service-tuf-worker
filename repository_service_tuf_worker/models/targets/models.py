# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Enum, Integer, String
from sqlalchemy.dialects.postgresql import JSON

from repository_service_tuf_worker.models.targets import Base, schemas


class RSTUFTargets(Base):
    __tablename__ = "rstuf_targets"
    id = Column(Integer, primary_key=True, index=True)
    path = Column(String, unique=True, index=True, nullable=False)
    info = Column(JSON, nullable=False)
    rolename = Column(String, nullable=False)
    published = Column(Boolean, default=False, nullable=False)
    action = Column(
        Enum(schemas.TargetAction),
        nullable=False,
    )
    last_update = Column(DateTime, default=datetime.now(), nullable=False)

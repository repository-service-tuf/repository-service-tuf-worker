# SPDX-FileCopyrightText: 2023 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
import enum
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from pydantic import BaseModel


class TargetAction(enum.Enum):
    ADD = "ADD"
    REMOVE = "REMOVE"


class RSTUFTargetRoleCreate(BaseModel):
    rolename: str
    version: int
    expires: datetime

    class Config:
        orm_mode = True


class RSTUFTargetFileCreate(BaseModel):
    path: str
    info: Dict[str, Any]
    published: bool
    action: TargetAction
    last_update: Optional[datetime] = datetime.now(timezone.utc)

    class Config:
        orm_mode = True

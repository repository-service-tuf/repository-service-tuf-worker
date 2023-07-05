# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
import enum
from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel


class TargetAction(enum.Enum):
    ADD = "ADD"
    REMOVE = "REMOVE"


class RSTUFTargetRoleCreate(BaseModel):
    rolename: str
    version: int

    class Config:
        orm_mode = True


class RSTUFTargetFileCreate(BaseModel):
    path: str
    info: Dict[str, Any]
    published: bool
    action: TargetAction
    last_update: Optional[datetime] = datetime.now()

    class Config:
        orm_mode = True

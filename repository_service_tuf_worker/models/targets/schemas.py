# SPDX-FileCopyrightText: 2022 VMware Inc
#
# SPDX-License-Identifier: MIT
import enum
from datetime import datetime
from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel


class TargetAction(enum.Enum):
    ADD = "ADD"
    REMOVE = "REMOVE"


class TargetsCreate(BaseModel):
    path: str
    info: Dict[str, Any]
    rolename: str
    published: bool
    action: TargetAction
    last_update: Optional[datetime]

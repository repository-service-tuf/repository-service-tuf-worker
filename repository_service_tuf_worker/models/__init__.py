# SPDX-FileCopyrightText: 2023 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
import os
import sys

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from repository_service_tuf_worker.models.targets import (  # noqa
    crud as targets_crud,
)
from repository_service_tuf_worker.models.targets import (  # noqa
    models as targets_models,
)
from repository_service_tuf_worker.models.targets import (  # noqa
    schemas as targets_schema,
)


def rstuf_db(db_server: str) -> Session:
    connect_args = {}

    if os.environ.get("RSTUF_DB_KEEPALIVE"):
        connect_args["keepalives"] = 1
        connect_args["keepalives_idle"] = int(
            os.environ.get("RSTUF_DB_KEEPALIVE_IDLE", "30")
        )
        connect_args["keepalives_interval"] = int(
            os.environ.get("RSTUF_DB_KEEPALIVE_INTERVAL", "5")
        )

        if sys.platform == "linux":
            connect_args["keepalives_count"] = int(
                os.environ.get("RSTUF_DB_KEEPALIVE_COUNT", "3")
            )

    engine = create_engine(
        db_server,
        pool_pre_ping=True,
        pool_recycle=1800,
        connect_args=connect_args,
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    return db

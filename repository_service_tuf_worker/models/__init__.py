# SPDX-FileCopyrightText: 2023 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from repository_service_tuf_worker.models.targets import (  # noqa
    crud as targets_crud,
)
from repository_service_tuf_worker.models.targets import (  # noqa
    models as targets_models,
)
from repository_service_tuf_worker.models.targets import (  # noqa
    schemas as targets_schema,
)


def rstuf_db(db_server: str) -> sessionmaker:
    engine = create_engine(db_server)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    return db

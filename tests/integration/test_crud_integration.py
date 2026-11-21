# SPDX-FileCopyrightText: 2023-2025 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import datetime
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from repository_service_tuf_worker.models.targets import Base, crud
from repository_service_tuf_worker.models.targets.models import (
    RSTUFTargetFiles,
    RSTUFTargetRoles,
)
from repository_service_tuf_worker.models.targets.schemas import (
    RSTUFTargetRoleCreate,
    RSTUFTargetFileCreate,
    TargetAction,
)

@pytest.fixture
def db_session():
    # Use an in-memory SQLite database for robust integration testing
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)

class TestCRUDIntegration:
    def test_create_and_read_role(self, db_session):
        # 1. Create a role
        expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        role_create = RSTUFTargetRoleCreate(
            rolename="bin",
            version=1,
            expires=expires,
        )
        created_role = crud.create_roles(db_session, [role_create])[0]
        assert created_role.id is not None
        assert created_role.rolename == "bin"
        assert created_role.version == 1

        # 2. Read the role
        read_role = crud.read_role_by_rolename(db_session, "bin")
        assert read_role is not None
        assert read_role.id == created_role.id
        assert read_role.rolename == "bin"

    def test_update_role_to_deactivated(self, db_session):
        # 1. Create a role
        expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        role_create = RSTUFTargetRoleCreate(
            rolename="bin",
            version=1,
            expires=expires,
        )
        created_role = crud.create_roles(db_session, [role_create])[0]
        
        # 2. Update the role to deactivated
        deactivated = crud.update_role_to_deactivated(db_session, created_role)
        assert deactivated.active is False
        
        # Verify in DB
        db_role = crud.read_role_deactivated_by_rolename(db_session, "bin")
        assert db_role is not None
        assert db_role.active is False
        
        # Original should be None because active is False
        assert crud.read_role_by_rolename(db_session, "bin") is None

    def test_create_and_read_file(self, db_session):
        # 1. Create a role
        expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        role_create = RSTUFTargetRoleCreate(
            rolename="bin",
            version=1,
            expires=expires,
        )
        role = crud.create_roles(db_session, [role_create])[0]
        
        # 2. Create file
        target_create = RSTUFTargetFileCreate(
            path="test.txt",
            info={"length": 100},
            published=False,
            action=TargetAction.ADD,
        )
        file_obj = crud.create_file(db_session, target_create, role)
        
        # 3. Read file
        db_file = crud.read_file_by_path(db_session, "test.txt")
        assert db_file is not None
        assert db_file.path == "test.txt"
        assert db_file.targets_role == role.id
        
        # 4. Joint queries
        joint_roles = crud.read_roles_with_unpublished_files(db_session)
        assert joint_roles[0][0] == "bin"

    def test_update_file_actions(self, db_session):
        # Full flow of modifying target files
        role_create = RSTUFTargetRoleCreate(
            rolename="bin",
            version=1,
            expires=datetime.datetime.now(datetime.timezone.utc),
        )
        role = crud.create_roles(db_session, [role_create])[0]
        
        target_create = RSTUFTargetFileCreate(
            path="test.txt",
            info={"length": 100},
            published=False,
            action=TargetAction.ADD,
        )
        file_obj = crud.create_file(db_session, target_create, role)
        
        # Update path and info
        crud.update_file_path_and_info(db_session, file_obj, "new.txt", {"length": 200})
        
        # Verify
        db_file = crud.read_file_by_path(db_session, "new.txt")
        assert db_file is not None
        assert db_file.info == {"length": 200}
        
        # Publish
        crud.update_files_to_published(db_session, ["new.txt"])
        
        # Verify Published
        db_file = crud.read_file_by_path(db_session, "new.txt")
        assert db_file.published is True
        
        # Remove
        crud.update_file_action_to_remove(db_session, db_file)
        
        # Verify Action
        db_file = crud.read_file_by_path(db_session, "new.txt")
        assert db_file.action == TargetAction.REMOVE
        assert db_file.published is False

import logging
import os
from logging.config import fileConfig
from urllib.parse import urlparse

from sqlalchemy import engine_from_config, pool

from alembic import context

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Support RSTUF Worker Container multiple environment variables for SQL
# TODO: Removed deprecated RSTUF_SQL_* environment variables in the future
sql_server = os.getenv("RSTUF_SQL_SERVER")
sql_user = os.getenv("RSTUF_SQL_USER")
sql_password = os.getenv("RSTUF_SQL_PASSWORD")
if sql_server or sql_user or sql_password:
    logging.warning("RSTUF_SQL_* are deprecated. Use RSTUF_DB_* instead.")
db_server = os.getenv("RSTUF_DB_SERVER", sql_server)
db_user = os.getenv("RSTUF_DB_USER", sql_user)
db_password = os.getenv("RSTUF_DB_PASSWORD", sql_password)

if db_server is None:
    raise ValueError("RSTUF_DB_SERVER is required")

# TODO: Remove this warning and default to postgresql://
if "://" not in db_server:
    logging.warning(
        "RSTUF_DB_SERVER does not contain a scheme. "
        "Defaulting to postgresql://"
    )
    db_server = f"postgresql://{db_server}"

uri = urlparse(db_server)

if db_user and db_password is None:
    raise ValueError("RSTUF_DB_PASSWORD is required when using RSTUF_DB_USER")
elif db_user and db_password:
    if db_password.startswith("/run/secrets"):
        with open(db_password) as f:
            db_password = f.read().rstrip("\n")
    sql_server_uri = f"{uri.scheme}://{db_user}:{db_password}@{uri.netloc}"
else:
    sql_server_uri = f"{uri.scheme}:{uri._replace(scheme='').geturl()}"

config.set_main_option("sqlalchemy.url", sql_server_uri)

# Interpret the config file for Python logging.ur
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata
from repository_service_tuf_worker.models.targets import models

target_metadata = models.Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

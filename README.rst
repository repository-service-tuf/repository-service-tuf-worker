#################################
Repository Service for TUF Worker
#################################

.. note::

  This service is in Experimental stage.


|Test Docker Image build| |Tests and Lint| |Coverage|

.. |Test Docker Image build| image:: https://github.com/repository-service-tuf/repository-service-tuf-worker/actions/workflows/test_docker_build.yml/badge.svg
  :target: https://github.com/repository-service-tuf/repository-service-tuf-worker/actions/workflows/test_docker_build.yml
.. |Tests and Lint| image:: https://github.com/repository-service-tuf/repository-service-tuf-worker/actions/workflows/ci.yml/badge.svg
  :target: https://github.com/repository-service-tuf/repository-service-tuf-worker/actions/workflows/ci.yml
.. |Coverage| image:: https://codecov.io/gh/repository-service-tuf/repository-service-tuf-worker/branch/main/graph/badge.svg
  :target: https://codecov.io/gh/repository-service-tuf/repository-service-tuf-worker

Repository Service for TUF Worker is part of `Repository Service for TUF
<https://github.com/repository-service-tuf/repository-service-tuf>`_.


Usage
#####

`Repository Service for TUF Repository Worker Docker Image documentation
<https://repository-service-tuf.readthedocs.io/projects/rstuf-worker/en/latest/guide/Docker_README.html>`_


Development
###########

Requirements
============

- Python >=3.10
- pip
- Pipenv
- Docker

Getting source code
===================

`Fork <https://docs.github.com/en/get-started/quickstart/fork-a-repo>`_ the
repository on `GitHub <https://github.com/repository-service-tuf/repository-service-tuf-worker>`_ and
`clone <https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository>`_
it to your local machine:

.. code-block:: console

    git clone git@github.com:YOUR-USERNAME/repository-service-tuf-worker.git

Add a `remote
<https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/configuring-a-remote-for-a-fork>`_ and
regularly `sync <https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/syncing-a-fork>`_ to make sure
you stay up-to-date with our repository:

.. code-block:: console

    git remote add upstream https://github.com/repository-service-tuf/repository-service-tuf-worker
    git checkout main
    git fetch upstream
    git merge upstream/main


Installing project requirements
===============================

This repository has the ``requirements.txt`` and the ``requirements-dev.txt``
files to help build your virtual environment.

We also recommend using `Pipenv <https://pipenv.pypa.io/en/latest/>`_ to manage
your virtual environment.

.. code:: shell

  $ pip install pipenv
  $ pipenv shell


Install development requirements


.. code:: shell

  $ pipenv install -d


.. note::

    MacOS running on Macbooks M1

    For developers, after above command, run

    .. code:: shell

        $ pip uninstall cryptography cffi -y
        $ pip cache purge
        $ LDFLAGS=-L$(brew --prefix libffi)/lib CFLAGS=-I$(brew --prefix libffi)/include pip install cffi cryptography

Running checks with pre-commit:
===============================

The pre-commit tool is installed as part of the development requirements.

To automatically run checks before you commit your changes you should run:

.. code:: shell

    $ make precommit

This will install the git hook scripts for the first time and
run the ``pre-commit`` tool.
Now ``pre-commit`` will run automatically on ``git commit``.


Running the development Worker locally

.. note::

  All code changes will reload the Worker container automatically.

.. code:: shell

  $ make run-dev

A specific docker compose can be used giving the parameter `DC=<name>`
For example: `docker-compose-redis.yml` use `DC=redis`

.. code:: shell

  $ make run-dev DC=redis

See Makefile for more options

Tests
=====

Unit tests
----------
We use `Tox <ttps://tox.wiki/en/latest/>`_ to manage running the tests.

Running tests

.. code:: shell

  $ tox

You can run specific test from `tox.ini` using `-e`


.. code:: shell

  $ tox -e test

Functional tests
----------------

1. Make sure you have a development environment running (``make run-dev``)

2. Run the FT tests ``make ft-das-local`` or ``make ft-signed-local``


Managing requirements
=====================

Installing new requirements
---------------------------

Project requirements

.. code:: shell

  $ pipenv install {package}


Development requirements

.. code:: shell

  $ pipenv install -d {package}


Updating requirements files from Pipenv
---------------------------------------

.. code:: shell

  $ make requirements


Managing Database migrations
============================

It is required when changing the RSTUF Worker Database Models
`repository_service_tuf_worker/models/`

Updating the models requires a database migrations with Alembic.

Use a clear update message with `M="Added field XYZ for Targets"`

.. code:: shell

  $ make db-migration M="update message"
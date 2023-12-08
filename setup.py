#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

from setuptools import find_packages, setup
from repository_service_tuf_worker.__version__ import version

setup(
    name="repository-service-tuf-worker",
    version=version,
    url="https://github.com/repository-service-tuf/repository-service-tuf-worker",  # noqa
    author="Kairo de Araujo",
    author_email="kairo@dearaujo.nl",
    description="Repository Service for TUF Worker",
    packages=find_packages(),
    install_requires=["celery"],
)

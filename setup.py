#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

from setuptools import find_packages, setup

setup(
    name="repository-service-tuf-worker",
    version="0.0.1",
    url="https://github.com/repository-service-tuf/repository-service-tuf-worker",  # noqa
    author="Kairo de Araujo",
    author_email="kairo@dearaujo.nl",
    description="Repository Service for TUF Worker",
    packages=find_packages(),
    install_requires=["celery"],
)

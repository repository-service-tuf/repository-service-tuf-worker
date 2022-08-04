#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2022 Kairo de Araujo. All Rights Reserved.
from setuptools import find_packages, setup

setup(
    name="kaprien-repo-worker",
    version="0.0.1",
    url="https://github.com/kaprien/kaprien-repo-worker",
    author="Kairo de Araujo",
    author_email="kairo@dearaujo.nl",
    description="Kaprien Repository Worker",
    packages=find_packages(),
    install_requires=["celery"],
)

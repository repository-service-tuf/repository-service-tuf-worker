# SPDX-FileCopyrightText: 2023-2026 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

from repository_service_tuf_worker.__version__ import author, copyright, version


def test_version():
    assert isinstance(version, str)
    assert isinstance(copyright, str)
    assert isinstance(author, str)

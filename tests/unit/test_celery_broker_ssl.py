# SPDX-FileCopyrightText: 2025-2026 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import json
import ssl

import pytest

from repository_service_tuf_worker.celery_broker_ssl import build_broker_use_ssl


class _Settings:
    def __init__(self, data):
        self._data = data

    def get(self, key, default=None):
        return self._data.get(key, default)


def test_build_broker_use_ssl_disabled_by_default():
    assert build_broker_use_ssl(_Settings({})) is None


@pytest.mark.parametrize("flag", ("true", "1", "yes", "on", True))
def test_build_broker_use_ssl_minimal(flag):
    result = build_broker_use_ssl(_Settings({"BROKER_USE_SSL": flag}))
    assert result == {"cert_reqs": ssl.CERT_REQUIRED}


def test_build_broker_use_ssl_cert_reqs_optional():
    result = build_broker_use_ssl(
        _Settings({"BROKER_USE_SSL": True, "BROKER_SSL_CERT_REQS": "optional"})
    )
    assert result == {"cert_reqs": ssl.CERT_OPTIONAL}


def test_build_broker_use_ssl_cert_reqs_none():
    result = build_broker_use_ssl(
        _Settings({"BROKER_USE_SSL": True, "BROKER_SSL_CERT_REQS": "none"})
    )
    assert result == {"cert_reqs": ssl.CERT_NONE}


def test_build_broker_use_ssl_invalid_cert_reqs():
    with pytest.raises(ValueError, match="Invalid BROKER_SSL_CERT_REQS"):
        build_broker_use_ssl(
            _Settings({"BROKER_USE_SSL": True, "BROKER_SSL_CERT_REQS": "bogus"})
        )


def test_build_broker_use_ssl_with_key_and_cert(tmp_path):
    key = tmp_path / "k.pem"
    cert = tmp_path / "c.pem"
    ca = tmp_path / "ca.pem"
    key.write_text("k")
    cert.write_text("c")
    ca.write_text("ca")
    result = build_broker_use_ssl(
        _Settings(
            {
                "BROKER_USE_SSL": True,
                "BROKER_SSL_KEYFILE": str(key),
                "BROKER_SSL_CERTFILE": str(cert),
                "BROKER_SSL_CA_CERTS": str(ca),
            }
        )
    )
    assert result["cert_reqs"] == ssl.CERT_REQUIRED
    assert result["keyfile"] == str(key)
    assert result["certfile"] == str(cert)
    assert result["ca_certs"] == str(ca)


def test_build_broker_use_ssl_missing_keyfile(tmp_path):
    cert = tmp_path / "c.pem"
    cert.write_text("c")
    with pytest.raises(ValueError, match="not a readable file"):
        build_broker_use_ssl(
            _Settings(
                {
                    "BROKER_USE_SSL": True,
                    "BROKER_SSL_KEYFILE": str(tmp_path / "missing.pem"),
                    "BROKER_SSL_CERTFILE": str(cert),
                }
            )
        )


def test_build_broker_use_ssl_options_json_string():
    payload = json.dumps(
        {"cert_reqs": "none", "ca_certs": "/does/not/exist"}
    )
    # Paths in JSON are not validated by build_broker_use_ssl for OPTIONS
    result = build_broker_use_ssl(_Settings({"BROKER_SSL_OPTIONS": payload}))
    assert result["cert_reqs"] == ssl.CERT_NONE
    assert result["ca_certs"] == "/does/not/exist"


def test_build_broker_use_ssl_options_dict():
    result = build_broker_use_ssl(
        _Settings(
            {
                "BROKER_SSL_OPTIONS": {"cert_reqs": "required"},
                "BROKER_USE_SSL": False,
            }
        )
    )
    assert result == {"cert_reqs": ssl.CERT_REQUIRED}


def test_build_broker_use_ssl_options_invalid_json():
    with pytest.raises(ValueError, match="valid JSON"):
        build_broker_use_ssl(_Settings({"BROKER_SSL_OPTIONS": "not-json"}))


def test_build_broker_use_ssl_options_not_object():
    with pytest.raises(ValueError, match="JSON object"):
        build_broker_use_ssl(_Settings({"BROKER_SSL_OPTIONS": "[1,2]"}))


def test_build_broker_use_ssl_options_takes_precedence_over_use_ssl(tmp_path):
    """Explicit JSON options win; BROKER_USE_SSL is ignored when OPTIONS set."""
    ca = tmp_path / "ca.pem"
    ca.write_text("ca")
    raw = json.dumps({"cert_reqs": "none", "ca_certs": str(ca)})
    result = build_broker_use_ssl(
        _Settings(
            {
                "BROKER_SSL_OPTIONS": raw,
                "BROKER_USE_SSL": True,
                "BROKER_SSL_CERT_REQS": "required",
            }
        )
    )
    assert result["cert_reqs"] == ssl.CERT_NONE
    assert result["ca_certs"] == str(ca)

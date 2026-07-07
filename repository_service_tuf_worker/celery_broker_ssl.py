# SPDX-FileCopyrightText: 2025-2026 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

"""Celery AMQP broker TLS options from worker settings (``RSTUF_*`` env)."""

from __future__ import annotations

import json
import os
import ssl
from typing import Any, Dict, Optional

_CERT_REQS_BY_NAME: Dict[str, int] = {
    "required": ssl.CERT_REQUIRED,
    "optional": ssl.CERT_OPTIONAL,
    "none": ssl.CERT_NONE,
}


def _truthy(value: Any) -> bool:
    if value is True:
        return True
    if value is False or value is None:
        return False
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def _parse_cert_reqs(value: Any) -> int:
    if isinstance(value, int):
        if value in (ssl.CERT_NONE, ssl.CERT_OPTIONAL, ssl.CERT_REQUIRED):
            return value
        raise ValueError(
            f"Invalid BROKER_SSL_CERT_REQS integer: {value!r} "
            "(use ssl.CERT_* values or a string name)"
        )
    if value is None:
        return ssl.CERT_REQUIRED
    name = str(value).strip().lower()
    if name not in _CERT_REQS_BY_NAME:
        allowed = ", ".join(sorted(_CERT_REQS_BY_NAME))
        raise ValueError(
            f"Invalid BROKER_SSL_CERT_REQS {value!r}; use one of: {allowed}"
        )
    return _CERT_REQS_BY_NAME[name]


def _normalize_ssl_dict(opts: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy with ``cert_reqs`` as an ``ssl.CERT_*`` int if present."""
    out = dict(opts)
    if "cert_reqs" in out:
        out["cert_reqs"] = _parse_cert_reqs(out["cert_reqs"])
    return out


def _existing_file_path(label: str, path: str) -> str:
    expanded = os.path.expanduser(path.strip())
    if not os.path.isfile(expanded):
        raise ValueError(f"{label} is not a readable file: {path!r}")
    return expanded


def build_broker_use_ssl(settings: Any) -> Optional[Dict[str, Any]]:
    """Build Celery ``broker_use_ssl`` from Dynaconf worker settings.

    Precedence:

    1. ``BROKER_SSL_OPTIONS`` — JSON object (or dict) merged as-is after
       normalizing ``cert_reqs`` strings. Enables TLS without requiring
       ``BROKER_USE_SSL``.
    2. Else if ``BROKER_USE_SSL`` is truthy — build a dict from
       ``BROKER_SSL_KEYFILE``, ``BROKER_SSL_CERTFILE``, ``BROKER_SSL_CA_CERTS``,
       and ``BROKER_SSL_CERT_REQS`` (default ``required``).

    Env vars use the ``RSTUF_`` prefix (e.g. ``RSTUF_BROKER_USE_SSL``).

    Returns:
        A dict for Celery's ``broker_use_ssl``, or ``None`` when TLS is off.

    Raises:
        ValueError: invalid JSON, unknown ``cert_reqs``, or missing SSL file.
    """
    raw_options = settings.get("BROKER_SSL_OPTIONS")
    if raw_options not in (None, "", {}):
        if isinstance(raw_options, dict):
            opts = raw_options
        else:
            try:
                opts = json.loads(str(raw_options))
            except json.JSONDecodeError as e:
                raise ValueError(
                    f"BROKER_SSL_OPTIONS must be valid JSON object: {e}"
                ) from e
        if not isinstance(opts, dict):
            raise ValueError("BROKER_SSL_OPTIONS must be a JSON object")
        return _normalize_ssl_dict(opts)

    if not _truthy(settings.get("BROKER_USE_SSL")):
        return None

    ssl_dict: Dict[str, Any] = {}
    cert_reqs = _parse_cert_reqs(settings.get("BROKER_SSL_CERT_REQS"))
    ssl_dict["cert_reqs"] = cert_reqs

    keyfile = settings.get("BROKER_SSL_KEYFILE")
    certfile = settings.get("BROKER_SSL_CERTFILE")
    ca_certs = settings.get("BROKER_SSL_CA_CERTS")

    if keyfile:
        ssl_dict["keyfile"] = _existing_file_path("BROKER_SSL_KEYFILE", keyfile)
    if certfile:
        ssl_dict["certfile"] = _existing_file_path(
            "BROKER_SSL_CERTFILE", certfile
        )
    if ca_certs:
        ssl_dict["ca_certs"] = _existing_file_path(
            "BROKER_SSL_CA_CERTS", ca_certs
        )

    return ssl_dict

AWS KMS online keys (worker)
############################

The worker loads signers from ``x-rstuf-online-key-uri`` on each key via
:class:`~repository_service_tuf_worker.signer.SignerStore`, which calls
``securesystemslib`` ``Signer.from_priv_key_uri`` inside an isolated process
environment.

Canonical KMS URIs (``securesystemslib``) use the ``awskms:`` scheme, for example:

* ``awskms:alias/my-key``
* ``awskms:arn:aws:kms:us-east-1:123456789012:key/uuid``

The worker also registers an ``aws-kms`` alias so the same logical key id can be
written with ``aws-kms:`` or ``aws-kms://`` forms; see
:func:`repository_service_tuf_worker.signer.normalize_aws_kms_priv_key_uri`.

Worker / Dynaconf settings passed into the signer environment (when set) include:

* ``AWS_ACCESS_KEY_ID``, ``AWS_SECRET_ACCESS_KEY``, ``AWS_SESSION_TOKEN``
* ``AWS_DEFAULT_REGION``
* ``AWS_ENDPOINT_URL`` (optional; useful for LocalStack in tests)

With the usual ``RSTUF_`` env prefix, set e.g. ``RSTUF_AWS_ACCESS_KEY_ID`` so
Dynaconf exposes ``AWS_ACCESS_KEY_ID`` to the worker.

One-off key import (ceremony / tooling) can use ``AWSSigner.import_`` from
``securesystemslib`` to obtain the stored URI and public key material; the
returned URI uses the ``awskms:`` prefix.

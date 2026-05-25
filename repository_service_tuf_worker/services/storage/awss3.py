# SPDX-FileCopyrightText: 2023 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import logging
import time
from io import BytesIO
from typing import Any, Dict, List, Optional

import awswrangler
import boto3
from botocore.exceptions import ClientError
from securesystemslib.exceptions import StorageError  # noqa
from tuf.api.metadata import Metadata, T, Timestamp
from tuf.api.serialization import DeserializationError

from repository_service_tuf_worker import parse_if_secret
from repository_service_tuf_worker.interfaces import (
    Dynaconf,
    IStorage,
    ServiceSettings,
)


class AWSS3(IStorage):
    # In-process version cache: role_name -> latest known version number.
    #
    # AWSS3.get() needs to resolve the latest version of a role before it can
    # fetch it from S3.  The original implementation called
    # awswrangler.s3.list_objects(path="s3://bucket/*.{role}.json") on every
    # call, which cannot use an S3 key-prefix scan and instead lists all
    # objects in the bucket client-side.  At ~5 000+ objects that took 2.5–4 s
    # per call; with 9+ calls per task it dominated task latency (~27 s of
    # ~33 s total).
    #
    # The fix has two parts:
    #
    # 1. Pre-warmup (_prewarm_version_cache): called once per worker process
    #    from configure() at startup.  Lists the entire bucket a single time,
    #    parses every "N.rolename.json" filename, and stores the max version
    #    seen for each role.  This runs before the first task arrives so there
    #    is no cold-start penalty.
    #
    # 2. Cache maintenance: get() reads from the cache (skipping list_objects
    #    entirely after warmup); put() updates the cache after every write so
    #    the next get() fetches the correct version key directly.
    #
    # The cache is per-worker-process.  Celery ForkPoolWorkers each get their
    # own copy after fork, independently pre-warmed.  A worker restart triggers
    # a fresh prewarm (~4 s) before accepting tasks.
    _version_cache: Dict[str, int] = {}
    _cache_warmed: bool = False

    def __init__(
        self,
        bucket: str,
        s3_session: boto3.Session,
        s3_client: Any,
        s3_resource: Any,
        s3_object_acl: Optional[str] = None,
        region: Optional[str] = None,
        endpoint_url: Optional[str] = None,
    ) -> None:
        self._bucket: str = bucket
        self._region: Optional[str] = region
        self._endpoint_url: Optional[str] = endpoint_url
        self._s3_session = s3_session
        self._s3_client = s3_client
        self._s3_resource = s3_resource
        self._s3_object_acl = s3_object_acl or "public-read"

    @classmethod
    def configure(cls, settings: Dynaconf) -> "AWSS3":
        access_key = parse_if_secret(settings.AWS_ACCESS_KEY_ID)
        secret_access_key = parse_if_secret(settings.AWS_SECRET_ACCESS_KEY)
        region = settings.get("AWS_DEFAULT_REGION")
        endpoint = settings.get("AWS_ENDPOINT_URL")
        object_acl = settings.get("AWS_S3_OBJECT_ACL")

        s3_session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_access_key,
            region_name=region,
        )
        s3_resource = s3_session.resource(
            "s3",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_access_key,
            region_name=region,
            endpoint_url=endpoint,
        )
        buckets = [bucket.name for bucket in s3_resource.buckets.all()]
        bucket_name = settings.AWS_STORAGE_BUCKET
        if bucket_name not in buckets:
            raise ValueError(f"Bucket '{bucket_name}' not found.")

        s3_client = s3_session.client(
            "s3",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_access_key,
            region_name=region,
            endpoint_url=endpoint,
        )

        instance = cls(
            bucket_name,
            s3_session,
            s3_client,
            s3_resource,
            object_acl,
            region,
            endpoint,
        )
        cls._prewarm_version_cache(bucket_name, s3_session)
        return instance

    @classmethod
    def settings(cls) -> List[ServiceSettings]:
        return [
            ServiceSettings(
                names=["AWS_STORAGE_BUCKET"],
                required=True,
            ),
            ServiceSettings(
                names=["AWS_ACCESS_KEY_ID"],
                required=True,
            ),
            ServiceSettings(
                names=["AWS_SECRET_ACCESS_KEY"],
                required=True,
            ),
            ServiceSettings(
                names=["AWS_DEFAULT_REGION"],
                required=False,
            ),
            ServiceSettings(
                names=["AWS_ENDPOINT_URL"],
                required=False,
            ),
            ServiceSettings(
                names=["AWS_S3_OBJECT_ACL"],
                required=False,
            ),
        ]

    @classmethod
    def _prewarm_version_cache(
        cls, bucket: str, s3_session: boto3.Session
    ) -> None:
        """
        Populate _version_cache with a single list_objects call at worker
        startup.  Scans all objects in the bucket once, parses every
        "N.rolename.json" filename, and records the highest version seen for
        each role.  Subsequent get() calls skip list_objects entirely.

        Guarded by _cache_warmed so it runs at most once per worker process
        even if configure() is called multiple times.
        """
        if cls._cache_warmed:
            return
        t0 = time.perf_counter()
        try:
            all_keys = awswrangler.s3.list_objects(
                path=f"s3://{bucket}/",
                boto3_session=s3_session,
            )
        except Exception as e:
            logging.warning("S3 version cache prewarm failed, skipping: %s", e)
            return
        prefix = f"s3://{bucket}/"
        for s3_uri in all_keys:
            filename = s3_uri[len(prefix):]
            parts = filename.split(".", 1)
            if (
                len(parts) == 2
                and parts[0].isdigit()
                and filename.endswith(".json")
            ):
                role_name = parts[1][:-5]  # strip ".json"
                version = int(parts[0])
                if version > cls._version_cache.get(role_name, 0):
                    cls._version_cache[role_name] = version
        cls._cache_warmed = True
        logging.info(
            "S3 version cache warmed: %d roles, %d objects scanned (%.2fs)",
            len(cls._version_cache),
            len(all_keys),
            time.perf_counter() - t0,
        )

    def get(self, role: str, version: Optional[int] = None) -> Metadata[T]:
        """
        Returns TUF role metadata object for the passed role name,
        optionally at the passed version (latest if None).
        """
        if self._endpoint_url is not None:
            awswrangler.config.s3_endpoint_url = self._endpoint_url

        if role == Timestamp.type:
            filename = f"{role}.json"
        else:
            if version is None:
                cached_version = AWSS3._version_cache.get(role)
                if cached_version is not None:
                    version = cached_version
                else:
                    # Cache miss (role not yet seen by this worker process).
                    # Scan the bucket once for this role and cache the result.
                    s3_path = f"s3://{self._bucket}/"
                    filenames = awswrangler.s3.list_objects(
                        path=f"{s3_path}*.{role}.json",
                        boto3_session=self._s3_session,
                    )
                    versions = [
                        int(name.split(s3_path)[-1].split(".", 1)[0])
                        for name in filenames
                    ]
                    try:
                        version = max(versions)
                    except ValueError:
                        version = 1
                    AWSS3._version_cache[role] = version

            filename = f"{version}.{role}.json"

        file_object = BytesIO()
        try:
            s3_object = self._s3_client.get_object(
                Bucket=self._bucket, Key=filename
            )
            file_object = s3_object.get("Body")
            return Metadata.from_bytes(file_object.read())
        except (DeserializationError, ClientError) as e:
            if "NoSuchKey" in str(e):
                raise StorageError(f"Role '{role}' not found") from e
            raise StorageError(f"Can't open Role '{role}'") from e
        finally:
            if file_object is not None:
                file_object.close()

    def put(
        self,
        data: bytes,
        filename: str,
    ) -> None:
        """
        Writes passed file object to configured TUF S3 bucked.
        """
        try:
            self._s3_client.put_object(
                Body=data,
                Bucket=self._bucket,
                Key=filename,
                ACL=self._s3_object_acl,
            )
        except ClientError:
            raise StorageError(f"Can't write role file '{filename}'")

        # Keep the version cache consistent: after writing "N.rolename.json",
        # record N so the next get() for this role fetches it directly without
        # calling list_objects.  Timestamp uses a fixed key ("timestamp.json")
        # and is not version-tracked in the cache.
        parts = filename.split(".", 1)
        if parts[0].isdigit():
            role_name = parts[1][:-5]  # strip ".json"
            AWSS3._version_cache[role_name] = int(parts[0])

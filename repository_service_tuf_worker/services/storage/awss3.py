# SPDX-FileCopyrightText: 2023 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

from io import BytesIO
from typing import Any, List, Optional

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
    def __init__(
        self,
        bucket: str,
        s3_session: boto3.Session,
        s3_client: Any,
        s3_resource: Any,
        region: Optional[str] = None,
        endpoint_url: Optional[str] = None,
    ) -> None:
        self._bucket: str = bucket
        self._region: Optional[str] = region
        self._endpoint_url: Optional[str] = endpoint_url
        self._s3_session = s3_session
        self._s3_client = s3_client
        self._s3_resource = s3_resource

    @classmethod
    def configure(cls, settings: Dynaconf) -> "AWSS3":
        access_key = parse_if_secret(settings.AWS_ACCESS_KEY_ID)
        secret_access_key = parse_if_secret(settings.AWS_SECRET_ACCESS_KEY)
        region = settings.get("AWS_DEFAULT_REGION")
        endpoint = settings.get("AWS_ENDPOINT_URL")

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

        return cls(
            bucket_name, s3_session, s3_client, s3_resource, region, endpoint
        )

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
        ]

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
                Body=data, Bucket=self._bucket, Key=filename
            )
        except ClientError:
            raise StorageError(f"Can't write role file '{filename}'")

# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

from io import BytesIO
from typing import List, Optional

import awswrangler
import boto3
from botocore.exceptions import ClientError
from securesystemslib.exceptions import StorageError  # noqa
from tuf.api.metadata import Metadata, T, Timestamp
from tuf.api.serialization import DeserializationError

from repository_service_tuf_worker import parse_if_secret
from repository_service_tuf_worker.interfaces import IStorage, ServiceSettings


class AWSS3(IStorage):
    def __init__(
        self,
        bucket: str,
        access_key: str,
        secret_key: str,
        region: Optional[str] = None,
        endpoint_url: Optional[str] = None,
    ) -> None:
        self._access_key: str = parse_if_secret(access_key)
        self._secret_key: str = parse_if_secret(secret_key)
        self._bucket: str = bucket
        self._region: Optional[str] = region
        self._endpoint_url: Optional[str] = endpoint_url

        self._s3_session = boto3.Session(
            aws_access_key_id=self._access_key,
            aws_secret_access_key=self._secret_key,
            region_name=self._region,
        )

        self._s3 = self._s3_session.client(
            "s3",
            aws_access_key_id=self._access_key,
            aws_secret_access_key=self._secret_key,
            region_name=self._region,
            endpoint_url=self._endpoint_url,
        )

        self._s3_resource = self._s3_session.resource(
            "s3",
            aws_access_key_id=self._access_key,
            aws_secret_access_key=self._secret_key,
            region_name=self._region,
            endpoint_url=self._endpoint_url,
        )

    @classmethod
    def configure(cls, settings) -> None:
        aws_access_key_id = settings.AWSS3_STORAGE_ACCESS_KEY
        aws_secret_access_key = settings.AWSS3_STORAGE_SECRET_KEY
        region_name = settings.get("AWSS3_STORAGE_REGION")
        endpoint_url = settings.get("AWSS3_STORAGE_ENDPOINT_URL")
        s3_resource = boto3.resource(
            "s3",
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=region_name,
            endpoint_url=endpoint_url,
        )
        buckets = [bucket.name for bucket in s3_resource.buckets.all()]
        if settings.AWSS3_STORAGE_BUCKET not in buckets:
            raise ValueError(
                f"Bucket '{settings.AWSS3_STORAGE_BUCKET}' not found."
            )

    @classmethod
    def settings(cls) -> List[ServiceSettings]:
        return [
            ServiceSettings(
                names=["AWSS3_STORAGE_BUCKET"],
                argument="bucket",
                required=True,
            ),
            ServiceSettings(
                names=["AWSS3_STORAGE_ACCESS_KEY"],
                argument="access_key",
                required=True,
            ),
            ServiceSettings(
                names=["AWSS3_STORAGE_SECRET_KEY"],
                argument="secret_key",
                required=True,
            ),
            ServiceSettings(
                names=["AWSS3_STORAGE_REGION"],
                argument="region",
                required=False,
            ),
            ServiceSettings(
                names=["AWSS3_STORAGE_ENDPOINT_URL"],
                argument="endpoint_url",
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
            s3_object = self._s3.get_object(Bucket=self._bucket, Key=filename)
            file_object = s3_object.get("Body")
            return Metadata.from_bytes(file_object.read())
        except DeserializationError as e:
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
            self._s3.put_object(Body=data, Bucket=self._bucket, Key=filename)
        except ClientError:
            raise StorageError(f"Can't write role file '{filename}'")

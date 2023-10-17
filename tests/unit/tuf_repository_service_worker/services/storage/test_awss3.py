# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import pretend
import pytest
from tuf.api.metadata import Metadata, Optional, Root, Timestamp

from repository_service_tuf_worker.services.storage import awss3


class TestAWSS3Service:
    def test_basic_init(self, mocked_boto3):
        service = awss3.AWSS3(
            "bucket",
            "session",
            "client",
            "resource",
        )

        assert service._bucket == "bucket"
        assert service._s3_session == "session"
        assert service._s3_client == "client"
        assert service._s3_resource == "resource"
        assert service._region is None
        assert service._endpoint_url is None

    def test_full_init(self, mocked_boto3):
        service = awss3.AWSS3(
            "bucket",
            "session",
            "client",
            "resource",
            "region",
            "http://localstack:4566",
        )

        assert service._bucket == "bucket"
        assert service._s3_session == "session"
        assert service._s3_client == "client"
        assert service._s3_resource == "resource"
        assert service._region == "region"
        assert service._endpoint_url == "http://localstack:4566"

    def test_configure(self, mocked_boto3):
        test_settings = pretend.stub(
            get=pretend.call_recorder(lambda *a: None),
            AWSS3_STORAGE_BUCKET="bucket",
            AWSS3_STORAGE_ACCESS_KEY="access_key",
            AWSS3_STORAGE_SECRET_KEY="secret_key",
        )

        service = awss3.AWSS3.configure(test_settings)
        assert awss3.boto3.Session.calls == [
            pretend.call(
                aws_access_key_id="access_key",
                aws_secret_access_key="secret_key",
                region_name=None,
            )
        ]
        assert service._s3_session.resource.calls == [
            pretend.call(
                "s3",
                aws_access_key_id="access_key",
                aws_secret_access_key="secret_key",
                region_name=service._region,
                endpoint_url=service._endpoint_url,
            )
        ]
        assert service._s3_session.client.calls == [
            pretend.call(
                "s3",
                aws_access_key_id="access_key",
                aws_secret_access_key="secret_key",
                region_name=service._region,
                endpoint_url=service._endpoint_url,
            )
        ]
        assert awss3.boto3.Session().resource().buckets.all.calls == [
            pretend.call()
        ]
        # By using awss3.boto3 functions we can access the internal objects
        # mocked in mocked_boto3.
        assert service._bucket == "bucket"
        assert service._s3_session == awss3.boto3.Session()
        assert service._s3_client == awss3.boto3.Session().client()
        assert service._s3_resource == awss3.boto3.Session().resource()
        assert service._region is None
        assert service._endpoint_url is None

    def test_configure_bucket_not_found(self, mocked_boto3):
        def _fake_get(key: str) -> Optional[str]:
            if key == "AWSS3_STORAGE_REGION":
                return "region"
            return None

        test_settings = pretend.stub(
            get=pretend.call_recorder(lambda a: _fake_get(a)),
            AWSS3_STORAGE_BUCKET="nonexistent-bucket",
            AWSS3_STORAGE_ACCESS_KEY="access_key",
            AWSS3_STORAGE_SECRET_KEY="secret_key",
        )

        service = None
        with pytest.raises(ValueError) as err:
            service = awss3.AWSS3.configure(test_settings)

        assert "Bucket 'nonexistent-bucket' not found." in str(err)
        assert service is None
        assert awss3.boto3.resource().buckets.all.calls == [pretend.call()]
        assert awss3.boto3.Session.calls == [
            pretend.call(
                aws_access_key_id="access_key",
                aws_secret_access_key="secret_key",
                region_name="region",
            )
        ]
        assert awss3.boto3.Session().resource.calls == [
            pretend.call(
                "s3",
                aws_access_key_id="access_key",
                aws_secret_access_key="secret_key",
                region_name="region",
                endpoint_url=None,
            )
        ]

    def test_settings(self, mocked_boto3):
        service_settings = awss3.AWSS3.settings()

        assert service_settings == [
            awss3.ServiceSettings(
                names=["AWSS3_STORAGE_BUCKET"],
                required=True,
            ),
            awss3.ServiceSettings(
                names=["AWSS3_STORAGE_ACCESS_KEY"],
                required=True,
            ),
            awss3.ServiceSettings(
                names=["AWSS3_STORAGE_SECRET_KEY"],
                required=True,
            ),
            awss3.ServiceSettings(
                names=["AWSS3_STORAGE_REGION"],
                required=False,
            ),
            awss3.ServiceSettings(
                names=["AWSS3_STORAGE_ENDPOINT_URL"],
                required=False,
            ),
        ]

    def test_get(self, mocked_boto3):
        service = awss3.AWSS3(
            "bucket",
            "session",
            "client",
            "resource",
        )
        awss3.awswrangler.s3.list_objects = pretend.call_recorder(
            lambda *a, **kw: [
                f"s3://{service._bucket}/1.root.json",
                f"s3://{service._bucket}/2.root.json",
            ]
        )
        fake_file_obj = pretend.stub(
            read=pretend.call_recorder(lambda: None),
            close=pretend.call_recorder(lambda: None),
        )
        fake_aws3_object = pretend.stub(
            get=pretend.call_recorder(lambda *a: fake_file_obj)
        )
        service._s3_client = pretend.stub(
            get_object=pretend.call_recorder(lambda *a, **kw: fake_aws3_object)
        )

        expected_root = Metadata(Root())
        awss3.Metadata = pretend.stub(
            from_bytes=pretend.call_recorder(lambda *a: expected_root)
        )
        result = service.get("root")

        assert result == expected_root
        assert fake_file_obj.read.calls == [pretend.call()]
        assert fake_file_obj.close.calls == [pretend.call()]
        assert fake_aws3_object.get.calls == [pretend.call("Body")]
        assert awss3.Metadata.from_bytes.calls == [pretend.call(None)]
        assert awss3.awswrangler.s3.list_objects.calls == [
            pretend.call(
                path=f"s3://{service._bucket}/*.root.json",
                boto3_session=service._s3_session,
            )
        ]
        assert service._s3_client.get_object.calls == [
            pretend.call(Bucket=service._bucket, Key="2.root.json")
        ]

    def test_get_endpoint_url_not_none(self, mocked_boto3):
        service = awss3.AWSS3(
            "bucket",
            "session",
            "client",
            "resource",
            "region",
            "http://localstack",
        )
        awss3.awswrangler.s3.list_objects = pretend.call_recorder(
            lambda *a, **kw: [
                f"s3://{service._bucket}/1.root.json",
                f"s3://{service._bucket}/2.root.json",
            ]
        )
        fake_file_obj = pretend.stub(
            read=pretend.call_recorder(lambda: None),
            close=pretend.call_recorder(lambda: None),
        )
        fake_aws3_object = pretend.stub(
            get=pretend.call_recorder(lambda *a: fake_file_obj)
        )
        service._s3_client = pretend.stub(
            get_object=pretend.call_recorder(lambda *a, **kw: fake_aws3_object)
        )

        expected_root = Metadata(Root())
        awss3.Metadata = pretend.stub(
            from_bytes=pretend.call_recorder(lambda *a: expected_root)
        )
        result = service.get("root")

        assert result == expected_root
        assert awss3.awswrangler.config.s3_endpoint_url == "http://localstack"
        assert fake_file_obj.read.calls == [pretend.call()]
        assert fake_file_obj.close.calls == [pretend.call()]
        assert fake_aws3_object.get.calls == [pretend.call("Body")]
        assert awss3.Metadata.from_bytes.calls == [pretend.call(None)]
        assert awss3.awswrangler.s3.list_objects.calls == [
            pretend.call(
                path=f"s3://{service._bucket}/*.root.json",
                boto3_session=service._s3_session,
            )
        ]
        assert service._s3_client.get_object.calls == [
            pretend.call(Bucket=service._bucket, Key="2.root.json")
        ]

    def test_get_timestamp(self, mocked_boto3):
        service = awss3.AWSS3(
            "bucket",
            "session",
            "client",
            "resource",
            "region",
            "http://localstack:4566",
        )

        awss3.awswrangler.s3.list_objects = pretend.call_recorder(
            lambda *a, **kw: [
                f"s3://{service._bucket}/1.root.json",
                f"s3://{service._bucket}/2.root.json",
            ]
        )
        fake_file_obj = pretend.stub(
            read=pretend.call_recorder(lambda: None),
            close=pretend.call_recorder(lambda: None),
        )
        fake_aws3_object = pretend.stub(
            get=pretend.call_recorder(lambda *a: fake_file_obj)
        )
        service._s3_client = pretend.stub(
            get_object=pretend.call_recorder(lambda *a, **kw: fake_aws3_object)
        )
        expected_timestamp = Metadata(Timestamp())
        awss3.Metadata = pretend.stub(
            from_bytes=pretend.call_recorder(lambda *a: expected_timestamp)
        )
        result = service.get("timestamp")

        assert result == expected_timestamp
        assert fake_file_obj.read.calls == [pretend.call()]
        assert fake_file_obj.close.calls == [pretend.call()]
        assert fake_aws3_object.get.calls == [pretend.call("Body")]
        assert awss3.Metadata.from_bytes.calls == [pretend.call(None)]
        assert awss3.awswrangler.s3.list_objects.calls == []
        assert service._s3_client.get_object.calls == [
            pretend.call(Bucket=service._bucket, Key="timestamp.json")
        ]

    def test_get_max_version_ValueError(self, mocked_boto3, monkeypatch):
        service = awss3.AWSS3(
            "bucket",
            "session",
            "client",
            "resource",
            "region",
            "http://localstack:4566",
        )

        awss3.awswrangler.s3.list_objects = pretend.call_recorder(
            lambda *a, **kw: [
                f"s3://{service._bucket}/1.root.json",
            ]
        )
        fake_file_obj = pretend.stub(
            read=pretend.call_recorder(lambda: None),
            close=pretend.call_recorder(lambda: None),
        )
        fake_aws3_object = pretend.stub(
            get=pretend.call_recorder(lambda *a: fake_file_obj)
        )
        service._s3_client = pretend.stub(
            get_object=pretend.call_recorder(lambda *a, **kw: fake_aws3_object)
        )
        monkeypatch.setitem(
            awss3.__builtins__, "max", pretend.raiser(ValueError)
        )
        expected_root = Metadata(Root())
        awss3.Metadata = pretend.stub(
            from_bytes=pretend.call_recorder(lambda *a: expected_root)
        )
        result = service.get("root")

        assert result == expected_root
        assert fake_file_obj.read.calls == [pretend.call()]
        assert fake_file_obj.close.calls == [pretend.call()]
        assert awss3.Metadata.from_bytes.calls == [pretend.call(None)]
        assert awss3.awswrangler.s3.list_objects.calls == [
            pretend.call(
                path=f"s3://{service._bucket}/*.root.json",
                boto3_session=service._s3_session,
            )
        ]
        assert service._s3_client.get_object.calls == [
            pretend.call(Bucket=service._bucket, Key="1.root.json")
        ]

    def test_get_DeserializationError(self, mocked_boto3):
        service = awss3.AWSS3(
            "bucket",
            "session",
            "client",
            "resource",
            "region",
            "http://localstack:4566",
        )

        awss3.awswrangler.s3.list_objects = pretend.call_recorder(
            lambda *a, **kw: [
                f"s3://{service._bucket}/1.root.json",
            ]
        )
        fake_file_obj = pretend.stub(
            read=pretend.call_recorder(lambda: None),
            close=pretend.call_recorder(lambda: None),
        )
        fake_aws3_object = pretend.stub(
            get=pretend.call_recorder(lambda *a: fake_file_obj)
        )
        service._s3_client = pretend.stub(
            get_object=pretend.call_recorder(lambda *a, **kw: fake_aws3_object)
        )
        awss3.Metadata = pretend.stub(
            from_bytes=pretend.raiser(awss3.DeserializationError("failed"))
        )

        with pytest.raises(awss3.StorageError) as err:
            service.get("root")

        assert "Can't open Role 'root'" in str(err)

        assert fake_file_obj.read.calls == [pretend.call()]
        assert fake_file_obj.close.calls == [pretend.call()]
        assert awss3.awswrangler.s3.list_objects.calls == [
            pretend.call(
                path=f"s3://{service._bucket}/*.root.json",
                boto3_session=service._s3_session,
            )
        ]
        assert service._s3_client.get_object.calls == [
            pretend.call(Bucket=service._bucket, Key="1.root.json")
        ]

    def test_put(self, mocked_boto3):
        test_settings = pretend.stub(
            get=pretend.call_recorder(lambda *a: None),
            AWSS3_STORAGE_BUCKET="bucket",
            AWSS3_STORAGE_ACCESS_KEY="access_key",
            AWSS3_STORAGE_SECRET_KEY="secret_key",
        )

        service = awss3.AWSS3.configure(test_settings)

        fake_file_data = b"fake_byte_data"
        result = service.put(fake_file_data, "3.bin-e.json")

        assert result is None
        assert service._s3_client.put_object.calls == [
            pretend.call(
                Body=fake_file_data, Bucket=service._bucket, Key="3.bin-e.json"
            )
        ]

    def test_put_ClientErro(self, mocked_boto3):
        test_settings = pretend.stub(
            get=pretend.call_recorder(lambda *a: None),
            AWSS3_STORAGE_BUCKET="bucket",
            AWSS3_STORAGE_ACCESS_KEY="access_key",
            AWSS3_STORAGE_SECRET_KEY="secret_key",
        )
        service = awss3.AWSS3.configure(test_settings)

        service._s3_client.put_object = pretend.raiser(
            awss3.ClientError({}, "put_object")
        )

        fake_file_data = b"fake_byte_data"

        with pytest.raises(awss3.StorageError) as err:
            service.put(fake_file_data, "3.bin-e.json")

        assert "Can't write role file '3.bin-e.json'" in str(err)

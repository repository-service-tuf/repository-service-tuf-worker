import pretend
import pytest


@pytest.fixture
def mocked_boto3(monkeypatch):
    fake_bucket = pretend.stub(name="bucket")
    fake_resource = pretend.stub(
        buckets=pretend.stub(all=pretend.call_recorder(lambda: [fake_bucket]))
    )
    fake_client = pretend.stub(
        put_object=pretend.call_recorder(lambda **kw: None)
    )
    fake_Session = pretend.stub(
        client=pretend.call_recorder(lambda *a, **kw: fake_client),
        resource=pretend.call_recorder(lambda *a, **kw: fake_resource),
    )
    mock_boto3 = pretend.stub(
        Session=pretend.call_recorder(lambda *a, **kw: fake_Session),
        resource=pretend.call_recorder(lambda *a, **kw: fake_resource),
    )

    monkeypatch.setattr(
        "repository_service_tuf_worker.services.storage.awss3.boto3",
        mock_boto3,
    )

# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import pretend
import pytest
from tuf.api.metadata import Metadata, Root, Timestamp

from repository_service_tuf_worker.services.storage import local


class TestLocalStorageService:
    def test_basic_init(self):
        service = local.LocalStorage("/path")
        assert service._path == "/path"

    def test_configure(self):
        test_settings = pretend.stub(
            LOCAL_STORAGE_BACKEND_PATH="/path",
            get=pretend.call_recorder(lambda *a: "/path"),
        )
        local.os = pretend.stub(
            makedirs=pretend.call_recorder(lambda *a, **kw: None)
        )

        service = local.LocalStorage("/path")
        service.configure(test_settings)
        assert service._path == "/path"
        assert local.os.makedirs.calls == [
            pretend.call("/path", exist_ok=True)
        ]
        assert test_settings.get.calls == [
            pretend.call("LOCAL_STORAGE_BACKEND_PATH")
        ]

    def test_settings(self):
        service = local.LocalStorage("/path")
        service_settings = service.settings()

        assert service_settings == [
            local.ServiceSettings(
                names=["LOCAL_STORAGE_BACKEND_PATH", "LOCAL_STORAGE_PATH"],
                argument="path",
                required=True,
            ),
        ]

    def test_get(self, monkeypatch):
        service = local.LocalStorage("/path")

        local.glob = pretend.stub(
            glob=pretend.call_recorder(lambda *a: ["2.root.json"])
        )
        local.os = pretend.stub(
            path=pretend.stub(
                join=pretend.call_recorder(
                    lambda *a, **kw: "/path/2.root.json"
                )
            )
        )
        fake_file_obj = pretend.stub(
            read=pretend.call_recorder(lambda: None),
            close=pretend.call_recorder(lambda: None),
        )
        monkeypatch.setitem(
            local.__builtins__, "open", lambda *a: fake_file_obj
        )

        expected_root = Metadata(Root())
        local.Metadata = pretend.stub(
            from_bytes=pretend.call_recorder(lambda *a: expected_root)
        )
        result = service.get("root")

        assert result == expected_root
        assert fake_file_obj.read.calls == [pretend.call()]
        assert fake_file_obj.close.calls == [pretend.call()]
        assert local.glob.glob.calls == [pretend.call("/path/2.root.json")]
        assert local.os.path.join.calls == [
            pretend.call(service._path, "*.root.json"),
            pretend.call(service._path, "2.root.json"),
        ]
        assert local.Metadata.from_bytes.calls == [pretend.call(None)]

    def test_get_timestamp(self, monkeypatch):
        service = local.LocalStorage("/path")

        local.os = pretend.stub(
            path=pretend.stub(
                join=pretend.call_recorder(
                    lambda *a, **kw: "/path/2.root.json"
                )
            )
        )
        fake_file_obj = pretend.stub(
            read=pretend.call_recorder(lambda: None),
            close=pretend.call_recorder(lambda: None),
        )
        monkeypatch.setitem(
            local.__builtins__, "open", lambda *a: fake_file_obj
        )
        expected_timestamp = Metadata(Timestamp())
        local.Metadata = pretend.stub(
            from_bytes=pretend.call_recorder(lambda *a: expected_timestamp)
        )
        result = service.get("timestamp")

        assert result == expected_timestamp
        assert fake_file_obj.read.calls == [pretend.call()]
        assert fake_file_obj.close.calls == [pretend.call()]
        assert local.os.path.join.calls == [
            pretend.call(service._path, "timestamp.json"),
        ]
        assert local.Metadata.from_bytes.calls == [pretend.call(None)]

    def test_get_max_version_ValueError(self, monkeypatch):
        service = local.LocalStorage("/path")
        local.glob = pretend.stub(
            glob=pretend.call_recorder(lambda *a: ["1.root.json"])
        )
        local.os = pretend.stub(
            path=pretend.stub(
                join=pretend.call_recorder(
                    lambda *a, **kw: "/path/1.root.json"
                )
            )
        )
        fake_file_obj = pretend.stub(
            read=pretend.call_recorder(lambda: None),
            close=pretend.call_recorder(lambda: None),
        )
        monkeypatch.setitem(
            local.__builtins__, "max", pretend.raiser(ValueError)
        )
        monkeypatch.setitem(
            local.__builtins__, "open", lambda *a: fake_file_obj
        )
        expected_root = Metadata(Root())
        local.Metadata = pretend.stub(
            from_bytes=pretend.call_recorder(lambda *a: expected_root)
        )
        result = service.get("root")

        assert result == expected_root
        assert fake_file_obj.read.calls == [pretend.call()]
        assert fake_file_obj.close.calls == [pretend.call()]
        assert local.os.path.join.calls == [
            pretend.call(service._path, "*.root.json"),
            pretend.call(service._path, "1.root.json"),
        ]
        assert local.glob.glob.calls == [pretend.call("/path/1.root.json")]
        assert local.Metadata.from_bytes.calls == [pretend.call(None)]

    def test_get_OSError(self, monkeypatch):
        service = local.LocalStorage("/path")
        local.glob = pretend.stub(
            glob=pretend.call_recorder(lambda *a: ["2.root.json"])
        )
        local.os = pretend.stub(
            path=pretend.stub(
                join=pretend.call_recorder(
                    lambda *a, **kw: "/path/2.root.json"
                )
            )
        )
        fake_file_object = pretend.stub(
            close=pretend.call_recorder(lambda: None),
            read=pretend.call_recorder(lambda: b"fake_root_data"),
        )
        monkeypatch.setitem(
            local.__builtins__,
            "open",
            pretend.raiser(PermissionError("No permissions")),
        )

        with pytest.raises(local.StorageError) as err:
            with service.get("root") as r:
                r.read()

        assert "Can't open Role 'root'" in str(err)

        assert fake_file_object.close.calls == []
        assert fake_file_object.read.calls == []
        assert local.os.path.join.calls == [
            pretend.call(service._path, "*.root.json"),
            pretend.call(service._path, "2.root.json"),
        ]
        assert local.glob.glob.calls == [pretend.call("/path/2.root.json")]

    def test_put(self, monkeypatch):
        service = local.LocalStorage("/path")

        local.os = pretend.stub(
            path=pretend.stub(
                join=pretend.call_recorder(
                    lambda *a, **kw: "/path/3.bin-e.json"
                )
            ),
            fsync=pretend.call_recorder(lambda *a: None),
        )

        fake_file_data = b"fake_byte_data"

        fake_destination_file = pretend.stub(
            write=pretend.call_recorder(lambda *a: "bytes_data"),
            flush=pretend.call_recorder(lambda: None),
            fileno=pretend.call_recorder(lambda: "fileno"),
        )

        class FakeDestinationFile:
            def __init__(self, file, mode):
                return None

            def __enter__(self):
                return fake_destination_file

            def __exit__(self, type, value, traceback):
                pass

        monkeypatch.setitem(local.__builtins__, "open", FakeDestinationFile)

        result = service.put(fake_file_data, b"3.bin-e.json")

        assert result is None
        assert local.os.path.join.calls == [
            pretend.call(service._path, b"3.bin-e.json"),
        ]
        assert fake_destination_file.write.calls == [
            pretend.call(fake_file_data)
        ]
        assert fake_destination_file.flush.calls == [pretend.call()]
        assert fake_destination_file.fileno.calls == [pretend.call()]
        assert local.os.fsync.calls == [pretend.call("fileno")]

    def test_put_OSError(self):
        service = local.LocalStorage("/path")

        local.os = pretend.stub(
            path=pretend.stub(
                join=pretend.call_recorder(
                    lambda *a, **kw: "/path/3.bin-e.json"
                )
            ),
            open=pretend.raiser(PermissionError("don't want this message")),
        )

        fake_bytes = b"data"

        with pytest.raises(local.StorageError) as err:
            service.put(fake_bytes, "3.bin-e.json")

        assert "Can't write role file '/path/3.bin-e.json'" in str(err)
        assert local.os.path.join.calls == [
            pretend.call(service._path, "3.bin-e.json"),
        ]

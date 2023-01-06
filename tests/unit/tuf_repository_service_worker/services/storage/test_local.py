# SPDX-FileCopyrightText: 2022 VMware Inc
#
# SPDX-License-Identifier: MIT

import os
import pretend
import pytest

from repository_service_tuf_worker.services.storage import local


class TestLocalStorageService:
    def test_basic_init(self):
        service = local.LocalStorage("/path")
        assert service._path == "/path"

    def test_configure(self):
        test_settings = pretend.stub(LOCAL_STORAGE_BACKEND_PATH="/path")
        local.os = pretend.stub(
            makedirs=pretend.call_recorder(lambda *a, **kw: None)
        )

        service = local.LocalStorage("/path")
        service.configure(test_settings)
        assert service._path == "/path"
        assert local.os.makedirs.calls == [
            pretend.call("/path", exist_ok=True)
        ]

    def test_settings(self):
        service = local.LocalStorage("/path")
        service_settings = service.settings()

        assert service_settings == [
            local.ServiceSettings(
                name="LOCAL_STORAGE_BACKEND_PATH",
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
        fake_file_object = pretend.stub(
            close=pretend.call_recorder(lambda: None),
            read=pretend.call_recorder(lambda: b"fake_root_data"),
        )
        monkeypatch.setitem(
            local.__builtins__, "open", lambda *a, **kw: fake_file_object
        )

        with service.get("root") as r:
            result = r.read()

        assert result == fake_file_object.read()
        assert fake_file_object.close.calls == [pretend.call()]
        assert fake_file_object.read.calls == [pretend.call(), pretend.call()]
        assert local.glob.glob.calls == [pretend.call("/path/2.root.json")]
        assert local.os.path.join.calls == [
            pretend.call(service._path, "*.root.json"),
            pretend.call(service._path, "2.root.json"),
        ]

    def test_get_timestamp(self, monkeypatch):
        service = local.LocalStorage("/path")

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
            local.__builtins__, "open", lambda *a, **kw: fake_file_object
        )

        with service.get("timestamp") as r:
            result = r.read()

        assert result == fake_file_object.read()
        assert fake_file_object.close.calls == [pretend.call()]
        assert fake_file_object.read.calls == [pretend.call(), pretend.call()]
        assert local.os.path.join.calls == [
            pretend.call(service._path, "timestamp.json"),
        ]

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
        fake_file_object = pretend.stub(
            close=pretend.call_recorder(lambda: None),
            read=pretend.call_recorder(lambda: b"fake_root_data"),
        )
        monkeypatch.setitem(
            local.__builtins__, "max", pretend.raiser(ValueError)
        )
        monkeypatch.setitem(
            local.__builtins__, "open", lambda *a, **kw: fake_file_object
        )

        with service.get("root") as r:
            result = r.read()

        assert result == fake_file_object.read()
        assert fake_file_object.close.calls == [pretend.call()]
        assert fake_file_object.read.calls == [pretend.call(), pretend.call()]
        assert local.os.path.join.calls == [
            pretend.call(service._path, "*.root.json"),
            pretend.call(service._path, "1.root.json"),
        ]
        assert local.glob.glob.calls == [pretend.call("/path/1.root.json")]

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

    def _put_setup(self, fake_destination_file, restrict=True):
        """Setup helper for all required functions in LocalStorage.put()"""

        class FakeDestinationFile:
            def __init__(self):
                pass

            def __enter__(self):
                return fake_destination_file

            def __exit__(self, type, value, traceback):
                pass

        local.os = pretend.stub(
            path=pretend.stub(
                join=pretend.call_recorder(
                    lambda *a, **kw: "/path/3.bin-e.json"
                )
            ),
            fsync=pretend.call_recorder(lambda *a: None),
            O_WRONLY=0,
            O_CREAT=0,
            open=pretend.call_recorder(lambda *a: 0),
            fdopen=pretend.call_recorder(lambda *a: FakeDestinationFile()),
        )

        if restrict:
            local.stat = pretend.stub(S_IRUSR=0, S_IWUSR=0)

        local.shutil = pretend.stub(
            copyfileobj=pretend.call_recorder(lambda *a: None)
        )

    def test_put(self):
        service = local.LocalStorage("/path")

        fake_destination_file = pretend.stub(
            flush=pretend.call_recorder(lambda: None),
            fileno=pretend.call_recorder(lambda: "fileno"),
        )

        fake_file_object = pretend.stub(
            closed=False,
            seek=pretend.call_recorder(lambda *a: None),
        )

        self._put_setup(fake_destination_file)
        result = service.put(fake_file_object, "3.bin-e.json")

        assert result is None
        assert local.os.path.join.calls == [
            pretend.call(service._path, "3.bin-e.json"),
        ]
        assert fake_file_object.seek.calls == [pretend.call(0)]
        expected_file_path = os.path.join(service._path, "3.bin-e.json")
        assert local.os.open.calls == [pretend.call(expected_file_path, 0, 0)]
        assert local.os.fdopen.calls == [pretend.call(0, "wb")]
        assert local.shutil.copyfileobj.calls == [
            pretend.call(fake_file_object, fake_destination_file)
        ]
        assert fake_destination_file.flush.calls == [pretend.call()]
        assert fake_destination_file.fileno.calls == [pretend.call()]
        assert local.os.fsync.calls == [pretend.call("fileno")]

    def test_put_without_restrict(self):
        service = local.LocalStorage("/path")

        fake_destination_file = pretend.stub(
            flush=pretend.call_recorder(lambda: None),
            fileno=pretend.call_recorder(lambda: "fileno"),
        )

        fake_file_object = pretend.stub(
            closed=False,
            seek=pretend.call_recorder(lambda *a: None),
        )

        self._put_setup(fake_destination_file, False)
        result = service.put(fake_file_object, "3.bin-e.json", False)

        assert result is None
        assert local.os.path.join.calls == [
            pretend.call(service._path, "3.bin-e.json"),
        ]
        assert fake_file_object.seek.calls == [pretend.call(0)]
        expected_file_path = os.path.join(service._path, "3.bin-e.json")
        assert local.os.open.calls == [pretend.call(expected_file_path, 0)]
        assert local.os.fdopen.calls == [pretend.call(0, "wb")]
        assert local.shutil.copyfileobj.calls == [
            pretend.call(fake_file_object, fake_destination_file)
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
            O_WRONLY=0,
            O_CREAT=0,
        )

        local.stat = pretend.stub(S_IRUSR=0, S_IWUSR=0)

        fake_file_object = pretend.stub(
            closed=False,
            seek=pretend.call_recorder(lambda *a: None),
        )

        with pytest.raises(OSError) as err:
            service.put(fake_file_object, "3.bin-e.json")

        assert "don't want this message" in str(err)
        assert local.os.path.join.calls == [
            pretend.call(service._path, "3.bin-e.json"),
        ]
        assert fake_file_object.seek.calls == [pretend.call(0)]

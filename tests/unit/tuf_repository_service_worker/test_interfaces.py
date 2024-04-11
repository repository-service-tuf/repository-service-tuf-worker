from typing import List, Optional

import pretend
import pytest
from tuf.api.metadata import Metadata, T

from repository_service_tuf_worker import interfaces


class TestInterfaces:
    def test_IKeyVault(self):
        class TestKeyVault(interfaces.IKeyVault):
            @classmethod
            def configure(): ...

            def get(): ...

            @classmethod
            def settings(): ...

        test_keyvault = TestKeyVault()

        assert isinstance(test_keyvault, interfaces.IKeyVault)

    def test_IStorage(self):
        class TestStorage(interfaces.IStorage):
            @classmethod
            def configure(): ...

            @classmethod
            def settings(): ...

            def get(): ...

            def put(): ...

        test_keyvault = TestStorage()

        assert isinstance(test_keyvault, interfaces.IStorage)

    def test__setup_service_dynaconf_invalid_interface(self, monkeypatch):
        test_cls = pretend.stub(
            __subclasses__=pretend.call_recorder(
                lambda: [pretend.stub(__name__="FakeService")]
            ),
            __name__="IFake",
        )
        test_settings = interfaces.Dynaconf()
        test_settings.RSTUF_FAKE_BACKEND = "FAKESERVICE"
        test_settings.FAKE_VAR1 = "value1"
        test_settings.FAKE_VAR2 = "value2"
        test_backend = pretend.stub(
            settings=pretend.call_recorder(
                lambda: [
                    interfaces.ServiceSettings(
                        names=["FAKE_VAR1", "FAKE_VAR2"],
                        required=True,
                    )
                ]
            ),
            configure=pretend.call_recorder(lambda *a: None),
        )
        test_module = pretend.stub(FAKESERVICE=test_backend)

        monkeypatch.setattr(
            "repository_service_tuf_worker.interfaces.importlib.import_module",
            lambda *a: test_module,
        )

        with pytest.raises(ValueError) as err:
            interfaces._setup_service_dynaconf(
                test_cls, test_settings.RSTUF_FAKE_BACKEND, test_settings
            )

        assert "Invalid Interface IFake" in str(err)
        assert test_backend.settings.calls == [pretend.call(), pretend.call()]
        assert test_backend.configure.calls == []
        assert test_cls.__subclasses__.calls == [pretend.call()]

    def test__setup_service_dynaconf_all_settings_none(self, monkeypatch):
        class FakeStorage(interfaces.IStorage):
            def __init__(self, var1: str, var2: str):
                self._var1 = var1
                self._var2 = var2

            @classmethod
            def configure(cls, settings: interfaces.Dynaconf) -> "FakeStorage":
                return FakeStorage(
                    settings.TEST_STORAGE_VAR1, settings.TEST_STORAGE_VAR2
                )

            @classmethod
            def settings(cls) -> List[interfaces.ServiceSettings]:
                return [
                    interfaces.ServiceSettings(
                        names=["TEST_STORAGE_VAR1", "TEST_STORAGE_VARIABLE1"],
                        required=False,
                    ),
                    interfaces.ServiceSettings(
                        names=["TEST_STORAGE_VAR2"],
                        required=False,
                    ),
                ]

            def get(
                self, rolename: str, version: Optional[int]
            ) -> Metadata[T]: ...

            def put(self, file_data: bytes, filename: str) -> None: ...

        test_settings = interfaces.Dynaconf()
        test_settings.STORAGE_BACKEND = "FAKESTORAGE"
        test_settings.TEST_STORAGE_VAR1 = None
        test_settings.TEST_STORAGE_VAR2 = None

        monkeypatch.setattr(
            "repository_service_tuf_worker.interfaces.importlib.import_module",
            lambda *a: test_module,
        )
        test_module = pretend.stub(FAKESTORAGE=FakeStorage)

        result = interfaces.IStorage.from_dynaconf(test_settings)
        assert result is None
        assert isinstance(test_settings.STORAGE, interfaces.IStorage)
        assert test_settings.STORAGE._var1 is None
        assert test_settings.STORAGE._var2 is None

    def test__setup_service_dynaconf_missing_config(self, monkeypatch):
        test_cls = pretend.stub(
            __subclasses__=pretend.call_recorder(
                lambda: [pretend.stub(__name__="FakeService")]
            ),
            __name__="IFake",
        )
        test_settings = interfaces.Dynaconf()
        test_settings.RSTUF_FAKE_BACKEND = "FAKESERVICE"
        test_backend = pretend.stub(
            FAKESERVICE=pretend.stub(
                settings=pretend.call_recorder(
                    lambda: [
                        interfaces.ServiceSettings(
                            names=["FAKE_VAR1", "FAKE_VAR2"],
                            required=True,
                        )
                    ]
                ),
            )
        )

        monkeypatch.setattr(
            "repository_service_tuf_worker.interfaces.importlib.import_module",
            lambda *a: test_backend,
        )

        with pytest.raises(AttributeError) as err:
            interfaces._setup_service_dynaconf(
                test_cls, test_settings.RSTUF_FAKE_BACKEND, test_settings
            )

        assert (
            "'Settings' object has no attribute(s) (environment variables): "
            "RSTUF_FAKE_VAR1 or RSTUF_FAKE_VAR2"
        ) in str(err)
        assert test_backend.FAKESERVICE.settings.calls == [pretend.call()]
        assert test_cls.__subclasses__.calls == [pretend.call()]

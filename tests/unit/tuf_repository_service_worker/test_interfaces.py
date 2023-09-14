import pretend
import pytest

from repository_service_tuf_worker import interfaces


class TestInterfaces:
    def test_IKeyVault(self):
        class TestKeyVault(interfaces.IKeyVault):
            @classmethod
            def configure():
                ...

            def get():
                ...

            @classmethod
            def settings():
                ...

        test_keyvault = TestKeyVault()

        assert isinstance(test_keyvault, interfaces.IKeyVault)

    def test_IStorage(self):
        class TestStorage(interfaces.IStorage):
            @classmethod
            def configure():
                ...

            @classmethod
            def settings():
                ...

            def get():
                ...

            def put():
                ...

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
                        name=["FAKE_VAR1", "FAKE_VAR2"],
                        argument="var",
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

    def test__setup_service_dynaconf_all_none(self, monkeypatch):
        test_cls = pretend.stub(
            __subclasses__=pretend.call_recorder(
                lambda: [pretend.stub(__name__="FakeService")]
            ),
            __name__="IFake",
        )
        test_settings = interfaces.Dynaconf()
        test_settings.RSTUF_FAKE_BACKEND = "FAKESERVICE"
        test_settings.FAKE_VAR1 = None
        test_settings.FAKE_VAR2 = None
        test_backend = pretend.stub(
            settings=pretend.call_recorder(
                lambda: [
                    interfaces.ServiceSettings(
                        name=["FAKE_VAR1", "FAKE_VAR2"],
                        argument="var",
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
                            name=["FAKE_VAR1", "FAKE_VAR2"],
                            argument="var",
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

        assert "not attribute(s) RSTUF_FAKE_VAR1 or RSTUF_FAKE_VAR2" in str(
            err
        )

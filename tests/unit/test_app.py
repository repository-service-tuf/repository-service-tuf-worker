import app


class TestApp:
    def test_app(self):
        assert app.Celery.__name__ == "Celery"

    def test_kaprien_repository_action(self):
        assert app.kaprien_repository_action({"key": "value"}) is True

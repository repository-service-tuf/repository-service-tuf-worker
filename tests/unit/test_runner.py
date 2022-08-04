from kaprien_repo_worker import runner


class TestRunner:
    def test_main(self):
        assert runner.main({"key": "value"}) is True

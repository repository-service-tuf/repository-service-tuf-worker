build-dev:
	docker build -t kaprien-repo-worker:dev .

run-dev:
	# $(MAKE) build-dev
	docker login ghcr.io
	docker-compose up --remove-orphans

init-repository:
	docker-compose run --rm kaprien-rest-api bash -c "apt update && apt install curl -y && curl -X POST http://kaprien-rest-api:8000/api/v1/bootstrap/ -H 'Content-Type: application/json' -d @tests/data_examples/bootstrap/payload.json"

stop:
	docker-compose down -v

clean:
	$(MAKE) stop
	docker-compose rm --force

reformat:
	black -l 79 .
	isort -l79 --profile black .

tests:
	tox -r

requirements:
	pipenv lock -r > requirements.txt
	pipenv lock -r -d > requirements-dev.txt

coverage:
	coverage report
	coverage html -i

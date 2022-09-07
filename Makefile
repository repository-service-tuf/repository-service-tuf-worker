.PHONY: build-dev run-dev stop clean purge reformat tests requirements coverage docs

build-dev:
	docker build -t kaprien-repo-worker:dev .

run-dev:
	$(MAKE) build-dev
	docker login ghcr.io
	docker pull ghcr.io/kaprien/kaprien-rest-api:dev
	docker-compose up --remove-orphans


stop:
	docker-compose down -v

clean:
	$(MAKE) stop
	docker-compose rm --force
	rm -rf ./data

purge:
	$(MAKE) clean
	docker rmi kaprien-repo-worker_kaprien-repo-worker --force

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

docs:
	tox -e docs

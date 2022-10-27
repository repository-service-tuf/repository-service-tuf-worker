.PHONY: build-dev run-dev stop clean purge reformat tests requirements coverage docs

build-dev:
	docker build -t repository-service-tuf-worker:dev .

run-dev:
	$(MAKE) build-dev
	docker pull ghcr.io/vmware/repository-service-tuf-api:dev
	docker-compose up --remove-orphans


stop:
	docker-compose down -v

clean:
	$(MAKE) stop
	docker-compose rm --force
	rm -rf ./data

purge:
	$(MAKE) clean
	docker rmi tuf-repository-service-worker_repository-service-tuf-worker --force

reformat:
	black -l 79 .
	isort -l79 --profile black .

tests:
	tox -r

requirements:
	pipenv requirements > requirements.txt
	pipenv requirements --dev > requirements-dev.txt

coverage:
	coverage report
	coverage html -i

docs:
	tox -e docs

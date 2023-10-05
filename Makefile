.PHONY: build-dev run-dev stop clean purge reformat tests requirements coverage docs

build-dev:
	docker build -t repository-service-tuf-worker:dev .

run-dev: export API_VERSION = dev
run-dev:
	$(MAKE) build-dev
	docker pull ghcr.io/repository-service-tuf/repository-service-tuf-api:dev
ifneq ($(DC),)
	docker compose -f docker-compose-$(DC).yml up --remove-orphans
else
	docker compose -f docker-compose.yml up --remove-orphans
endif


db-migration:
	if [ -z "$(M)" ]; then echo "Use: make db-migration M=\'message here\'"; exit 1; fi
	docker compose run --rm --entrypoint='alembic revision --autogenerate -m "$(M)"' repository-service-tuf-worker

stop:
	docker compose down -v

clean:
	$(MAKE) stop
	docker compose rm --force
	docker rm repository-service-tuf-worker-localstack-1 -f
	rm -rf ./data
	rm -rf ./data_test

purge:
	$(MAKE) clean
	docker rmi repository-service-tuf-worker_repository-service-tuf-worker --force

reformat:
	black -l 79 .
	isort -l79 --profile black .

tests:
	tox -r

requirements:
	pipenv lock
	pipenv requirements > requirements.txt
	pipenv requirements --dev > requirements-dev.txt

precommit:
	pre-commit install
	pre-commit autoupdate
	pre-commit run --all-files --show-diff-on-failure

coverage:
	coverage report
	coverage html -i

docs:
	tox -e docs

precommit:
	pre-commit install
	pre-commit autoupdate
	pre-commit run --all-files --show-diff-on-failure

clone-umbrella:
	if [ -d rstuf-umbrella ];\
		then \
		cd rstuf-umbrella && git pull;\
	else \
		git clone https://github.com/repository-service-tuf/repository-service-tuf.git rstuf-umbrella;\
	fi

ft-das:
# Use "GITHUB_ACTION" to identify if we are running from a GitHub action.
ifeq ($(GITHUB_ACTION),)
	$(MAKE) clone-umbrella
endif
	docker compose run --env UMBRELLA_PATH=rstuf-umbrella --entrypoint 'bash tests/functional/scripts/run-ft-das.sh $(CLI_VERSION)' --rm repository-service-tuf-worker

ft-signed:
# Use "GITHUB_ACTION" to identify if we are running from a GitHub action.
ifeq ($(GITHUB_ACTION),)
	$(MAKE) clone-umbrella
endif
	docker compose run --env UMBRELLA_PATH=rstuf-umbrella --entrypoint 'bash tests/functional/scripts/run-ft-signed.sh $(CLI_VERSION)' --rm repository-service-tuf-worker
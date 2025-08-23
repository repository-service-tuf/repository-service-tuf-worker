.PHONY: build-dev run-dev stop clean purge reformat tests requirements coverage docs

all: help

ifeq ($(DC),)
DC := docker-compose.yml
endif

ifeq ($(DCO),)
DCO := docker-compose-otel.yml
endif

ifeq ($(DCS),)
DCS := ./otel_signoz_config/docker-compose-signoz.yml
endif

build-dev:  ## Build the dev image
	docker build -t repository-service-tuf-worker:dev .

run-dev: export API_VERSION = dev
run-dev:  ## Run the development environment
	$(MAKE) build-dev
	docker pull ghcr.io/repository-service-tuf/repository-service-tuf-api:dev

	docker compose -f $(DC) up --remove-orphans

run-dev-otel: export API_VERSION = dev
run-dev-otel:  ## Run dev environment with OpenTelemetry
	$(MAKE) build-dev
	docker pull ghcr.io/repository-service-tuf/repository-service-tuf-api:dev
	docker compose -f $(DCO) -f $(DCS) up -d
	docker compose -f $(DCO) logs -f

db-migration:  ## Run a database migration
	if [ -z "$(M)" ]; then echo "Use: make db-migration M=\'message here\'"; exit 1; fi
	docker compose run --rm --entrypoint='alembic revision --autogenerate -m "$(M)"' repository-service-tuf-worker

stop:  ## Stop the development environment
	docker compose -f $(DCO) down -v --remove-orphans
	docker compose -f $(DCS) down -v --remove-orphans
	docker compose -f $(DC) down -v --remove-orphans

clean:  ## Clean up the development environment
	$(MAKE) stop
	docker compose -f $(DC) rm --force
	docker rm repository-service-tuf-worker-localstack-1 -f
	rm -rf ./data
	rm -rf ./data_test

purge:  ## Purge the development environment
	$(MAKE) clean
	docker rmi repository-service-tuf-worker_repository-service-tuf-worker --force

reformat:  ## Reformat the code using black and isort
	black -l 79 .
	isort -l79 --profile black .

tests:  ## Run the tests
	tox -r

coverage:  ## Run the tests with coverage
	coverage report
	coverage html -i

docs:  ## Build the documentation
	tox -e docs

precommit:  ## install and run pre-commit hooks
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
	docker compose -f $(DC) run --env UMBRELLA_PATH=rstuf-umbrella --rm rstuf-ft-runner bash rstuf-umbrella/tests/functional/scripts/run-ft-das.sh $(CLI_VERSION) $(PYTEST_GROUP) $(SLOW)

ft-das-local:
	docker compose -f $(DC) run --env UMBRELLA_PATH=rstuf-umbrella --rm rstuf-ft-runner bash rstuf-umbrella/tests/functional/scripts/run-ft-das.sh $(CLI_VERSION)


ft-signed:
# Use "GITHUB_ACTION" to identify if we are running from a GitHub action.
ifeq ($(GITHUB_ACTION),)
	$(MAKE) clone-umbrella
endif
	docker compose -f $(DC) run --env UMBRELLA_PATH=rstuf-umbrella --rm rstuf-ft-runner bash rstuf-umbrella/tests/functional/scripts/run-ft-signed.sh $(CLI_VERSION) $(PYTEST_GROUP) $(SLOW)

ft-signed-local:
	docker compose -f $(DC) run --env UMBRELLA_PATH=rstuf-umbrella --rm rstuf-ft-runner bash rstuf-umbrella/tests/functional/scripts/run-ft-signed.sh $(CLI_VERSION)


help:  ## Show this help message
	@echo "Makefile commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Environment variables:"
	@echo "  DC: Path to the docker-compose file (default: docker-compose.yml)"
	@echo "  M: Migration message for alembic"
	@echo "  CLI_VERSION: Version of the CLI to use"
	@echo "  PYTEST_GROUP: Group of tests to run with pytest"
	@echo "  SLOW: Run slow tests"
SHELL := /bin/bash
.DEFAULT_GOAL := help

GO      ?= go
PYTHON  ?= python3
OPA     ?= opa
COMPOSE ?= docker compose

CORE_DIR := core
BIN_DIR  := $(CORE_DIR)/bin
AIOS     := $(BIN_DIR)/aios
AIOSD    := $(BIN_DIR)/aiosd

API_PORT ?= 8000
ARGS     ?=
TARGET   ?=
PLAN     ?= plan.json
HASH     ?=

.PHONY: help all build core-build install-python test test-go test-py test-policy \
        lint fmt vet check docker-config docker-build up down logs ps health \
        install-go \
        aios docker-aios planner planner-json shell scan quarantine restore \
        clean docker-clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "; printf "\nAIOS targets:\n\n"} \
		/^[a-zA-Z0-9_-]+:.*## / {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}' \
		$(MAKEFILE_LIST)
	@printf "\nExamples:\n"
	@printf "  make up\n"
	@printf "  make planner ARGS='how is memory?'\n"
	@printf "  make scan TARGET=~/Downloads PLAN=plan.json\n"
	@printf "  make quarantine PLAN=plan.json HASH=sha256:...\n\n"

all: build check ## Build and run every check

build: core-build ## Build the Go CLI and daemon into core/bin

core-build: ## Build Go binaries
	@mkdir -p $(BIN_DIR)
	cd $(CORE_DIR) && $(GO) build -trimpath -o bin/aios ./cmd/aios
	cd $(CORE_DIR) && $(GO) build -trimpath -o bin/aiosd ./cmd/aiosd

install-go: ## Install the Go CLI and daemon onto PATH
	cd $(CORE_DIR) && GOBIN="$${GOBIN:-$$HOME/.local/bin}" $(GO) install ./cmd/aios ./cmd/aiosd

install-python: ## Install the Python planner in editable mode
	$(PYTHON) -m pip install -e ".[dev]"

test: test-go test-py test-policy ## Run Go, Python, and Rego suites

test-go: ## Run Go tests with the race detector
	cd $(CORE_DIR) && $(GO) test ./... -race

test-py: ## Run the Python planner tests
	$(PYTHON) -m pytest -q

test-policy: ## Run the Rego policy tests
	$(OPA) test aios/policies

lint: ## Check Python style
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check aios tests

fmt: ## Format Go and Python sources
	cd $(CORE_DIR) && gofmt -w .
	$(PYTHON) -m ruff format aios tests
	$(PYTHON) -m ruff check --fix aios tests

vet: ## Run go vet
	cd $(CORE_DIR) && $(GO) vet ./...

check: vet lint test ## Vet, lint, and test everything

docker-config: ## Validate the compose file
	$(COMPOSE) config -q

docker-build: ## Build the runtime image
	$(COMPOSE) build core

up: ## Build and start the core in the background
	$(COMPOSE) up -d --build core
	@$(COMPOSE) ps core

down: ## Stop the core and planner containers
	$(COMPOSE) down

logs: ## Follow core logs
	$(COMPOSE) logs -f core

ps: ## Show container status
	$(COMPOSE) ps

health: ## Query the core health endpoint on the host
	curl -fsS http://127.0.0.1:$(API_PORT)/health
	@printf "\n"

aios: ## Run the local CLI, e.g. make aios ARGS='status --json'
	$(AIOS) $(ARGS)

docker-aios: ## Run a one-off CLI command in the core container
	$(COMPOSE) run --rm --build core aios $(ARGS)

planner: ## Run the containerized planner, e.g. make planner ARGS='"how is cpu?"'
	$(COMPOSE) run --rm --build planner python -m aios.ai $(ARGS)

planner-json: ## Run the planner and print JSON
	$(COMPOSE) run --rm --build planner python -m aios.ai --json $(ARGS)

shell: ## Open a shell in the runtime image
	$(COMPOSE) run --rm core sh

scan: ## Scan TARGET for cleanup candidates and write PLAN
	@test -n "$(TARGET)" || { echo "usage: make scan TARGET=/path [PLAN=plan.json]"; exit 2; }
	$(AIOS) cleanup scan "$(TARGET)" --plan-out "$(PLAN)" $(ARGS)

quarantine: ## Quarantine an approved PLAN (requires HASH)
	@test -n "$(HASH)" || { echo "usage: make quarantine PLAN=plan.json HASH=sha256:..."; exit 2; }
	$(AIOS) cleanup quarantine "$(PLAN)" --confirm-plan-hash "$(HASH)" $(ARGS)

restore: ## Restore an approved PLAN (requires HASH)
	@test -n "$(HASH)" || { echo "usage: make restore PLAN=plan.json HASH=sha256:..."; exit 2; }
	$(AIOS) cleanup restore "$(PLAN)" --confirm-plan-hash "$(HASH)" $(ARGS)

clean: ## Remove local binaries and caches
	rm -rf $(BIN_DIR) .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

docker-clean: ## Stop containers and delete the state volume
	@printf "This deletes the audit ledger and quarantined files.\n"
	$(COMPOSE) down -v

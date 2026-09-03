BINARY  := padl
PKG     := github.com/mnorrsken/padl
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X $(PKG)/internal/version.Version=$(VERSION) -X $(PKG)/internal/version.Commit=$(COMMIT)

COMPOSE := docker compose -f dev/docker-compose.yml

.PHONY: help build run test race it lint fmt vet tidy clean lab lab-down lab-logs \
	lab-edir lab-profiles lab-profiles-rm dist

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

build: ## Build ./bin/padl
	go build -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/$(BINARY)

run: build ## Build and run
	./bin/$(BINARY)

test: ## Unit tests (no network, no containers)
	go test ./...

race: ## Unit tests under the race detector
	go test -race ./...

it: lab ## Integration tests against the lab directory
	PADL_IT=1 go test -count=1 ./...

lint: vet ## go vet plus golangci-lint when it is installed
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run || \
		echo "golangci-lint not installed, skipping"

vet: ## go vet
	go vet ./...

fmt: ## Format
	gofmt -w cmd internal dev

tidy: ## Tidy go.mod
	go mod tidy

lab: ## Start the throwaway directories (OpenLDAP + lldap + Samba AD) and wait for them
	$(COMPOSE) up -d
	@echo "waiting for the lab directories..."
	@for c in padl-lab-openldap padl-lab-lldap padl-lab-ad; do \
		i=0; \
		until [ "$$(docker inspect --format='{{.State.Health.Status}}' $$c 2>/dev/null)" = "healthy" ]; do \
			i=$$((i + 1)); \
			if [ $$i -gt 90 ]; then \
				echo "$$c never became healthy; see: $(COMPOSE) logs $$c" >&2; exit 1; \
			fi; \
			sleep 2; \
		done; \
	done
	@echo "openldap: ldap://127.0.0.1:13389  ldaps://127.0.0.1:13636"
	@echo "lldap:    ldap://127.0.0.1:13390  (web ui on http://127.0.0.1:17170)"
	@echo "samba ad: ldaps://127.0.0.1:13638  starttls://127.0.0.1:13392  (cleartext binds refused)"

lab-edir: ## Start the eDirectory container (needs dev/edir.env; skipped without it)
	@./dev/lab-edir.sh

lab-profiles: lab lab-edir ## Start every lab server and add a profile for each to your PADL config
	@set -a; if [ -f dev/edir.env ]; then . ./dev/edir.env; fi; set +a; \
		go run ./dev/labprofiles

lab-profiles-rm: ## Remove those profiles and their keychain entries
	@go run ./dev/labprofiles -rm

lab-down: ## Stop and delete the lab directories
	$(COMPOSE) down -v
	@docker rm -f padl-lab-edir >/dev/null 2>&1 && echo "removed padl-lab-edir" || true

lab-logs: ## Follow the lab directories' logs
	$(COMPOSE) logs -f

dist: ## Cross-compile release binaries into ./dist
	@mkdir -p dist
	@for target in darwin/arm64 darwin/amd64 linux/arm64 linux/amd64 windows/amd64 windows/arm64; do \
		os=$${target%/*}; arch=$${target#*/}; ext=""; \
		[ "$$os" = "windows" ] && ext=".exe"; \
		echo "building $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' \
			-o dist/$(BINARY)-$$os-$$arch$$ext ./cmd/$(BINARY) || exit 1; \
	done

clean: ## Remove build output
	rm -rf bin dist

IMAGE_NAME ?= log-watcher
TAG ?= latest

.PHONY: help build rebuild run

help:
	@echo Available targets:
	@echo   make build    - Build the Docker image
	@echo   make rebuild  - Rebuild the Docker image without cache
	@echo   make run      - Run the Docker image locally

build:
	docker build -t $(IMAGE_NAME):$(TAG) .

rebuild:
	docker build --no-cache -t $(IMAGE_NAME):$(TAG) .

run:
	docker run --rm --env-file .env $(IMAGE_NAME):$(TAG)

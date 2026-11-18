PY ?= python3

.PHONY: help test unit
help:
	@echo "make unit | test"

test: unit

unit:
	$(PY) -m pytest tests -q

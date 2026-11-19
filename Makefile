PY ?= python3
.PHONY: help unit integration test run-all unseen docker clean
help:
	@echo "make unit | integration | test | run-all | unseen | docker | clean"
unit:
	$(PY) -m pytest tests/test_unit.py -q
integration:
	$(PY) -m pytest tests/test_integration.py -q
test:
	$(PY) -m pytest tests -q
run-all:
	./run_all.sh
unseen:
	./run_unseen.sh
docker:
	scripts/run_in_docker.sh -c targets/csvsum/config.correct.yaml
clean:
	rm -rf _runs docker_out reports .pytest_cache patchval/__pycache__ tests/__pycache__

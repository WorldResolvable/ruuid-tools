# RUUID Python tools — generate, resolve, demo, tests.
#
# Targets:
#  deps             - pip install --user of ruuid and deps
#  test             - run the pytest suite
#  demo             - run the bash demo against a local anchor.
#                     Override the zone with `make demo ZONE=path/to/zone.json`.
#  install-global   - pip-install for system-wide sudo use, plus the
#                     man page. (No demo-only side effects.)
#  setup-demo       - one-time demo prep: self-signed cert at
#                     /etc/ruuid/anchor-cert.pem + /etc/hosts entry
#                     for demo.example.com.
#  refresh-cert     - regenerate /etc/ruuid/anchor-cert.pem.
#  uninstall-global - reverse install-global.
#  clean            - remove Python build/cache artifacts.

PYTHON := python3

PY_SRC = $(wildcard ruuid/*.py)

.PHONY: deps test install-global uninstall-global setup-demo demo clean

deps: $(PY_SRC)
	$(PYTHON) -m pip install --user -e ".[test]"

test:
	$(PYTHON) -m pytest

install-global:
	./install/install-global.sh

uninstall-global:
	./install/uninstall-global.sh

setup-demo:
	./demo/setup-demo.sh

/etc/ruuid/anchor-cert.pem refresh-cert:
	./demo/gen-cert.sh

demo:
	./demo/demo.sh $(ZONE)

clean:
	rm -rf *.egg-info .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete

# RUUID Python tools — generate, resolve, demo, tests.
#
# Targets:
#  deps             - pip install --user of ruuid and deps
#  test             - run the pytest suite
#  setup-demo       - one-time demo prep: self-signed cert at
#                     /etc/ruuid/anchor-cert.pem + /etc/hosts entry
#                     for demo.example.com.
#  demo             - run the bash demo against a local anchor.
#                     Override the zone with `make demo ZONE=path/to/zone.json`.
#  refresh-demo     - regenerate /etc/ruuid/anchor-cert.pem.
#  install          - pip-install for system-wide sudo use, plus the
#                     man page. (No demo-only side effects.)
#  uninstall        - reverse install
#  clean            - remove Python build/cache artifacts.

PYTHON := python3

PY_SRC = $(wildcard ruuid/*.py)

.PHONY: deps test install uninstall setup-demo demo clean

deps: $(PY_SRC)
	$(PYTHON) -m pip install --user -e ".[test]"

test:
	$(PYTHON) -m pytest

install:
	./install/install.sh

uninstall:
	./install/uninstall.sh

setup-demo:
	./demo/setup-demo.sh

demo:
	./demo/demo.sh $(ZONE)

/etc/ruuid/anchor-cert.pem refresh-demo:
	./demo/gen-cert.sh

clean:
	rm -rf *.egg-info .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete

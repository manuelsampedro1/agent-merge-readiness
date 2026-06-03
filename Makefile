.PHONY: test lint build smoke

test:
	PYTHONPATH=src python3 -m unittest discover -s tests

lint:
	python3 -m py_compile src/agent_merge_readiness/*.py tests/test_cli.py

build:
	python3 -m py_compile src/agent_merge_readiness/*.py tests/test_cli.py

smoke:
	PYTHONPATH=src python3 -m agent_merge_readiness examples/risky.diff --title "Sample" --check "scope guard:pass" --check "unit tests:pass" --check "secret scan:pass" --check "runbook drift:pass" --check "rollback plan:pass" --closeout examples/closeout.md
	PYTHONPATH=src python3 -m agent_merge_readiness examples/risky.diff --title "Sample" --check "scope guard:pass" --check "unit tests:pass" --check "secret scan:pass" --check "runbook drift:pass" --check "rollback plan:pass" --closeout examples/closeout.md --format json > /tmp/agent-merge-readiness.json
	PYTHONPATH=src python3 -m agent_merge_readiness examples/risky.diff --title "Proof packet sample" --proof-packet examples/proof-packet.json --closeout examples/closeout.md > /tmp/agent-merge-readiness-proof-packet.md

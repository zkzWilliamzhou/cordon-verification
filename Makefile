PYTHON ?= python3
export PYTHONPATH := $(CURDIR)/src

.PHONY: help test demo check golden equivalence skills-verify logs review clean zip

help:
	@echo "targets: test demo check golden equivalence skills-verify logs review zip"

test:
	$(PYTHON) -m unittest discover -s tests -v

demo:
	$(PYTHON) -m cordon demo

check:
	$(PYTHON) -m compileall -q src tests scripts
	$(PYTHON) scripts/review_harness.py --quick

golden:
	$(PYTHON) scripts/golden.py --out docs/review/golden_after.json

equivalence:
	$(PYTHON) scripts/verify_equivalence.py

skills-verify:
	$(PYTHON) scripts/install_skills.py --verify-only

logs:
	$(PYTHON) scripts/write_round_logs.py

review:
	$(PYTHON) scripts/review_harness.py --all

zip:
	cd .. && zip -qr cordon.zip cordon -x 'cordon/.git/*' 'cordon/__pycache__/*' 'cordon/**/__pycache__/*' 'cordon/*.egg-info/*' 'cordon/build/*'

clean:
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	find . -name '*.pyc' -delete

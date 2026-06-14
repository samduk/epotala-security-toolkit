.PHONY: test check

test:
	python3 -m unittest discover -s tests -v

check: test
	python3 -m compileall -q epxtool tests
	mypy --ignore-missing-imports epxtool
	pylint --disable=all --enable=E,F epxtool epx-recon epx-forensics epx-report epx-verify tests

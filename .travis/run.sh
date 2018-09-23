#! /usr/bin/env bash
set -e

###
# Run flake8 before running any tests to fail fast on style problems
###
flake8 py3tftp/ tests/

###
# Run unit tests and output coverage report
###
coverage run -m unittest discover tests/unit -p *test.py
coverage report

###
# Run acceptance tests:
# - Run py3tftp server on local host on default port.
# - Run acceptance tests.
# - Kill server and tests after 15 seconds.
###
timeout=15

timeout -s SIGINT "${timeout}" python -m py3tftp --host 127.0.0.1 &> /dev/null &
sleep 1
timeout -s SIGINT "${timeout}" python -m unittest discover -s tests/acceptance -p *_test.py

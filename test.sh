#! /usr/bin/env bash
timeout=15

timeout -s SIGINT "${timeout}" python -m py3tftp &> /dev/null &
sleep 1
timeout -s SIGINT "${timeout}" python -m unittest discover -s tests/acceptance -p *_test.py

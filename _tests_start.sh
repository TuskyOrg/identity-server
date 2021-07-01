#! /usr/bin/env bash
set -e
python /app/_tests_start.py

pytest /app/tests "${@}"
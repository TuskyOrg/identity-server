#! /usr/bin/env bash
# How tests are set up:
#   This file "test.sh" deletes the old docker-volumes & builds new containers using docker compose.
#   The "backend" container runs "_tests_start.sh", which in turn calls "_tests_start.py" (which creates the tables) & pytest

# Exit in case of error
set -e

echo Welcome to the Tusky test runner.

if [ $(uname -s) = "Linux" ]; then
    echo "This script __pycache__ files & delete previous docker-volumes."
    sudo find . -type d -name __pycache__ -exec rm -r {} \+
fi

# Remove possibly previous broken stacks left hanging after an error
# We don't remove any volumes until after the sudo command.
# This gives a unwary user the chance to realize they shouldn't run this script on production
docker compose down -v --remove-orphans
# Also, tear down docker environment after script is finished
trap "docker-compose down -v --remove-orphans" EXIT

docker-compose build --build-arg INSTALL_DEV=true
docker-compose up -d
docker-compose exec -T backend bash /app/_tests_start.sh "$@"
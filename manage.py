import os
import sys

import click
import dotenv

# Load environment variables into server
# Todo: Figure out automatically if POSTGRES_SERVER is "db" or "localhost" so the
#  eventual runserver command works inside a docker container
dotenv.load_dotenv("dev.env")
# Checks are added to dropdb make sure the server isn't in production
import server


@click.group()
def cli():
    pass


@click.command()
def initdb():
    server.initdb()


@click.command()
def dropdb():
    server.dropdb()


@click.command()
def resetdb():
    server.dropdb()
    server.initdb()


cli.add_command(initdb)
cli.add_command(dropdb)
cli.add_command(resetdb)


if __name__ == "__main__":
    cli()

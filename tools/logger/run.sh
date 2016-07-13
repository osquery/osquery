#!/bin/sh
# Run it with --help for help.
# You should have Flask-0.11 or later installed.

export FLASK_APP=$(dirname "$0")/logger.py
flask run "$@"

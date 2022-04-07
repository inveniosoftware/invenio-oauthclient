#!/usr/bin/env bash
# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2020 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

# Usage:
#   env DB=postgresql ./run-tests.sh [cli-options] [<specific_module_test.py>]
#   Eg:
#   ./run-tests.sh -x tests/test_contrib_gitlab.py

# Quit on errors
set -o errexit

# Quit on unbound symbols
set -o nounset

# Always bring down docker services
cleanup() {
    eval "$(docker-services-cli down --env)"
}
trap cleanup EXIT

python -m check_manifest --ignore ".*-requirements.txt"
python -m sphinx.cmd.build -qnN docs docs/_build/html
eval "$(docker-services-cli up --db ${DB:-postgresql} --env)"
python -m pytest $@
tests_exit_code=$?
exit "$tests_exit_code"

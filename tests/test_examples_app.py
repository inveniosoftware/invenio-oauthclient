# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2016-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Test example app."""

import os
import signal
import subprocess
import time
from contextlib import contextmanager

import pytest


@contextmanager
def _create_example_app(app_name):
    """Example app fixture."""
    current_dir = os.getcwd()
    # go to example directory
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    exampleappdir = os.path.join(project_dir, "examples")
    os.chdir(exampleappdir)
    # setup example
    cmd = "FLASK_APP={0} ./app-setup.sh".format(app_name)
    exit_status = subprocess.call(cmd, shell=True)
    assert exit_status == 0
    # Starting example web app
    cmd = "FLASK_APP={0} flask run --debugger -p 5000".format(app_name)
    webapp = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, preexec_fn=os.setsid, shell=True
    )
    time.sleep(5)
    # return webapp
    yield webapp
    # stop server
    os.killpg(webapp.pid, signal.SIGTERM)
    # tear down example app
    cmd = "FLASK_APP={0} ./app-teardown.sh".format(app_name)
    subprocess.call(cmd, shell=True)
    # return to the original directory
    os.chdir(current_dir)
    time.sleep(2)


@pytest.mark.parametrize("service", ["orcid", "github", "globus"])
def test_app(service):
    """Test example app for given service."""
    with _create_example_app("{0}_app.py".format(service)):
        cmd = "curl http://localhost:5000/{0}".format(service)
        output = subprocess.check_output(cmd, shell=True).decode("utf-8")
        assert "Redirect" in output


@pytest.mark.parametrize("service", ["orcid", "github", "globus"])
def test_app_rest(service):
    """Test example app for given service."""
    with _create_example_app("{0}_app_rest.py".format(service)):
        cmd = "curl http://localhost:5000/{0}".format(service)
        output = subprocess.check_output(cmd, shell=True).decode("utf-8")
        assert "Redirect" in output

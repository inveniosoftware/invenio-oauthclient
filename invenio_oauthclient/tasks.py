# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2023 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Tasks."""

from celery import shared_task

from .handlers.utils import create_or_update_roles


@shared_task
def create_or_update_roles_task(groups):
    """Task to create/update DB roles based on the groups provided."""
    create_or_update_roles(groups)

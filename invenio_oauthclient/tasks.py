# SPDX-FileCopyrightText: 2023 CERN.
# SPDX-License-Identifier: MIT

"""Tasks."""

from celery import shared_task

from .handlers.utils import create_or_update_roles


@shared_task
def create_or_update_roles_task(groups):
    """Task to create/update DB roles based on the groups provided."""
    create_or_update_roles(groups)

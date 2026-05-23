#!/bin/sh
# SPDX-FileCopyrightText: 2017 CERN.
# SPDX-License-Identifier: MIT

DIR=`dirname "$0"`

cd $DIR

# Delete database
flask db drop --yes-i-know

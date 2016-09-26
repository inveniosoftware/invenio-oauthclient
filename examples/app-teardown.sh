#!/bin/sh

DIR=`dirname "$0"`

cd $DIR

# Delete database
flask db drop --yes-i-know

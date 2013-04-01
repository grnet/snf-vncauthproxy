#!/bin/sh
. ./ci/config

for project in $PROJECTS; do
  flake8 --exclude=d3des.py $project
done

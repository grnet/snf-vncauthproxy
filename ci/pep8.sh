#!/usr/bin/env sh
. ./ci/config

for project in $PROJECTS; do
  pep8 --exclude=d3des.py $project
done

#!/usr/bin/env sh
. ./ci/config

for project in $PROJECTS; do
  pylint --ignore=d3des.py $project
done

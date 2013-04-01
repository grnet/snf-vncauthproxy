#!/bin/sh

if [ -n $VIRTUAL_ENV ]; then
  OPTIONS=--script-dir=$VIRTUAL_ENV/bin/
  echo $OPTIONS
else
  OPTIONS=
fi

set -e
. ./ci/config

# Update version
devflow-update-version

#for project in $PROJECTS; do
#  cd $project
#  python setup.py develop $OPTIONS
#  cd -
# done

# There is a single setup.py for the time being
python setup.py develop $OPTIONS

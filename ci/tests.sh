#!/bin/sh

# Copied from main Synnefo repository
# snf-vncauthproxy has no tests yet :(
exit 0

set -e

TEST="$(which snf-manage) test api db logic plankton vmapi --settings=synnefo.settings.test"

if coverage >/dev/null 2>&1; then
  coverage run $TEST
  coverage report --include=snf-*
else
  echo "coverage not installed"
  $TEST
fi

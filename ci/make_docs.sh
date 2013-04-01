#!/bin/sh

# Copied from main Synnefo repository
# snf-vncauthproxy has no Sphinx-based docs yet
exit 0

set -e

DOCS_DIR=$1

cd docs
make html
cd -

mkdir -p $DOCS_DIR
mv -n docs/_build/html/* $DOCS_DIR

echo "Moved docs to to: $(pwd)/$DOCS_DIR"

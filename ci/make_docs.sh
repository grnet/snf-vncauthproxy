#!/bin/sh

# Copied from main Synnefo repository
# snf-vncauthproxy has no Sphinx-based docs yet

set -e

DOCS_DIR=$1

# Make sure the $DOCS_DIR exists, otherwise
# buildbot/common.py will throw exception
mkdir -p $DOCS_DIR
cat << EOF >$DOCS_DIR/index.html
<html>
<body>
No docs yet.
</body>
</html>
EOF

echo "Created documentation stub in $(pwd)/$DOCS_DIR"
exit 0

cd docs
make html
cd -

mkdir -p $DOCS_DIR
mv -n docs/_build/html/* $DOCS_DIR

echo "Moved docs to to: $(pwd)/$DOCS_DIR"
